# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# run-openclaw-forward-test.ps1 - OpenClaw-over-MXC test (both backends).
#
# Proves the full path this package exists to demonstrate:
#   gateway -> MXC driver -> ProcessContainer OR isolation_session sandbox
#     (neither has an in-sandbox supervisor process; ProcessContainer also
#     has no inbound network capability at all)
#     -> openshell-supervisor-relay launches OpenClaw's gateway inside it
#     -> `openshell forward service --target-port 18889` opens a per-request,
#        on-demand WebSocket relay (bound fresh for this call, torn down when
#        it ends -- there is no always-on bridge)
#     -> a real OpenClaw client (`openclaw gateway health`) on the HOST,
#        talking through that forwarded port, authenticates and gets a real
#        response.
#
# -Backend selects which MXC backend to exercise (default: process_container).
# Both go through the exact same dynamic-forward/control-channel code path in
# the driver -- spawner wrapping is computed before the backend branch, so
# nothing about openshell-supervisor-relay or the relay protocol differs.
# What DOES differ is the config: isolation_session merges the sandbox env onto the
# full host environment (no pc_minimal_env / LOCALAPPDATA workaround needed)
# and ignores ProcessContainer-only fields like pc_capabilities entirely --
# see mxc-openclaw-isolation.toml's own comments.
#
# This test brings its OWN OpenClaw install (node.exe + the openclaw npm
# package) rather than shipping one: point -NodeExePath and
# -OpenClawInstallDir at your existing install. The AppContainer here can
# only read paths under share_dir, so this script STAGES (copies) your
# node.exe, the openclaw package, and this package's own
# openclaw-capture.mjs / openshell-supervisor-relay.exe into share_dir before
# creating the sandbox -- see the "Stage artifacts" step below. The OpenClaw
# package can be large (native-addon plugins etc.); the copy uses robocopy
# and only re-copies changed files on a rerun.
#
# Run from inside the package folder (gateway + cli + openshell-supervisor-
# relay.exe + mxc-openclaw-gateway.toml + openclaw-gateway.yaml +
# openclaw-capture.mjs + this script all sit together):
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-openclaw-forward-test.ps1 `
#     -WxcExecPath C:\mxc-kit\bin\wxc-exec.exe `
#     -NodeExePath C:\path\to\node.exe `
#     -OpenClawInstallDir C:\path\to\node_modules\openclaw

[CmdletBinding()]
param(
  [string] $WxcExecPath = "C:\mxc-kit\bin\wxc-exec.exe",
  # Your existing Node.js binary. Copied (not run in place) into share_dir --
  # the AppContainer cannot read paths outside it.
  [Parameter(Mandatory = $true)]
  [string] $NodeExePath,
  # Root directory of your OpenClaw npm package install -- the directory that
  # directly contains openclaw.mjs and its own node_modules. Copied
  # (recursively, via robocopy) into share_dir\runtime\node_modules\openclaw.
  [Parameter(Mandatory = $true)]
  [string] $OpenClawInstallDir,
  # Must be a DIRECT CHILD of a drive root (e.g. C:\openshell-openclaw, not
  # C:\work\openshell-openclaw). Node's CommonJS module resolver calls
  # fs.realpathSync while resolving the entry script, which lstat()s every
  # parent directory up the chain -- including ones OUTSIDE share_dir. The
  # AppContainer only grants share_dir itself, so an intermediate parent like
  # C:\work fails with EPERM (confirmed empirically: this exact test failed
  # with "EPERM: operation not permitted, lstat 'C:\work'" until the share
  # dir was moved to the drive root). The drive root itself (C:\) apparently
  # doesn't need an explicit grant to lstat successfully, so a one-level path
  # sidesteps the problem entirely.
  [string] $ShareDir = "C:\openshell-openclaw",
  [int]    $TargetPort = 18889,
  [int]    $ForwardLocalPort = 28889,
  [int]    $Port = 17670,
  [string] $GatewayName = "openshell-mxc-openclaw",
  [string] $GatewayToken = "openshell-mxc-test-token",
  # Sandbox name. Default is UNIQUE per run (openclaw-$PID): ProcessContainer
  # sandboxes are one-shot, but a leftover from a killed prior run can still
  # collide with `sandbox create` by name. Not backend-suffixed: sandbox
  # names are capped at 19 chars (observed: "name exceeds maximum length (20
  # > 19)"), and "openclaw-$PID" alone is already close to that budget.
  [string] $SandboxName = "",
  [switch] $KeepRunning,
  # Which MXC backend to exercise. process_container: one-shot AppContainer,
  # no inbound network capability, needs pc_minimal_env's curated sandbox env
  # (mxc-openclaw-gateway.toml). isolation_session: persistent
  # provision/start/exec session, merges the sandbox env onto the full host env,
  # ignores ProcessContainer-only fields (mxc-openclaw-isolation.toml).
  [ValidateSet("process_container", "isolation_session")]
  [string] $Backend = "process_container",
  # Use mxc-openclaw-localnet.toml (pc_allow_local_network=true) instead of
  # mxc-openclaw-gateway.toml (egress_proxy=true), to test whether traffic
  # through the egress_proxy shim was responsible for a data-plane failure
  # seen on one corp-managed machine (clean TCP connect + WS handshake, then
  # silently dropped bytes). VERIFIED BROKEN as an escape hatch on the
  # currently-used wxc-exec build, though: pc_allow_local_network does not
  # actually let the sandbox reach the gateway's relay at all here --
  # `relay connect failed: ... actively refused it (os error 10061)` on
  # every attempt, a hard connectivity failure, not the subtler data-drop
  # this switch was meant to test around. Left in for whoever investigates
  # next (a different wxc-exec build may behave differently), but don't
  # expect it to work today.
  [switch] $UseLocalNetwork
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

# The OpenShell CLI emits UTF-8 (status glyphs like Ok/× and checkmarks). PowerShell
# decodes captured native-command output using [Console]::OutputEncoding; if that is a
# legacy OEM code page the glyphs render as mojibake. Force UTF-8.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

if ([string]::IsNullOrWhiteSpace($SandboxName)) {
  $SandboxName = "openclaw-$PID"
}

$stamp     = Get-Date -Format "yyyyMMdd-HHmmss"
$resultDir = Join-Path $here "results-openclaw-forward-$stamp"
New-Item -ItemType Directory -Force $resultDir | Out-Null
Start-Transcript -Path (Join-Path $resultDir "transcript.txt") -Force | Out-Null

function Step([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Info([string]$m) { Write-Host "    $m" }

# ProcessContainer teardown on this box has been observed to leave the
# sandboxed node.exe (and occasionally openshell-supervisor-relay.exe)
# running for a few seconds after `sandbox delete` returns success -- long
# enough to still hold a lock on share_dir\node.exe when the NEXT run tries
# to re-stage it. Retry with backoff rather than failing outright, since
# "run this script again right after the last run" is a completely normal
# thing to do.
function Copy-ItemRetry([string]$src, [string]$dst, [int]$attempts = 10, [int]$delayMs = 1000) {
  for ($i = 1; $i -le $attempts; $i++) {
    try { Copy-Item $src $dst -Force; return } catch {
      if ($i -eq $attempts) { throw }
      Info "copy '$dst' locked (attempt $i/$attempts): $($_.Exception.Message) -- retrying in $($delayMs)ms"
      Start-Sleep -Milliseconds $delayMs
    }
  }
}
function Ok([string]$m)   { Write-Host "[OK]   $m" -ForegroundColor Green }
function Bad([string]$m)  { Write-Host "[FAIL] $m" -ForegroundColor Red }

function Grant-AppContainerWritableDirectory([string]$Path) {
  # AppContainer access is a dual check: the generated package SID grant from
  # MXC is necessary, but OpenClaw's SQLite staging also needs the two built-in
  # application-package group SIDs. Scope inherited Modify access to the
  # disposable writable data directories; never grant it to staged binaries.
  & "$env:SystemRoot\System32\icacls.exe" $Path /grant `
    '*S-1-15-2-1:(OI)(CI)(M)' `
    '*S-1-15-2-2:(OI)(CI)(M)' /T /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "failed to prepare AppContainer DACL for '$Path'"
  }
}

# Present the EXPECTED-on-MXC `sandbox create` outcomes as information rather
# than raw CLI error text -- see run-ollama-test.ps1 for the same pattern and
# rationale (ProcessContainer has no in-sandbox shell to attach to; a
# leftover sandbox from a prior run is cleared and recreated).

# Returns $true when $out's content matches one of the known-benign
# MXC `sandbox create` patterns (post-create attach skipped / stale sandbox
# recreated), $false when it contains anything else -- the caller uses this
# plus the exit code to decide whether to stop instead of silently sailing
# into a 90s readiness wait that can only time out uninformatively.
function Show-SandboxCreate([object]$out, [string]$name) {
  $lines = @($out | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($lines.Count -eq 0) { return $true }
  $attachPat = '(?i)cannot exec in sandbox|no in-sandbox supervisor|has no interactive shell|supervisor session not connected|ssh exited with status'
  $existsPat = '(?i)already exists|delete it first'
  $joined    = $lines -join "`n"
  $hasOther  = @($lines | Where-Object { $_ -notmatch $attachPat -and $_ -notmatch $existsPat }).Count -gt 0
  if ($joined -match $attachPat -and -not $hasOther) {
    Info "sandbox '$name' created; agent ran in-driver. ProcessContainer has no in-sandbox shell, so the post-create attach was skipped (expected, not an error)."
    return $true
  } elseif ($joined -match $existsPat -and -not $hasOther) {
    Info "sandbox '$name': a leftover from a prior run was cleared and recreated (expected, not an error)."
    return $true
  } else {
    $lines | ForEach-Object { Info $_ }
    return -not $hasOther
  }
}

$gateway     = Join-Path $here "openshell-gateway.exe"
$cli         = Join-Path $here "openshell.exe"
$relayExe    = Join-Path $here "openshell-supervisor-relay.exe"
$policy      = Join-Path $here "e2e-policies\openclaw-gateway.yaml"
if ($UseLocalNetwork -and $Backend -eq "isolation_session") {
  throw "-UseLocalNetwork only applies to -Backend process_container (it swaps in pc_allow_local_network, a ProcessContainer-only field; isolation_session already has default-allow egress and needs no such override)."
}
$tomlName = switch ($Backend) {
  "isolation_session" { "mxc-openclaw-isolation.toml" }
  default { if ($UseLocalNetwork) { "mxc-openclaw-localnet.toml" } else { "mxc-openclaw-gateway.toml" } }
}
$tomlBaseName = [System.IO.Path]::GetFileNameWithoutExtension($tomlName)
$toml        = Join-Path $here $tomlName
$captureScript = Join-Path $here "openclaw-capture.mjs"

$shareDirNorm = $ShareDir.TrimEnd('\','/').Replace('/', '\')
# Must be a direct child of a drive root (see the -ShareDir param doc for
# why: Node's module resolver lstat()s ungranted parent dirs otherwise).
# Enforced here too so a bad path fails fast instead of silently breaking
# node's resolver deep into the run, or -- worse -- widening the stale-
# process prefix match below to something unexpectedly shallow.
if ($shareDirNorm -notmatch '^[A-Za-z]:\\[^\\]+$') {
  throw "ShareDir must be a direct child of a drive root (e.g. C:\openshell-openclaw), got '$shareDirNorm'"
}
$openClawStageDir = Join-Path $shareDirNorm "runtime\node_modules\openclaw"

$gw          = $null
$gwLog       = Join-Path $resultDir "gateway.log"
$gwErrLog    = Join-Path $resultDir "gateway.err.log"
$fwdProc     = $null
$fwdLog      = Join-Path $resultDir "forward.log"
$fwdErrLog   = Join-Path $resultDir "forward.err.log"
$passed      = $false
$healthJson  = $null
$selfProbeOutcome = "not-recorded"
$selfProbeResponseBytes = 0

try {
  # 1. Validate package artifacts + caller-supplied paths.
  Step "Validate artifacts"
  Info "backend: $Backend -- network mode: $(if ($UseLocalNetwork) { 'pc_allow_local_network (bypasses egress_proxy for the relay hop)' } else { 'default' }) -- config: $tomlName"
  foreach ($f in @($gateway, $cli, $relayExe, $policy, $toml, $captureScript)) {
    if (-not (Test-Path $f)) { throw "missing artifact: $f (run from inside the package folder)" }
    Info "found $(Split-Path $f -Leaf)"
  }
  if (-not (Test-Path $WxcExecPath)) { throw "wxc-exec not found at '$WxcExecPath'. Pass -WxcExecPath." }
  if (-not (Test-Path $NodeExePath)) { throw "node.exe not found at '$NodeExePath'. Pass -NodeExePath." }
  if (-not (Test-Path $OpenClawInstallDir)) { throw "OpenClaw install dir not found at '$OpenClawInstallDir'. Pass -OpenClawInstallDir." }
  $openClawEntry = Join-Path $OpenClawInstallDir "openclaw.mjs"
  if (-not (Test-Path $openClawEntry)) { throw "expected an OpenClaw entry point at '$openClawEntry' -- is -OpenClawInstallDir the package root (the dir containing openclaw.mjs)?" }
  Info "machine : $env:COMPUTERNAME   user: $env:USERNAME   PS: $($PSVersionTable.PSVersion)"

  # 2. Patch a DISPOSABLE copy of the TOML in the results dir (never mutate the
  #    tracked source config in place).
  Step "Patch gateway config (disposable copy)"
  $tomlText = Get-Content $toml -Raw
  $escaped  = $WxcExecPath.Replace('\', '\\')
  $tomlText = [regex]::Replace($tomlText, '(?m)^\s*#?\s*wxc_exec_path\s*=.*$', "wxc_exec_path = `"$escaped`"")
  # The shipped TOMLs hardcode the default share dir only in the relay spawner
  # path. Workload command/cwd/env are supplied per sandbox below.
  $defaultShareDirToml = "C:/openshell-openclaw"
  $shareDirToml = $shareDirNorm.Replace('\', '/')
  if ($shareDirToml -ne $defaultShareDirToml) {
    $tomlText = $tomlText.Replace($defaultShareDirToml, $shareDirToml)
  }
  $tomlUsed = Join-Path $resultDir "${tomlBaseName}.used.toml"
  Set-Content $tomlUsed -Value $tomlText -Encoding UTF8
  # The policy's read_write grant is the only source of filesystem access
  # now (the driver no longer adds share_dir automatically) -- it hardcodes
  # the same default share dir literal as the TOML, so it needs the same
  # -ShareDir substitution, or an overridden share_dir loses its grant
  # entirely and every sandboxed file access fails closed.
  $policyText = Get-Content $policy -Raw
  if ($shareDirToml -ne $defaultShareDirToml) {
    $policyText = $policyText.Replace($defaultShareDirToml, $shareDirToml)
  }
  if ($Backend -eq "isolation_session") {
    # isolation_session advertises no UI-policy support, so the gateway
    # rejects an explicit `ui:` section before provisioning even starts
    # (see README.md's Capability Matrix). Strip it from this backend's
    # disposable copy -- process_container is the only backend that needs
    # it (Node.js touches user32/gdi32 at startup even though it never
    # opens a window).
    $policyText = [regex]::Replace($policyText, '(?ms)^ui:\r?\n(?:^[ \t].*\r?\n?)*', '')
  }
  $policyUsed = Join-Path $resultDir "openclaw-gateway.used.yaml"
  Set-Content $policyUsed -Value $policyText -Encoding UTF8

  # 3. Port free (auto-clear our own stale gateway).
  Step "Check gateway port $Port is free"
  $busy = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
  if ($busy) {
    $owner = Get-Process -Id $busy.OwningProcess -ErrorAction SilentlyContinue
    if ($owner -and $owner.Name -eq "openshell-gateway") {
      Info "stopping stale gateway pid $($owner.Id)"; Stop-Process -Id $owner.Id -Force -ErrorAction SilentlyContinue; Start-Sleep 2
    } else { throw "port $Port in use by '$($owner.Name)' (pid $($busy.OwningProcess))" }
  }
  Ok "port $Port free"

  # 4. Stage artifacts into share_dir. The AppContainer here has a read-write
  #    grant on share_dir ONLY (see openclaw-gateway.yaml) -- no read-only
  #    grants on arbitrary host paths -- so node.exe, this package's
  #    openclaw-capture.mjs and openshell-supervisor-relay.exe, and your
  #    OpenClaw install must all physically live under share_dir.
  Step "Stage artifacts into share_dir ($shareDirNorm)"
  # A prior run's sandboxed processes can outlive `sandbox delete` by more
  # than a few seconds -- sometimes indefinitely, if that run's own teardown
  # hit a transport error talking to an already-stopped gateway. Rather than
  # retry a locked copy indefinitely, find and kill anything still running
  # out of share_dir before touching it. Copy-ItemRetry (below) remains as a
  # short-window fallback for the ordinary "just exited, handle not released
  # yet" case.
  # Trailing separator anchors the match to "inside $shareDirNorm", not just
  # "starts with the same characters" -- without it, a sibling directory like
  # C:\openshell-openclaw-old would also match C:\openshell-openclaw.
  $shareDirPrefix = $shareDirNorm.TrimEnd('\') + '\'
  $stale = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($shareDirPrefix, [System.StringComparison]::OrdinalIgnoreCase) }
  foreach ($p in $stale) {
    Info "killing stale process from a prior run: $($p.ProcessName) (pid $($p.Id), $($p.Path))"
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  }
  if ($stale) { Start-Sleep -Seconds 1 }

  New-Item -ItemType Directory -Force $shareDirNorm | Out-Null
  New-Item -ItemType Directory -Force (Join-Path $shareDirNorm "home") | Out-Null
  New-Item -ItemType Directory -Force (Join-Path $shareDirNorm "temp") | Out-Null
  New-Item -ItemType Directory -Force (Join-Path $shareDirNorm "local") | Out-Null
  Grant-AppContainerWritableDirectory (Join-Path $shareDirNorm "home")
  Grant-AppContainerWritableDirectory (Join-Path $shareDirNorm "temp")
  Remove-Item (Join-Path $shareDirNorm "openclaw-capture.log") -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $shareDirNorm "openshell-shutdown.signal") -Force -ErrorAction SilentlyContinue

  Copy-ItemRetry $NodeExePath (Join-Path $shareDirNorm "node.exe")
  Info "staged node.exe"
  Copy-ItemRetry $captureScript (Join-Path $shareDirNorm "openclaw-capture.mjs")
  Info "staged openclaw-capture.mjs"
  Copy-ItemRetry $relayExe (Join-Path $shareDirNorm "openshell-supervisor-relay.exe")
  Info "staged openshell-supervisor-relay.exe"

  New-Item -ItemType Directory -Force $openClawStageDir | Out-Null
  # /MIR deletes files in the destination not present in the source, which
  # is what we want on a rerun after an OpenClaw upgrade/rollback -- without
  # it, /E alone can leave a mixed tree from multiple versions, making
  # failures hard to reproduce. Safe here because $openClawStageDir is
  # computed from $shareDirNorm, already validated above (a direct child of
  # a drive root, not user-arbitrary), not a path this script accepts raw.
  $roboArgs = @($OpenClawInstallDir, $openClawStageDir, "/MIR", "/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/R:2", "/W:1")
  $roboOut = & robocopy.exe @roboArgs 2>&1
  # robocopy exit codes 0-7 are all "success" (bit flags for copied/skipped/
  # mismatched files); only >= 8 indicates a real failure.
  if ($LASTEXITCODE -ge 8) { throw "robocopy failed staging OpenClaw install (exit $LASTEXITCODE): $($roboOut -join ' ')" }
  Info "staged OpenClaw install ($OpenClawInstallDir -> $openClawStageDir, robocopy exit $LASTEXITCODE)"
  Ok "share_dir staged"

  # 5. Gateway env: config path via env var (clap: OPENSHELL_GATEWAY_CONFIG),
  #    NOT a --config token -- Start-Process -ArgumentList does not quote
  #    array elements, so a config path containing a space gets split and the
  #    gateway's arg parser rejects it. OPENCLAW_GATEWAY_TOKEN is passed with
  #    sandbox create --env-from below, so setting it here gives the sandboxed
  #    OpenClaw a stable, known token without placing it in argv.
  $env:OPENSHELL_DRIVERS        = "mxc"
  $env:OPENSHELL_GATEWAY_CONFIG = $tomlUsed
  $env:OPENCLAW_GATEWAY_TOKEN   = $GatewayToken
  Remove-Item Env:OPENSHELL_MXC_MOCK_WXC -ErrorAction SilentlyContinue

  # 6. Start gateway.
  Step "Start gateway"
  $gw = Start-Process -FilePath $gateway `
    -ArgumentList @("--disable-tls", "--log-level", "info", "--port", "$Port") `
    -WorkingDirectory $here -PassThru -NoNewWindow `
    -RedirectStandardOutput $gwLog -RedirectStandardError $gwErrLog
  Info "gateway pid $($gw.Id)"
  $deadline = (Get-Date).AddSeconds(30); $ready = $false
  while ((Get-Date) -lt $deadline) {
    if ($gw.HasExited) { Get-Content $gwLog, $gwErrLog -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object { Info $_ }; throw "gateway exited early (code $($gw.ExitCode))" }
    if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) { $ready = $true; break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $ready) { throw "gateway did not start listening on $Port within 30s" }
  Ok "gateway listening on 127.0.0.1:$Port"

  # 7. Register CLI -> gateway. See run-ollama-test.ps1 for why EAP is
  #    dropped to 'Continue' around these calls (the CLI writes success
  #    banners to stderr too, which $ErrorActionPreference='Stop' would
  #    otherwise turn into terminating errors on Windows PowerShell 5.1).
  Step "Register CLI -> gateway"
  Remove-Item Env:OPENSHELL_GATEWAY -ErrorAction SilentlyContinue
  $prevEAP = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $expectedEndpoint = "http://127.0.0.1:$Port"
    & $cli gateway add $expectedEndpoint --local --name $GatewayName 2>&1 | ForEach-Object { Info "$_" }
    if ($LASTEXITCODE -ne 0) {
      # Most likely "$GatewayName already registered" from a prior run. Don't
      # just continue and select it blindly -- if it points at a stale URL
      # (e.g. a different port from an earlier run), the rest of this script
      # would create sandboxes and forward against the wrong gateway process.
      # Verify the existing registration's endpoint actually matches this
      # run's port; re-point the alias if it doesn't.
      Info "gateway add exit $LASTEXITCODE -- '$GatewayName' likely already registered; verifying its endpoint matches this run"
      $existingEndpoint = $null
      try {
        $listJson = & $cli gateway list -o json 2>&1
        # Split from the filter below (rather than one chained pipeline) --
        # piping ConvertFrom-Json's array output directly into Where-Object
        # in the same pipeline expression does not filter correctly here.
        $gateways = $listJson | ConvertFrom-Json
        $existingEndpoint = ($gateways | Where-Object { $_.name -eq $GatewayName } | Select-Object -First 1).endpoint
      } catch {
        Info "could not parse 'gateway list -o json' output ($($_.Exception.Message)); treating as a mismatch"
      }
      if ($existingEndpoint -ne $expectedEndpoint) {
        Info "'$GatewayName' is missing or points at '$existingEndpoint' (expected '$expectedEndpoint') -- removing and re-adding"
        & $cli gateway remove $GatewayName 2>&1 | ForEach-Object { Info "$_" }
        & $cli gateway add $expectedEndpoint --local --name $GatewayName 2>&1 | ForEach-Object { Info "$_" }
        if ($LASTEXITCODE -ne 0) { throw "gateway add failed after removing stale alias '$GatewayName' (exit $LASTEXITCODE)" }
      } else {
        Info "'$GatewayName' already points at '$expectedEndpoint' -- reusing"
      }
    }
    & $cli gateway select $GatewayName 2>&1 | ForEach-Object { Info "$_" }
    $selExit = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $prevEAP
  }
  if ($selExit -ne 0) { throw "gateway select failed (exit $selExit); cannot guarantee the correct gateway context." }

  # 8. Create sandbox. Best-effort clear of any leftover sandbox of this name
  #    first (see run-ollama-test.ps1 for the same defensive pattern).
  Step "Create sandbox '$SandboxName' (runs OpenClaw's gateway inside a ProcessContainer)"
  $delOut = ""; $delCode = 0
  try { $delOut = (& $cli sandbox delete $SandboxName 2>&1 | Out-String).Trim(); $delCode = $LASTEXITCODE }
  catch { $delOut = "$($_.Exception.Message)"; $delCode = 1 }
  if ($delCode -ne 0) {
    if ($delOut -match '(?i)not found') { Info "no leftover sandbox '$SandboxName' to remove (expected on a clean run)" }
    elseif ($delOut) { Info "sandbox pre-delete '$SandboxName': $delOut (continuing)" }
    else { Info "sandbox pre-delete '$SandboxName': delete exited $delCode (continuing)" }
  }
  $driverConfigJson = @{
    mxc = @{
      command = @(
        "$shareDirToml/node.exe",
        "$shareDirToml/openclaw-capture.mjs",
        "gateway", "run", "--dev", "--allow-unconfigured",
        "--auth", "token", "--bind", "loopback", "--port", "$TargetPort"
      )
      cwd = $shareDirToml
    }
  } | ConvertTo-Json -Compress -Depth 5
  $createArgs = @(
    "sandbox", "create", "--name", $SandboxName, "--policy", $policyUsed,
    "--driver-config-json", $driverConfigJson,
    "--env-from", "SYSTEMROOT", "--env-from", "WINDIR",
    "--env-from", "PATH", "--env-from", "COMSPEC",
    "--env-from", "OPENCLAW_GATEWAY_TOKEN",
    "--env", "OPENCLAW_NO_UPDATE_CHECK=1",
    "--env", "NO_UPDATE_NOTIFIER=1",
    "--env", "LOCALAPPDATA=$shareDirToml/local",
    "--env", "HOME=$shareDirToml/home",
    "--env", "USERPROFILE=$shareDirToml/home",
    "--env", "TEMP=$shareDirToml/temp", "--env", "TMP=$shareDirToml/temp",
    "--env", "NEMOCLAW_MXC_CAPTURE_ENTRY=$shareDirToml/runtime/node_modules/openclaw/openclaw.mjs",
    "--env", "NEMOCLAW_MXC_CAPTURE_LOG=$shareDirToml/openclaw-capture.log",
    "--env", "NEMOCLAW_MXC_CAPTURE_SELF_PROBE_PORT=$TargetPort",
    "--env", "NODE_OPTIONS=--use-env-proxy",
    "--env", "NEMOCLAW_MXC_EGRESS_PROOF=1",
    "--env", "NEMOCLAW_MXC_EGRESS_ALLOWED_URL=https://example.com/",
    "--env", "NEMOCLAW_MXC_EGRESS_DENIED_URL=https://example.org/",
    "--env", "NEMOCLAW_MXC_EGRESS_DIRECT_HOST=1.1.1.1",
    "--env", "NEMOCLAW_MXC_EGRESS_LOOPBACK_PORT=29999",
    "--no-tty", "--", "exit"
  )
  try { $createOut = & $cli @createArgs 2>&1; $createCode = $LASTEXITCODE }
  catch { $createOut = $_.Exception.Message; $createCode = 1 }
  $createBenign = Show-SandboxCreate $createOut $SandboxName
  if ($createCode -ne 0 -and -not $createBenign) {
    throw "sandbox create '$SandboxName' failed (exit $createCode): $($createOut | Out-String)"
  }

  # 9. Wait for OpenClaw's gateway to report ready, by tailing the gateway's
  #    own log for the line it prints on successful startup (forwarded from
  #    the sandbox's stdout via "wxc-exec stdout:"). Generous timeout: Node
  #    startup + AppContainer/UAC elevation + plugin warmup can take a while
  #    on a cold run.
  Step "Wait for OpenClaw gateway readiness"
  $readyDeadline = (Get-Date).AddSeconds(90)
  $openclawReady = $false
  while ((Get-Date) -lt $readyDeadline) {
    if (Test-Path $gwLog) {
      # `.*` (not `\s+`) between "[gateway]" and "ready": OpenClaw wraps its
      # log lines in ANSI color codes whenever it inherits enough of the host
      # env to detect a color-capable terminal -- which happens with
      # mxc-openclaw-localnet.toml (-UseLocalNetwork), since that config
      # doesn't set pc_minimal_env and so inherits the full host env, unlike
      # mxc-openclaw-gateway.toml's curated minimal set. A strict \s+ match
      # missed this entirely and timed out waiting for a line that had
      # already printed. Those codes render in this log as LITERAL backslash-
      # escaped text (e.g. "...\x1b[36mready..."), not real ESC bytes -- so
      # "m" from "36m" directly abuts "ready" with no word boundary, which is
      # why a \bready\b tightening (tried once) also failed to match; a bare
      # substring check is what actually works here. The resulting collision
      # risk with "already" is theoretical -- no such line has been observed
      # on this "[gateway]"-tagged forwarded-stdout path in practice.
      if (Select-String -Path $gwLog -Pattern '\[gateway\].*ready' -Quiet -ErrorAction SilentlyContinue) { $openclawReady = $true; break }
    }
    Start-Sleep -Seconds 2
  }
  if (-not $openclawReady) { throw "OpenClaw did not report ready within 90s (see gateway.log in the results bundle)" }
  Ok "OpenClaw gateway ready"

  # 10. openshell forward service: opens a fresh, on-demand relay for this
  #     one call and bridges TargetPort (inside the sandbox) to
  #     ForwardLocalPort (on this host). No port needs to be pre-declared
  #     anywhere except pc_relay_target_port's startup liveness check.
  Step "openshell forward service --target-port $TargetPort --local $ForwardLocalPort"
  $fwdProc = Start-Process -FilePath $cli `
    -ArgumentList @("forward", "service", "--target-port", "$TargetPort", "--local", "$ForwardLocalPort", $SandboxName) `
    -WorkingDirectory $here -PassThru -NoNewWindow `
    -RedirectStandardOutput $fwdLog -RedirectStandardError $fwdErrLog
  Info "forward pid $($fwdProc.Id)"
  $fwdDeadline = (Get-Date).AddSeconds(20); $fwdUp = $false
  while ((Get-Date) -lt $fwdDeadline) {
    if ($fwdProc.HasExited) { throw "forward process exited early (code $($fwdProc.ExitCode)); see forward.log/forward.err.log" }
    if ((Test-Path $fwdLog) -and (Select-String -Path $fwdLog -Pattern 'Forwarding' -Quiet -ErrorAction SilentlyContinue)) { $fwdUp = $true; break }
    if ((Test-Path $fwdErrLog) -and (Select-String -Path $fwdErrLog -Pattern 'Forwarding' -Quiet -ErrorAction SilentlyContinue)) { $fwdUp = $true; break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $fwdUp) { throw "forward did not report 'Forwarding ...' within 20s; see forward.log/forward.err.log" }
  Ok "forward active: 127.0.0.1:$ForwardLocalPort -> sandbox:$TargetPort"

  # 11. Real OpenClaw client, on the HOST, through the forwarded port. This
  #     is the actual end-to-end proof: authenticate + get a real response
  #     from the sandboxed gateway via the relay, exactly as an external
  #     client would use `openshell forward service` in practice.
  #
  #     Retried: OpenClaw's own log declares a startup-grace window ("[health-
  #     monitor] started (interval: 300s, startup-grace: 60s, ...)") after
  #     printing "[gateway] ready" -- on a slower/more heavily-loaded machine
  #     (observed on a domain-joined box with corporate AV/EDR) it can still
  #     be settling internally for longer than that, and a request landing in
  #     that window gets silently dropped with ZERO trace in any log (not a
  #     WS close, not an error -- the client's own 10s timeout just fires).
  #     Each attempt already blocks for up to 10s on failure, so a handful of
  #     attempts comfortably covers the declared 60s grace without a fixed
  #     sleep that would either undershoot on a slow box or waste time on a
  #     fast one.
  Step "OpenClaw client: gateway health via the forwarded port"
  $healthArgs = @($openClawEntry, "gateway", "health", "--port", "$ForwardLocalPort", "--token", $GatewayToken, "--json")
  # Isolate the 2026.7.1 host client from any newer ~/.openclaw schema/state.
  $savedOpenClawConfigPath = $env:OPENCLAW_CONFIG_PATH
  $savedOpenClawStateDir = $env:OPENCLAW_STATE_DIR
  $cleanOpenClawStateDir = Join-Path $ShareDir "home\.openclaw"
  try {
    $env:OPENCLAW_CONFIG_PATH = Join-Path $cleanOpenClawStateDir "openclaw.json"
    $env:OPENCLAW_STATE_DIR = $cleanOpenClawStateDir
    # Bumped from 6 -> 14 (2026-09-10): on this box OpenClaw's actual startup
    # (port bind -> SQLite agent-db open -> HTTP server listening -> "ready")
    # measured ~90s wall clock, longer than 6 attempts' ~60s budget covers --
    # the sandbox was torn down mid-startup before the health check could ever
    # succeed. 14 attempts at up to 10s each comfortably covers 90s+ without
    # a fixed sleep that would undershoot on a slower box.
    $healthAttempts = 14
    for ($attempt = 1; $attempt -le $healthAttempts; $attempt++) {
      $healthRaw = & $NodeExePath @healthArgs 2>&1
      $healthRaw | Out-File (Join-Path $resultDir "openclaw-health-raw.txt") -Encoding UTF8
      # --json output is PRETTY-PRINTED (multi-line), not compact -- extract from
      # the first '{' to the last '}' across the whole output rather than
      # assuming any single line is a complete JSON document.
      $rawJoined = ($healthRaw | ForEach-Object { [string]$_ }) -join "`n"
      $startIdx = $rawJoined.IndexOf('{')
      $endIdx   = $rawJoined.LastIndexOf('}')
      $healthJson = $null
      if ($startIdx -ge 0 -and $endIdx -gt $startIdx) {
        $jsonText = $rawJoined.Substring($startIdx, $endIdx - $startIdx + 1)
        try { $healthJson = $jsonText | ConvertFrom-Json } catch { Info "could not parse health JSON: $($_.Exception.Message)" }
      }
      if ($healthJson -and $healthJson.ok -eq $true) {
        $passed = $true
        Ok "gateway health: ok=true (attempt $attempt/$healthAttempts)"
        break
      } else {
        Info "attempt $attempt/${healthAttempts}: no ok=true response yet$(if ($attempt -lt $healthAttempts) { ' -- retrying (still inside OpenClaws own startup-grace window)' })"
      }
    }
    if (-not $passed) {
      Bad "gateway health did not report ok=true after $healthAttempts attempts"
      $healthRaw | ForEach-Object { Info "$_" }
    }

    # Treat egress as a qualification gate, not just diagnostic output. The
    # capture script runs these probes before importing OpenClaw, so the record
    # is available by the time gateway health succeeds.
    Step "Verify governed egress evidence"
    $capturePath = Join-Path $ShareDir "openclaw-capture.log"
    $proofMatch = Select-String -Path $capturePath -Pattern '^\[egress-proof\] (?<json>\{.*\})$' -ErrorAction SilentlyContinue | Select-Object -Last 1
    $proof = $null
    if ($proofMatch) {
      try { $proof = $proofMatch.Matches[0].Groups['json'].Value | ConvertFrom-Json }
      catch { Info "could not parse egress proof JSON: $($_.Exception.Message)" }
    }
    $proofPassed = $proof -and
      $proof.proxyConfigured -eq $true -and
      $proof.allowedViaProxy.connected -eq $true -and
      $proof.deniedViaProxy.connected -eq $false -and
      $proof.directInternetBypass.connected -eq $false
    if ($proofPassed) {
      Ok "allowed host passed proxy; denied host and direct Internet bypass were blocked"
      Info "unrelated host loopback reachable: $($proof.unrelatedHostLoopback.connected) (known limitation)"
    } else {
      $passed = $false
      Bad "governed egress proof failed or was not recorded"
    }
  } finally {
    if ($null -eq $savedOpenClawConfigPath) {
      Remove-Item Env:OPENCLAW_CONFIG_PATH -ErrorAction SilentlyContinue
    } else {
      $env:OPENCLAW_CONFIG_PATH = $savedOpenClawConfigPath
    }
    if ($null -eq $savedOpenClawStateDir) {
      Remove-Item Env:OPENCLAW_STATE_DIR -ErrorAction SilentlyContinue
    } else {
      $env:OPENCLAW_STATE_DIR = $savedOpenClawStateDir
    }
  }
}
catch {
  Bad $_.Exception.Message
}
finally {
  # Stop the forward before the sandbox so its relay tears down cleanly.
  if ($fwdProc -and -not $fwdProc.HasExited) {
    try { Stop-Process -Id $fwdProc.Id -Force -ErrorAction SilentlyContinue } catch {}
  }

  # Tear down the sandbox while the gateway is still up (delete needs it).
  if ($cli -and $SandboxName) {
    try { & $cli sandbox delete $SandboxName 2>&1 | Out-Null }
    catch { Info "sandbox teardown '$SandboxName': $($_.Exception.Message) (continuing)" }
  }

  if ($KeepRunning -and $gw -and -not $gw.HasExited) {
    Info "leaving gateway pid $($gw.Id) running (-KeepRunning); stop with: Stop-Process -Id $($gw.Id) -Force"
  } elseif ($gw -and -not $gw.HasExited) {
    Step "Cleanup"; Stop-Process -Id $gw.Id -Force -ErrorAction SilentlyContinue
    try { $gw.WaitForExit(5000) | Out-Null } catch {}
    Info "stopped gateway pid $($gw.Id)"
  }

  Step "Gateway log (tail)"
  if (Test-Path $gwLog) {
    Get-Content $gwLog -Tail 30 -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object { Info $_ }
  }

  # Copy the OpenClaw capture log (if it made it far enough to write one) for
  # post-hoc debugging, then extract only the credential-free target-side
  # self-probe outcome. The probe records a byte count, never response data.
  # It is diagnostic and cannot make the end-to-end verdict pass: only the
  # authenticated host-side OpenClaw client above owns that verdict.
  $captureLog = Join-Path $shareDirNorm "openclaw-capture.log"
  if (Test-Path $captureLog) {
    Copy-Item $captureLog (Join-Path $resultDir "openclaw-capture.log") -Force -ErrorAction SilentlyContinue
    $selfProbeLine = Select-String -Path $captureLog -Pattern '\[self-probe\] outcome=([^ ]+) response_bytes=([0-9]+)' -AllMatches -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($selfProbeLine -and $selfProbeLine.Matches.Count -gt 0) {
      $selfProbeOutcome = $selfProbeLine.Matches[0].Groups[1].Value
      $selfProbeResponseBytes = [int64]$selfProbeLine.Matches[0].Groups[2].Value
    } elseif (Select-String -Path $captureLog -Pattern '\[self-probe\] invalid_port' -Quiet -ErrorAction SilentlyContinue) {
      $selfProbeOutcome = "invalid-port"
    } elseif (Select-String -Path $captureLog -Pattern '\[self-probe-attempt\] started' -Quiet -ErrorAction SilentlyContinue) {
      $selfProbeOutcome = "started-no-completion"
    }
  }
  if ($selfProbeOutcome -eq "response" -and $selfProbeResponseBytes -gt 0) {
    Info "target-side self-probe: response ($selfProbeResponseBytes bytes); OpenClaw serviced a local sandbox connection"
  } else {
    Info "target-side self-probe: $selfProbeOutcome ($selfProbeResponseBytes bytes); inspect the sandboxed OpenClaw target/event loop"
  }

  Step "RESULT"
  $verdict = if ($passed) { "PASS" } else { "FAIL" }
  $summary = @"
OpenShell MXC OpenClaw + dynamic forward test
=====================================================================
timestamp         : $stamp
machine            : $env:COMPUTERNAME
verdict            : $verdict
sandbox            : $SandboxName
backend            : $Backend
config             : $tomlName
target_port        : $TargetPort (inside sandbox)
forward_local_port : $ForwardLocalPort (on this host)
wxc_exec           : $WxcExecPath
node_exe            : $NodeExePath
openclaw_install    : $OpenClawInstallDir
target_self_probe   : $selfProbeOutcome ($selfProbeResponseBytes response bytes; diagnostic only)

What PASS means: the gateway created a sandbox on the $Backend backend (no
in-sandbox supervisor process; ProcessContainer also has no inbound network
capability at all); openshell-supervisor-relay launched OpenClaw's gateway
inside it via the driver's control channel;
`openshell forward service` opened a fresh, on-demand WebSocket relay for
this one call (nothing pre-declared beyond the startup liveness port); and a
REAL OpenClaw client running on this host, talking only through that
forwarded port, authenticated with a token and got back a real 'ok: true'
health response. The egress proof also required an allowed HTTPS request to
pass through the OpenShell proxy while a denied host and direct Internet
bypass were blocked. Host loopback remains broadly reachable because dynamic
forwarding uses ephemeral loopback ports.

Files in this bundle:
  transcript.txt                    full console transcript
  gateway.log/.err.log              gateway stdout/stderr (includes
                                     forwarded sandbox stdout/stderr, tagged
                                     "wxc-exec stdout:"/"wxc-exec stderr:")
  forward.log/.err.log               `openshell forward service` stdout/stderr
  openclaw-health-raw.txt           raw output of the OpenClaw health client
  openclaw-capture.log              OpenClaw's own captured stdout/stderr
                                     plus credential-free target self-probe
                                     outcome/byte count (no response payload)
                                     (if the sandbox got far enough to write it)
  ${tomlBaseName}.used.toml         exact config used (wxc_exec_path patched)
  openclaw-gateway.used.yaml        exact policy used
"@
  Set-Content -Path (Join-Path $resultDir "summary.txt") -Value $summary -Encoding UTF8
  Write-Host $summary -ForegroundColor ($(if ($passed) { "Green" } else { "Red" }))

  try { Stop-Transcript | Out-Null } catch {}
  try {
    $zip = Join-Path $here "results-openclaw-forward-$stamp.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $resultDir "*") -DestinationPath $zip -Force
    Write-Host "`nBUNDLE: $zip" -ForegroundColor Yellow
    Write-Host "Hand that zip back for evaluation." -ForegroundColor Yellow
  } catch { Write-Host "zip failed: $($_.Exception.Message)" -ForegroundColor Red }
}

if ($passed) { exit 0 } else { exit 1 }
