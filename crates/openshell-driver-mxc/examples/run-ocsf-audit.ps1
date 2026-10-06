# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# run-ocsf-audit.ps1 - gateway-driven ETW -> OCSF audit-trail example for OpenShell/MXC.
#
# Proves the FULL product path on the test box AND produces a durable OCSF log:
#   start gateway (etw_audit on, OCSF JSONL on) -> register CLI ->
#   create N sandboxes (each drives the OS "Sandboxing" ETW provider) ->
#   the in-process consumer decodes, attributes, and maps every event to OCSF ->
#   tear the sandboxes + gateway down -> collect the OCSF log + every artifact
#   into a results\ folder -> zip it.
#
# The deliverable is the OCSF audit log itself: openshell-ocsf.<date>.log, a
# durable JSONL file with one OCSF event object per line - the same schema and
# medium the Linux OpenShell pipeline produces.
#
# MUST RUN ELEVATED. Opening the real-time ETW session requires an elevated shell
# (Run as administrator) or an account in the 'Performance Log Users' group.
#
# Run from inside the package folder (gateway + cli + mxc-ocsf-audit.toml +
# ocsf-audit.yaml + this script all sit together):
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-ocsf-audit.ps1 `
#     -WxcExecPath C:\mxc-kit\bin\wxc-exec.exe
#
# Hosted CI can pass -Mock. That mode runs the complete gateway/CLI/script path
# with the in-process wxc shim, then requires the ETW consumer's durable
# mxc-etw-zero-events OCSF finding. It does not prove real provider events,
# attribution, or MXC enforcement.
#
# By default the per-sandbox egress proxy is ON so the full event set (including
# SandboxProxyConfigured) is produced. Pass -NoProxy to omit only that one event.
#
# The deliverable is the OCSF audit log (openshell-ocsf.<date>.log) inside the
# results-*.zip the script produces. Pass -ShareOut '\\server\share' to also copy
# the bundle to a shared location (off by default).

[CmdletBinding()]
param(
  # Real wxc-exec on the test box.
  [string] $WxcExecPath  = "C:\mxc-kit\bin\wxc-exec.exe",
  [string] $GatewayPath,
  [string] $CliPath,
  # Host folder granted read-write in the disposable sandbox policy.
  [string] $ShareDir     = "C:\work\openshell-mxc-demo",
  # How many sandboxes to create (each drives a full event burst).
  [int]    $SandboxCount = 2,
  # Disable the per-sandbox egress proxy (omits the SandboxProxyConfigured event).
  [switch] $NoProxy,
  # Gateway bind port (matches the gateway default) + CLI registration name.
  [int]    $Port         = 17670,
  [string] $GatewayName  = "openshell-mxc-ocsf",
  # Internal driver ETW session prefix (used to find owned or proven-stale sessions).
  [string] $SessionName  = "OpenShell-MXC-ETW",
  # Optional: copy the results bundle to this path (e.g. a shared drive) for
  # pickup. Empty by default (no copy); pass -ShareOut '\\server\share' to enable.
  [string] $ShareOut     = "",
  # Run with the in-process wxc shim and score the zero-event audit diagnostic.
  [switch] $Mock,
  [ValidateRange(31, 120)]
  [int]    $MockAuditWaitSeconds = 35,
  # Leave the gateway running afterward (for inspection).
  [switch] $KeepRunning
)

$ErrorActionPreference = "Stop"
# Don't let expected non-zero CLI exits (e.g. the post-create attach) throw on PS 7.4+.
$PSNativeCommandUseErrorActionPreference = $false
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# Results bundle (everything we hand back) ------------------------------------
$stamp     = Get-Date -Format "yyyyMMdd-HHmmss"
$resultDir = Join-Path $here "results-$stamp"
New-Item -ItemType Directory -Force $resultDir | Out-Null
Start-Transcript -Path (Join-Path $resultDir "transcript.txt") -Force | Out-Null

function Step([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Info([string]$m) { Write-Host "    $m" }
function Ok([string]$m)   { Write-Host "[OK]   $m" -ForegroundColor Green }
function Bad([string]$m)  { Write-Host "[FAIL] $m" -ForegroundColor Red }

function Quote-NativeArgument([string]$value) {
  if ($value.Length -gt 0 -and $value -notmatch '[\s"]') { return $value }

  $quoted = New-Object System.Text.StringBuilder
  [void]$quoted.Append('"')
  $backslashes = 0
  foreach ($ch in $value.ToCharArray()) {
    if ($ch -eq '\') {
      $backslashes++
      continue
    }
    if ($ch -eq '"') {
      [void]$quoted.Append(('\' * (2 * $backslashes + 1)))
      [void]$quoted.Append('"')
    } else {
      if ($backslashes -gt 0) { [void]$quoted.Append(('\' * $backslashes)) }
      [void]$quoted.Append($ch)
    }
    $backslashes = 0
  }
  if ($backslashes -gt 0) { [void]$quoted.Append(('\' * (2 * $backslashes))) }
  [void]$quoted.Append('"')
  return $quoted.ToString()
}

function Invoke-Cli([string[]]$CommandArgs, [switch]$AllowFailure) {
  $startInfo = New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName = $cli
  $startInfo.Arguments = (($CommandArgs | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true

  $process = New-Object System.Diagnostics.Process
  $process.StartInfo = $startInfo
  if (-not $process.Start()) { throw "failed to start $cli" }
  $stdout = $process.StandardOutput.ReadToEndAsync()
  $stderr = $process.StandardError.ReadToEndAsync()
  $process.WaitForExit()
  $text = (@($stdout.Result, $stderr.Result) | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_)
  }) -join [Environment]::NewLine
  $text = $text.Trim()
  if (-not $AllowFailure -and $process.ExitCode -ne 0) {
    throw "openshell $($CommandArgs -join ' ') failed (exit $($process.ExitCode)): $text"
  }
  return @{
    ExitCode = $process.ExitCode
    Text = $text
  }
}

function Resolve-Artifact([string]$explicit, [string]$leaf) {
  if (-not [string]::IsNullOrWhiteSpace($explicit)) {
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($explicit)
  }
  return (Join-Path $here $leaf)
}

function Get-MxcEtwSessions {
  $pattern = [regex]::Escape($SessionName) + '-(?<pid>[0-9]+)-[0-9a-fA-F]{32}-[0-9a-fA-F]{8}'
  foreach ($line in @(logman query -ets 2>$null)) {
    $match = [regex]::Match([string]$line, $pattern)
    if ($match.Success) {
      [pscustomobject]@{
        Name = $match.Value
        Pid  = [int]$match.Groups['pid'].Value
      }
    }
  }
}

$cliStateRoot = $null
$cliEnvironmentSnapshot = @{}
$cliEnvironmentNames = @(
  "APPDATA",
  "LOCALAPPDATA",
  "XDG_CONFIG_HOME",
  "XDG_STATE_HOME",
  "XDG_DATA_HOME",
  "OPENSHELL_GATEWAY",
  "OPENSHELL_GATEWAY_ENDPOINT",
  "OPENSHELL_GATEWAY_INSECURE",
  "OPENSHELL_GATEWAY_CONFIG",
  "OPENSHELL_GATEWAY_NAME"
)

function Enter-IsolatedCliEnvironment {
  foreach ($name in $cliEnvironmentNames) {
    $script:cliEnvironmentSnapshot[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
  }
  $script:cliStateRoot = Join-Path ([IO.Path]::GetTempPath()) "openshell-mxc-ocsf-cli-$PID-$([Guid]::NewGuid().ToString('N'))"
  $isolatedPaths = @{
    APPDATA = Join-Path $script:cliStateRoot "appdata"
    LOCALAPPDATA = Join-Path $script:cliStateRoot "localappdata"
    XDG_CONFIG_HOME = Join-Path $script:cliStateRoot "xdg-config"
    XDG_STATE_HOME = Join-Path $script:cliStateRoot "xdg-state"
    XDG_DATA_HOME = Join-Path $script:cliStateRoot "xdg-data"
  }
  try {
    New-Item -ItemType Directory -Force -Path @($isolatedPaths.Values) | Out-Null
    foreach ($entry in $isolatedPaths.GetEnumerator()) {
      [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
    }
    foreach ($name in $cliEnvironmentNames | Where-Object { -not $isolatedPaths.ContainsKey($_) }) {
      [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
  } catch {
    Exit-IsolatedCliEnvironment
    throw
  }
}

function Exit-IsolatedCliEnvironment {
  foreach ($name in $cliEnvironmentNames) {
    [Environment]::SetEnvironmentVariable($name, $script:cliEnvironmentSnapshot[$name], "Process")
  }
  if ($script:cliStateRoot -and (Test-Path -LiteralPath $script:cliStateRoot)) {
    Remove-Item -LiteralPath $script:cliStateRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

$gateway = Resolve-Artifact $GatewayPath "openshell-gateway.exe"
$cli     = Resolve-Artifact $CliPath "openshell.exe"
$policySrc = Join-Path $here "ocsf-audit.yaml"
$policy    = Join-Path $resultDir "ocsf-audit.used.yaml"   # disposable policy matching -ShareDir
$tomlSrc = Join-Path $here "mxc-ocsf-audit.toml"
$toml    = Join-Path $resultDir "mxc-ocsf-audit.used.toml"   # disposable patched copy (bundled)
$helloPath = Join-Path $ShareDir "hello.txt"

$gw       = $null
$gatewayEtwSessions = @()
$passed   = $true
$proxyOn  = -not $NoProxy
$oldMockWxc = $env:OPENSHELL_MXC_MOCK_WXC

try {
  Enter-IsolatedCliEnvironment

  # 1. Validate artifacts + privilege.
  Step "Validate package artifacts"
  foreach ($f in @($gateway, $cli, $policySrc, $tomlSrc)) {
    if (-not (Test-Path $f)) { throw "missing artifact: $f (run this script from inside the package folder)" }
    Info "found $(Split-Path $f -Leaf)"
  }
  Info "machine : $env:COMPUTERNAME   user: $env:USERNAME   PS: $($PSVersionTable.PSVersion)"

  # Opening the real-time ETW session requires elevation or 'Performance Log Users'.
  $wid   = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp    = New-Object Security.Principal.WindowsPrincipal($wid)
  $admin = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $plu   = $wp.IsInRole((New-Object Security.Principal.SecurityIdentifier("S-1-5-32-559")))
  Info "elevated=$admin  perfLogUsers=$plu"
  if (-not $admin -and -not $plu) {
    throw "This run must open a real-time ETW session, which needs elevation. Re-run from an elevated shell (Run as administrator) or add this account to 'Performance Log Users'."
  }

  if ($Mock) {
    $WxcExecPath = Join-Path $here "mock-wxc-exec.exe"
    Info "mock mode: using the in-process wxc shim"
  } elseif (-not (Test-Path $WxcExecPath)) {
    throw "wxc-exec not found at '$WxcExecPath'. Pass -WxcExecPath pointing at the real binary."
  }
  Info "wxc-exec: $WxcExecPath"

  # 2. Patch the disposable gateway config and derive a sandbox policy whose
  #    filesystem grant matches -ShareDir.
  Step "Prepare gateway config and sandbox policy (disposable copies)"
  $tomlText = Get-Content $tomlSrc -Raw
  $escaped  = $WxcExecPath.Replace('\', '\\')
  $tomlText = [regex]::Replace($tomlText, '(?m)^\s*#?\s*wxc_exec_path\s*=.*$', "wxc_exec_path = `"$escaped`"")
  $tomlText = [regex]::Replace($tomlText, '(?m)^\s*#?\s*backend\s*=.*$',       'backend = "process_container"')
  if ($tomlText -match '(?m)^\s*#?\s*etw_audit\s*=') {
    $tomlText = [regex]::Replace($tomlText, '(?m)^\s*#?\s*etw_audit\s*=.*$',   'etw_audit = true')
  } else {
    $tomlText = [regex]::Replace($tomlText, '(?m)^\[openshell\.drivers\.mxc\]\s*$', "[openshell.drivers.mxc]`r`netw_audit = true")
  }
  $proxyVal = if ($proxyOn) { 'true' } else { 'false' }
  if ($tomlText -match '(?m)^\s*#?\s*egress_proxy\s*=') {
    $tomlText = [regex]::Replace($tomlText, '(?m)^\s*#?\s*egress_proxy\s*=.*$', "egress_proxy = $proxyVal")
  } else {
    $tomlText = [regex]::Replace($tomlText, '(?m)^\[openshell\.drivers\.mxc\]\s*$', "[openshell.drivers.mxc]`r`negress_proxy = $proxyVal")
  }
  Set-Content $toml -Value $tomlText -Encoding UTF8

  $shareDirPolicy = $ShareDir.Replace('\', '/')
  $shareDirJson = ConvertTo-Json $shareDirPolicy -Compress
  $policyText = Get-Content $policySrc -Raw
  if (-not $proxyOn) {
    $policyText = [regex]::Replace($policyText, '(?ms)^network_policies:\s*.*\z', '')
  }
  $defaultGrant = '    - "C:/work/openshell-mxc-demo"'
  if (-not $policyText.Contains($defaultGrant)) {
    throw "policy template does not contain the expected default ShareDir grant"
  }
  $policyText = $policyText.Replace($defaultGrant, "    - $shareDirJson")
  Set-Content $policy -Value $policyText -Encoding UTF8

  $cmdExe = Join-Path $env:SystemRoot "System32\cmd.exe"
  if (-not (Test-Path $cmdExe -PathType Leaf)) { throw "cmd.exe not found at '$cmdExe'" }
  $helloPathCommand = $helloPath.Replace('\', '/')
  $driverConfig = @{
    mxc = @{
      command = @($cmdExe, "/c", "echo hello from openshell ocsf audit 1>`"$helloPathCommand`"")
      cwd = $shareDirPolicy
    }
  } | ConvertTo-Json -Compress -Depth 4
  Info "backend=process_container  etw_audit=true  egress_proxy=$proxyVal"
  Info "workload cwd=$shareDirPolicy  policy grant=$shareDirPolicy"

  # 3. Port must be free. Auto-clear a stale OUR-gateway; refuse anything else.
  Step "Check gateway port $Port is free"
  $busy = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
  if ($busy) {
    $owner = Get-Process -Id $busy.OwningProcess -ErrorAction SilentlyContinue
    if ($owner -and $owner.Name -eq "openshell-gateway") {
      Info "stale gateway on port $Port (pid $($owner.Id)) - stopping it"
      Stop-Process -Id $owner.Id -Force -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 2
    } else {
      throw "port $Port in use by '$($owner.Name)' (pid $($busy.OwningProcess)) - not our gateway; stop it and retry."
    }
  }
  Ok "port $Port free"

  # 4. ETW session pre-flight. A force-killed gateway never runs Drop, so its
  #    real-time ETW session can leak. Session names include their owning PID;
  #    stop only sessions whose process is proven gone and leave live gateways
  #    untouched.
  Step "ETW session pre-flight"
  $discoveredSessions = @(Get-MxcEtwSessions)
  $staleSessions = @($discoveredSessions | Where-Object {
    -not (Get-Process -Id $_.Pid -ErrorAction SilentlyContinue)
  })
  Info "'$SessionName' sessions before run: $($discoveredSessions.Count) total, $($staleSessions.Count) proven stale"
  foreach ($session in $staleSessions) {
    logman stop $session.Name -ets 2>&1 | Out-Null
    Info "stopped stale session '$($session.Name)'"
  }

  # 5. Prepare share folder.
  New-Item -ItemType Directory -Force $ShareDir | Out-Null
  Remove-Item $helloPath -Force -ErrorAction SilentlyContinue

  # 6. Gateway environment. Enable the durable OCSF JSONL audit sink and point it
  #    at THIS run's dir so the log lands directly in the bundle.
  $env:OPENSHELL_DRIVERS       = "mxc"
  $env:OPENSHELL_WXC_EXEC_PATH = $WxcExecPath
  $env:OPENSHELL_OCSF_JSON     = "1"
  $env:OPENSHELL_OCSF_LOG_DIR  = $resultDir
  # Config path goes through the env var (clap: OPENSHELL_GATEWAY_CONFIG), NOT a
  # --config token: Start-Process -ArgumentList does not quote array elements, so a
  # config path containing a space gets split and the gateway's arg parser rejects it.
  $env:OPENSHELL_GATEWAY_CONFIG = $toml
  if ($Mock) {
    $env:OPENSHELL_MXC_MOCK_WXC = "1"
  } else {
    Remove-Item Env:OPENSHELL_MXC_MOCK_WXC -ErrorAction SilentlyContinue
  }

  # 7. Start the gateway (background, TLS disabled on the loopback control plane).
  Step "Start gateway (OCSF audit on)"
  $gwLog    = Join-Path $resultDir "gateway.log"
  $gwErrLog = Join-Path $resultDir "gateway.err.log"
  $gw = Start-Process -FilePath $gateway `
    -ArgumentList @("--disable-tls", "--port", $Port, "--db-url", "sqlite::memory:", "--log-level", "info") `
    -WorkingDirectory $here -PassThru -NoNewWindow `
    -RedirectStandardOutput $gwLog -RedirectStandardError $gwErrLog
  Info "gateway pid $($gw.Id); logs -> $(Split-Path $gwLog -Leaf) (+ .err)"

  # 8. Wait until the gateway is listening.
  $deadline = (Get-Date).AddSeconds(30); $ready = $false
  while ((Get-Date) -lt $deadline) {
    if ($gw.HasExited) {
      Get-Content $gwLog, $gwErrLog -ErrorAction SilentlyContinue | ForEach-Object { Info $_ }
      throw "gateway exited early (code $($gw.ExitCode)). See logs above."
    }
    if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) { $ready = $true; break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $ready) { throw "gateway did not start listening on $Port within 30s." }
  Ok "gateway listening on 127.0.0.1:$Port"
  $gatewayEtwSessions = @(Get-MxcEtwSessions | Where-Object { $_.Pid -eq $gw.Id })
  if ($gatewayEtwSessions.Count -eq 1) {
    Info "gateway ETW session: $($gatewayEtwSessions[0].Name)"
  } else {
    Info "gateway ETW session lookup returned $($gatewayEtwSessions.Count) matches for pid $($gw.Id)"
  }

  # 9. Register CLI -> gateway.
  Step "Register CLI -> gateway"
  $expectedEndpoint = "http://127.0.0.1:$Port"
  $gatewayAdd = Invoke-Cli @("gateway", "add", $expectedEndpoint, "--local", "--name", $GatewayName) -AllowFailure
  if ($gatewayAdd.Text) { Info $gatewayAdd.Text }
  if ($gatewayAdd.ExitCode -ne 0) {
    throw "gateway registration failed (exit $($gatewayAdd.ExitCode)): $($gatewayAdd.Text)"
  }
  $gatewaySelect = Invoke-Cli @("gateway", "select", $GatewayName)
  if ($gatewaySelect.Text) { Info $gatewaySelect.Text }
  Ok "selected gateway '$GatewayName'"

  # 10. Create N sandboxes. Each drives the Sandboxing provider -> a full OCSF
  #     event burst. The post-create interactive attach failure is EXPECTED on
  #     MXC (no in-sandbox supervisor) and harmless - the agent already ran.
  Step "Create $SandboxCount sandbox(es) (drives the Sandboxing provider)"
  for ($i = 1; $i -le $SandboxCount; $i++) {
    $name = "ocsf$i"
    Info "-- creating $name --"
    $create = Invoke-Cli @(
      "sandbox", "create", "--name", $name, "--policy", $policy,
      "--driver-config-json", $driverConfig, "--no-tty"
    ) -AllowFailure
    if ($create.Text) { Info $create.Text }
    if ($create.ExitCode -ne 0) {
      Info "sandbox create returned exit $($create.ExitCode); workload and audit evidence will determine the verdict"
    }
    Start-Sleep -Seconds 3
    try { Invoke-Cli @("sandbox", "delete", $name) -AllowFailure | Out-Null } catch {}
  }
  if ($Mock) {
    Step "Wait for the ETW zero-event audit diagnostic"
    Info "waiting $MockAuditWaitSeconds seconds for mxc-etw-zero-events"
    Start-Sleep -Seconds $MockAuditWaitSeconds
  }
}
catch {
  Bad $_.Exception.Message
  $passed = $false
}
finally {
  if (-not $KeepRunning -and $gw -and $gatewayEtwSessions.Count -eq 0) {
    $gatewayEtwSessions = @(Get-MxcEtwSessions | Where-Object { $_.Pid -eq $gw.Id })
  }
  # Stop the gateway FIRST so it releases its log + JSONL file handles.
  if ($KeepRunning -and $gw -and -not $gw.HasExited) {
    Info "leaving gateway pid $($gw.Id) running (-KeepRunning); stop it with: Stop-Process -Id $($gw.Id) -Force"
  } elseif ($gw -and -not $gw.HasExited) {
    Step "Cleanup"
    Stop-Process -Id $gw.Id -Force -ErrorAction SilentlyContinue
    try { $gw.WaitForExit(5000) | Out-Null } catch {}
    Info "stopped gateway pid $($gw.Id)"
  }
  # Belt-and-suspenders: force-kill skips Drop, so stop only the exact session(s)
  # observed for the gateway process started by this run.
  if (-not $KeepRunning) {
    foreach ($session in $gatewayEtwSessions) {
      logman stop $session.Name -ets 2>&1 | Out-Null
    }
  }
  if ($null -eq $oldMockWxc) {
    Remove-Item Env:OPENSHELL_MXC_MOCK_WXC -ErrorAction SilentlyContinue
  } else {
    $env:OPENSHELL_MXC_MOCK_WXC = $oldMockWxc
  }
  Exit-IsolatedCliEnvironment

  # ---- summarise the OCSF audit trail --------------------------------------
  $logText = @()
  if (Test-Path (Join-Path $resultDir "gateway.log"))     { $logText += Get-Content (Join-Path $resultDir "gateway.log") }
  if (Test-Path (Join-Path $resultDir "gateway.err.log")) { $logText += Get-Content (Join-Path $resultDir "gateway.err.log") }
  # The gateway writes ANSI colour codes even when redirected; strip them so
  # matches are reliable.
  $esc = [char]27
  $logText = $logText | ForEach-Object { $_ -replace "$esc\[[0-9;]*m", "" }

  $consumerStarted = [bool]($logText | Select-String -SimpleMatch "consumer started" -Quiet)
  $consumerFailed  = [bool]($logText | Select-String -SimpleMatch "ETW audit consumer failed to start" -Quiet)
  $consumerOverloaded = [bool]($logText | Select-String -SimpleMatch "ETW audit queue overloaded" -Quiet)

  # Locate the durable OCSF JSONL audit log and tally by OCSF class.
  $jsonlFiles = @(Get-ChildItem -Path $resultDir -Filter "openshell-ocsf*.log" -ErrorAction SilentlyContinue)
  $jsonlPath  = if ($jsonlFiles.Count) { $jsonlFiles[0].FullName } else { $null }
  $classNames = @{ 6002 = "Application Lifecycle"; 5019 = "Device Config State Change"; 1007 = "Process Activity"; 2004 = "Detection Finding" }
  $classCounts = @{ 6002 = 0; 5019 = 0; 1007 = 0; 2004 = 0 }
  $jsonlCount = 0; $jsonlBad = 0; $sids = @(); $hosts = @(); $zeroEventFinding = $false
  if ($jsonlPath) {
    $raw = @(Get-Content $jsonlPath -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne "" })
    $jsonlCount = $raw.Count
    foreach ($line in $raw) {
      try {
        $o = $line | ConvertFrom-Json
        if ($o.class_uid -ne $null -and $classCounts.ContainsKey([int]$o.class_uid)) { $classCounts[[int]$o.class_uid]++ }
        if ($o.container -and $o.container.uid) { $sids += [string]$o.container.uid }
        if ($o.device -and $o.device.hostname) { $hosts += [string]$o.device.hostname }
        if ($o.finding_info -and $o.finding_info.uid -eq "mxc-etw-zero-events") { $zeroEventFinding = $true }
      } catch { $jsonlBad++ }
    }
    $sids  = @($sids  | Select-Object -Unique)
    $hosts = @($hosts | Select-Object -Unique)
  }

  # Event-type coverage (detected from the human-readable shorthand lines).
  function Seen([string]$pat) { [bool]($logText | Select-String -Pattern $pat -Quiet) }

  # Expected happy-path ETW->OCSF event types for THIS run. The egress-proxy
  # event only fires when the proxy is enabled, so it only counts toward the
  # expected total when -NoProxy was NOT passed.
  $coreEvents = [ordered]@{
    "sandbox lifecycle (start)"     = Seen "(?i)ocsf:.*LIFECYCLE:"
    "OS policy enforced"            = Seen "(?i)ocsf:.*OS policy enforced"
    "OS policy configured"          = Seen "(?i)ocsf:.*OS policy configured"
    "win32k lockdown applied"       = Seen "(?i)ocsf:.*win32k lockdown"
    "UI restrictions applied"       = Seen "(?i)ocsf:.*UI restrictions"
    "console reference plumbed"     = Seen "(?i)ocsf:.*console reference plumbed"
    "process launch (executable identity)" = Seen "(?i)ocsf:.*PROC:LAUNCH"
  }
  if ($proxyOn) { $coreEvents["egress proxy configured"] = Seen "(?i)ocsf:.*proxy configured" }

  # Findings are anomaly / fallback signals - reported separately, NOT part of
  # the expected-coverage denominator (a clean run may emit none).
  $findingEvents = [ordered]@{
    "ActivityError finding" = Seen "(?i)ocsf:.*ActivityError"
    "FallbackError finding" = Seen "(?i)ocsf:.*FallbackError"
  }

  $coreExpected     = $coreEvents.Count
  $coreObserved     = @($coreEvents.Values   | Where-Object { $_ }).Count
  $findingsObserved = @($findingEvents.Values | Where-Object { $_ }).Count
  $classesSeen      = @($classCounts.Keys | Where-Object { $classCounts[$_] -gt 0 }).Count
  $workloadCompleted = Test-Path $helloPath -PathType Leaf
  $zeroEventWarning = Seen "(?i)MXC ETW->OCSF consumer has received zero events"
  if ($passed) {
    if ($Mock) {
      $passed = $consumerStarted -and (-not $consumerFailed) -and (-not $consumerOverloaded) -and
        $workloadCompleted -and ($jsonlCount -gt 0) -and ($jsonlBad -eq 0) -and
        $zeroEventWarning -and $zeroEventFinding
    } else {
      $passed = $consumerStarted -and (-not $consumerOverloaded) -and $workloadCompleted -and
        ($jsonlCount -gt 0) -and ($jsonlBad -eq 0) -and ($coreObserved -eq $coreExpected)
    }
  }

  $verdict      = if ($passed) { "PASS" } else { "FAIL" }
  $classLines   = foreach ($uid in @(6002, 5019, 1007, 2004)) { "  [{0}] {1,-28} : {2}" -f $uid, $classNames[$uid], $classCounts[$uid] }
  $coreLines    = foreach ($k in $coreEvents.Keys)    { "  {0} {1}" -f $(if ($coreEvents[$k])    { "[x]" } else { "[ ]" }), $k }
  $findingLines = foreach ($k in $findingEvents.Keys) { "  {0} {1}" -f $(if ($findingEvents[$k]) { "[x]" } else { "[ ]" }), $k }

  Step "RESULT"
  $summary = @"
OpenShell MXC ETW -> OCSF audit trail
=====================================
timestamp        : $stamp
machine          : $env:COMPUTERNAME
user             : $env:USERNAME   (admin=$admin  perfLogUsers=$plu)
verdict          : $verdict
mode             : $(if ($Mock) { 'mock-wiring' } else { 'real-mxc' })
event coverage   : $coreObserved of $coreExpected expected event types fired   (+ $findingsObserved anomaly finding(s))
zero-event audit : $(if ($zeroEventWarning -and $zeroEventFinding) { 'warning + durable finding observed' } else { 'not observed' })
queue overload   : $(if ($consumerOverloaded) { 'YES - ETW records dropped; audit coverage gap' } else { 'no dropped ETW records observed' })
proxy            : $(if ($proxyOn) { 'on (full event set)' } else { 'off (-NoProxy; omits egress proxy event)' })
workload output  : $(if ($workloadCompleted) { $helloPath } else { '(missing)' })
wxc_exec         : $WxcExecPath
backend          : process_container
gateway_port     : $Port
sandboxes        : $SandboxCount   (distinct sandbox_ids in log: $($sids.Count))

Event-type coverage - $coreObserved of $coreExpected expected event types fired:
$($coreLines -join "`r`n")

Anomaly findings emitted (not counted toward coverage; a clean run may emit none): $findingsObserved
$($findingLines -join "`r`n")

OCSF events written : $jsonlCount total   ($jsonlBad invalid-json)   across $classesSeen OCSF class(es)
$($classLines -join "`r`n")

>> YOUR OCSF AUDIT LOG (the deliverable - durable JSONL, one OCSF event per line):
     $(if ($jsonlPath) { $jsonlPath } else { '(none written - see gateway.log)' })

Files in this bundle ($resultDir):
  openshell-ocsf.<date>.log   THE DELIVERABLE: durable OCSF audit trail (JSONL)
  summary.txt                 this summary
  transcript.txt              full console transcript
  gateway.log / .err.log      gateway stdout/stderr (OCSF shorthand lines live here)
  mxc-ocsf-audit.used.toml    the exact gateway config used (wxc path patched)
  ocsf-audit.used.yaml        the exact sandbox policy used

$(if ($Mock) {
"What PASS means: the gateway launched the mock workload, the ETW consumer
started, detected that sandbox activity produced zero provider events, and
wrote the mxc-etw-zero-events finding to durable OCSF JSONL. This does not
validate real Sandboxing-provider events, sandbox attribution, or MXC enforcement."
} else {
"What PASS means: the gateway launched sandbox(es), the in-process ETW consumer
started, decoded the Sandboxing provider, attributed each event to a sandbox_id,
reported no callback-queue overload, mapped events to OCSF, and wrote a durable
JSONL audit log covering all $coreExpected expected event types across
$classesSeen OCSF class(es) - the full Windows OCSF path end-to-end, at parity
with the Linux pipeline."
})
"@
  Set-Content -Path (Join-Path $resultDir "summary.txt") -Value $summary -Encoding UTF8
  Write-Host $summary -ForegroundColor ($(if ($passed) { "Green" } else { "Red" }))

  try { Stop-Transcript | Out-Null } catch {}

  # Zip the bundle for easy return (defensive; never throw out of finally).
  try {
    $zip = Join-Path $here "results-$stamp.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $resultDir "*") -DestinationPath $zip -Force
    Write-Host "`nResults bundle: $zip" -ForegroundColor Yellow
  } catch { Write-Host "zip failed: $($_.Exception.Message)" -ForegroundColor Red }

  # Auto-push the bundle to the shared drive for pickup/analysis (skip if we
  # already ran from the share, or if -ShareOut "" disables it).
  if (-not [string]::IsNullOrWhiteSpace($ShareOut)) {
    try {
      $alreadyThere = $false
      try { if ((Resolve-Path $here).Path -eq (Resolve-Path $ShareOut -ErrorAction SilentlyContinue).Path) { $alreadyThere = $true } } catch {}
      if ($alreadyThere) {
        Write-Host "PUSHED: results-$stamp (ran from share; already there)" -ForegroundColor Green
      } elseif (Test-Path $ShareOut) {
        if ($zip -and (Test-Path $zip)) { Copy-Item $zip (Join-Path $ShareOut "results-$stamp.zip") -Force }
        Write-Host "PUSHED: results-$stamp.zip -> $ShareOut" -ForegroundColor Green
      } else {
        Write-Host "share not reachable: $ShareOut (results local only at $resultDir)" -ForegroundColor Yellow
      }
    } catch { Write-Host "push failed: $($_.Exception.Message)" -ForegroundColor Yellow }
  }

  Write-Host "`nYour OCSF audit log:" -ForegroundColor Cyan
  Write-Host "  $(if ($jsonlPath) { $jsonlPath } else { '(none written - see gateway.log)' })" -ForegroundColor Green
}

if ($passed) { exit 0 } else { exit 1 }
