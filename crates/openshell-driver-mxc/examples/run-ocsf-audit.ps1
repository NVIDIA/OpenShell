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
  # Host folder mapped read-write into the sandbox (must match ocsf-audit.yaml).
  [string] $ShareDir     = "C:\work\openshell-mxc-demo",
  # How many sandboxes to create (each drives a full event burst).
  [int]    $SandboxCount = 2,
  # Disable the per-sandbox egress proxy (omits the SandboxProxyConfigured event).
  [switch] $NoProxy,
  # Gateway bind port (matches the gateway default) + CLI registration name.
  [int]    $Port         = 17670,
  [string] $GatewayName  = "openshell-mxc-ocsf",
  # Internal driver ETW session name (used to clean up a leaked session).
  [string] $SessionName  = "OpenShell-MXC-ETW",
  # Optional: copy the results bundle to this path (e.g. a shared drive) for
  # pickup. Empty by default (no copy); pass -ShareOut '\\server\share' to enable.
  [string] $ShareOut     = "",
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

$gateway = Join-Path $here "openshell-gateway.exe"
$cli     = Join-Path $here "openshell.exe"
$policy  = Join-Path $here "ocsf-audit.yaml"
$tomlSrc = Join-Path $here "mxc-ocsf-audit.toml"
$toml    = Join-Path $resultDir "mxc-ocsf-audit.used.toml"   # disposable patched copy (bundled)

$gw       = $null
$passed   = $true
$proxyOn  = -not $NoProxy

try {
  # 1. Validate artifacts + privilege.
  Step "Validate package artifacts"
  foreach ($f in @($gateway, $cli, $policy, $tomlSrc)) {
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

  if (-not (Test-Path $WxcExecPath)) {
    throw "wxc-exec not found at '$WxcExecPath'. Pass -WxcExecPath pointing at the real binary."
  }
  Info "wxc-exec: $WxcExecPath"

  # 2. Patch the disposable TOML copy: wxc path + backend + etw_audit + egress.
  Step "Patch gateway config (disposable copy)"
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
  Copy-Item $policy (Join-Path $resultDir "ocsf-audit.used.yaml") -Force
  Info "backend=process_container  etw_audit=true  egress_proxy=$proxyVal"

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
  #    real-time ETW session LEAKS and can starve the next run's capture. Stop
  #    any leftover before we start.
  Step "ETW session pre-flight"
  $leaked = @(logman query -ets 2>$null | Select-String -SimpleMatch $SessionName)
  Info "leaked '$SessionName' sessions before run: $($leaked.Count)"
  if ($leaked.Count -gt 0) { logman stop $SessionName -ets 2>&1 | Out-Null; Info "stopped leaked session(s)" }

  # 5. Prepare share folder.
  New-Item -ItemType Directory -Force $ShareDir | Out-Null
  Remove-Item (Join-Path $ShareDir "hello.txt") -Force -ErrorAction SilentlyContinue

  # 6. Gateway environment. Enable the durable OCSF JSONL audit sink and point it
  #    at THIS run's dir so the log lands directly in the bundle.
  $env:OPENSHELL_DRIVERS       = "mxc"
  $env:OPENSHELL_MXC_SHARE_DIR = $ShareDir
  $env:OPENSHELL_WXC_EXEC_PATH = $WxcExecPath
  $env:OPENSHELL_OCSF_JSON     = "1"
  $env:OPENSHELL_OCSF_LOG_DIR  = $resultDir
  Remove-Item Env:OPENSHELL_MXC_MOCK_WXC -ErrorAction SilentlyContinue

  # 7. Start the gateway (background, TLS disabled on the loopback control plane).
  Step "Start gateway (OCSF audit on)"
  $gwLog    = Join-Path $resultDir "gateway.log"
  $gwErrLog = Join-Path $resultDir "gateway.err.log"
  $gw = Start-Process -FilePath $gateway `
    -ArgumentList @("--disable-tls", "--config", $toml, "--log-level", "info") `
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

  # 9. Register CLI -> gateway.
  Step "Register CLI -> gateway"
  $env:OPENSHELL_GATEWAY = ""
  try { & $cli gateway add "http://127.0.0.1:$Port" --local --name $GatewayName 2>&1 | ForEach-Object { Info $_ } }
  catch { Info "gateway add: $($_.Exception.Message) (continuing - likely already registered)" }
  try { & $cli gateway select $GatewayName 2>&1 | ForEach-Object { Info $_ } }
  catch { Info "gateway select: $($_.Exception.Message) (continuing)" }
  Ok "selected gateway '$GatewayName'"

  # 10. Create N sandboxes. Each drives the Sandboxing provider -> a full OCSF
  #     event burst. The post-create interactive attach failure is EXPECTED on
  #     MXC (no in-sandbox supervisor) and harmless - the agent already ran.
  Step "Create $SandboxCount sandbox(es) (drives the Sandboxing provider)"
  for ($i = 1; $i -le $SandboxCount; $i++) {
    $name = "ocsf$i"
    Info "-- creating $name --"
    try { & $cli sandbox create --name $name --policy $policy --no-tty -- exit 2>&1 | ForEach-Object { Info $_ } }
    catch { Info "sandbox create attach: $($_.Exception.Message) (expected on MXC - agent ran in-driver; continuing)" }
    Start-Sleep -Seconds 3
    try { & $cli sandbox delete $name 2>&1 | Out-Null } catch {}
  }
}
catch {
  Bad $_.Exception.Message
  $passed = $false
}
finally {
  # Stop the gateway FIRST so it releases its log + JSONL file handles.
  if ($KeepRunning -and $gw -and -not $gw.HasExited) {
    Info "leaving gateway pid $($gw.Id) running (-KeepRunning); stop it with: Stop-Process -Id $($gw.Id) -Force"
  } elseif ($gw -and -not $gw.HasExited) {
    Step "Cleanup"
    Stop-Process -Id $gw.Id -Force -ErrorAction SilentlyContinue
    try { $gw.WaitForExit(5000) | Out-Null } catch {}
    Info "stopped gateway pid $($gw.Id)"
  }
  # Belt-and-suspenders: force-kill skips Drop, so stop the leaked session here.
  if (-not $KeepRunning) { logman stop $SessionName -ets 2>&1 | Out-Null }

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

  # Locate the durable OCSF JSONL audit log and tally by OCSF class.
  $jsonlFiles = @(Get-ChildItem -Path $resultDir -Filter "openshell-ocsf*.log" -ErrorAction SilentlyContinue)
  $jsonlPath  = if ($jsonlFiles.Count) { $jsonlFiles[0].FullName } else { $null }
  $classNames = @{ 6002 = "Application Lifecycle"; 5019 = "Device Config State Change"; 1007 = "Process Activity"; 2004 = "Detection Finding" }
  $classCounts = @{ 6002 = 0; 5019 = 0; 1007 = 0; 2004 = 0 }
  $jsonlCount = 0; $jsonlBad = 0; $sids = @(); $hosts = @()
  if ($jsonlPath) {
    $raw = @(Get-Content $jsonlPath -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne "" })
    $jsonlCount = $raw.Count
    foreach ($line in $raw) {
      try {
        $o = $line | ConvertFrom-Json
        if ($o.class_uid -ne $null -and $classCounts.ContainsKey([int]$o.class_uid)) { $classCounts[[int]$o.class_uid]++ }
        if ($o.metadata -and $o.metadata.uid) { $sids += [string]$o.metadata.uid }
        if ($o.device -and $o.device.hostname) { $hosts += [string]$o.device.hostname }
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
    "process launch (command line)" = Seen "(?i)ocsf:.*PROC:LAUNCH"
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
  if ($passed) { $passed = $consumerStarted -and ($jsonlCount -gt 0) -and ($jsonlBad -eq 0) -and ($coreObserved -eq $coreExpected) }

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
event coverage   : $coreObserved of $coreExpected expected event types fired   (+ $findingsObserved anomaly finding(s))
proxy            : $(if ($proxyOn) { 'on (full event set)' } else { 'off (-NoProxy; omits egress proxy event)' })
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

What PASS means: the gateway launched sandbox(es), the in-process ETW consumer
started, decoded the Sandboxing provider, attributed each event to a sandbox_id,
mapped them to OCSF, and wrote a durable JSONL audit log covering all $coreExpected
expected event types across $classesSeen OCSF class(es) - the full Windows OCSF path
end-to-end, at parity with the Linux pipeline.
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
