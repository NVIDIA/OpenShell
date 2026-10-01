# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Validate the CLI <-> gateway mTLS control channel without creating an MXC
# sandbox. The gateway uses the in-process MXC mock only to satisfy compute-
# driver startup; the test itself exercises gateway registration, a live list
# RPC, and rejection of a client that presents no certificate.

[CmdletBinding()]
param(
  [string] $TlsDir = "C:\work\openshell-mtls",
  [ValidateRange(0, 65535)] [int] $Port = 0,
  [ValidateSet("openshell")] [string] $GatewayName = "openshell",
  [string] $GatewayPath,
  [string] $CliPath,
  [string] $OutputDir,
  [switch] $KeepRunning
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutputDir = if ([string]::IsNullOrWhiteSpace($OutputDir)) { $here } else { [System.IO.Path]::GetFullPath($OutputDir) }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$resultDir = Join-Path $OutputDir "results-mtls-$stamp-$PID"
New-Item -ItemType Directory -Path $resultDir | Out-Null
Start-Transcript -Path (Join-Path $resultDir "transcript.txt") -Force | Out-Null

function Step([string]$message) { Write-Host "`n=== $message ===" -ForegroundColor Cyan }
function Info([string]$message) { Write-Host "    $message" }
function Ok([string]$message) { Write-Host "[OK]   $message" -ForegroundColor Green }
function Bad([string]$message) { Write-Host "[FAIL] $message" -ForegroundColor Red }

function Resolve-Executable([string]$explicit, [string]$leaf) {
  $candidates = New-Object System.Collections.Generic.List[string]
  if (-not [string]::IsNullOrWhiteSpace($explicit)) { [void]$candidates.Add($explicit) }
  [void]$candidates.Add((Join-Path $here $leaf))
  [void]$candidates.Add((Join-Path (Join-Path $here "bin") $leaf))
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return [System.IO.Path]::GetFullPath($candidate)
    }
  }
  throw "$leaf was not found. Pass its path explicitly or place it beside this script."
}

function Get-AvailablePort {
  $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
  try {
    $listener.Start()
    return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
  } finally {
    $listener.Stop()
  }
}

function Test-Port([int]$candidate) {
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $pending = $client.BeginConnect("127.0.0.1", $candidate, $null, $null)
    if (-not $pending.AsyncWaitHandle.WaitOne(250)) { return $false }
    $client.EndConnect($pending)
    return $true
  } catch {
    return $false
  } finally {
    $client.Dispose()
  }
}

function Invoke-Native {
  param([string]$File, [string[]]$Arguments)
  $old = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $raw = & $File @Arguments 2>&1
    $code = $LASTEXITCODE
    $out = @($raw | ForEach-Object { [string] $_ })
    return [pscustomobject]@{ Out = $out; Code = $code }
  } finally {
    $ErrorActionPreference = $old
  }
}

function Restore-ProcessEnvironment([hashtable]$snapshot) {
  foreach ($name in $snapshot.Keys) {
    [Environment]::SetEnvironmentVariable($name, $snapshot[$name], "Process")
  }
}

$environmentNames = @(
  "OPENSHELL_COMPUTE_DRIVER",
  "OPENSHELL_GATEWAY",
  "OPENSHELL_GATEWAY_CONFIG",
  "OPENSHELL_LOCAL_TLS_DIR",
  "OPENSHELL_MXC_MOCK_WXC",
  "OPENSHELL_SYSTEM_GATEWAY_DIR",
  "XDG_CONFIG_HOME",
  "XDG_STATE_HOME"
)
$environmentSnapshot = @{}
foreach ($name in $environmentNames) {
  $environmentSnapshot[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

$gateway = $null
$cli = $null
$gw = $null
$gwLog = Join-Path $resultDir "gateway.log"
$gwErrLog = Join-Path $resultDir "gateway.err.log"
$stateRoot = $null
$leftRunning = $false
$passed = $true
$tlsEnabled = $false
$clientVerify = $false
$mtlsAuth = $false
$addOk = $false
$listOk = $false
$noCertRefused = $false

try {
  Step "Validate artifacts"
  $gateway = Resolve-Executable $GatewayPath "openshell-gateway.exe"
  $cli = Resolve-Executable $CliPath "openshell.exe"
  Info "found $gateway"
  Info "found $cli"
  Info "machine: $env:COMPUTERNAME   user: $env:USERNAME   PS: $($PSVersionTable.PSVersion)"

  $TlsDir = [System.IO.Path]::GetFullPath($TlsDir)
  New-Item -ItemType Directory -Path $TlsDir -Force | Out-Null
  $stateRoot = Join-Path $TlsDir ".openshell-mtls-state-$PID-$([Guid]::NewGuid().ToString('N'))"
  $xdgConfigHome = Join-Path $stateRoot "config"
  $xdgStateHome = Join-Path $stateRoot "state"
  $systemConfigHome = Join-Path $stateRoot "system-config"
  foreach ($directory in @($xdgConfigHome, $xdgStateHome, $systemConfigHome)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
  }

  # Keep gateway registration, active selection, generated client materials,
  # and CLI state entirely inside this test-owned directory.
  $env:XDG_CONFIG_HOME = $xdgConfigHome
  $env:XDG_STATE_HOME = $xdgStateHome
  $env:OPENSHELL_SYSTEM_GATEWAY_DIR = $systemConfigHome
  [Environment]::SetEnvironmentVariable("OPENSHELL_GATEWAY", $null, "Process")

  Step "Generate isolated mTLS cert bundle -> $TlsDir"
  $certgen = Invoke-Native $gateway @("generate-certs", "--output-dir", $TlsDir)
  $certgen.Out | ForEach-Object { Info $_ }
  if ($certgen.Code -ne 0) { throw "generate-certs failed (exit $($certgen.Code))" }
  $bundle = @("ca.crt", "server\tls.crt", "server\tls.key", "client\tls.crt", "client\tls.key")
  $missing = $bundle | Where-Object { -not (Test-Path -LiteralPath (Join-Path $TlsDir $_) -PathType Leaf) }
  if ($missing) { throw "incomplete bundle, missing: $($missing -join ', ')" }
  Ok "5-file TLS bundle present (+ JWT material)"
  Copy-Item -LiteralPath (Join-Path $TlsDir "server\tls.crt") -Destination (Join-Path $resultDir "server-tls.crt") -Force

  if ($Port -eq 0) { $Port = Get-AvailablePort }
  Step "Check gateway port $Port is free"
  if (Test-Port $Port) {
    throw "port $Port is already accepting connections; choose another port with -Port. No process was stopped."
  }
  Ok "port $Port is free"

  # The control-channel test never creates a sandbox. A schema-v2 MXC config
  # plus the in-process mock provides a valid, dependency-free gateway startup.
  $mockWxc = Join-Path $stateRoot "mock-wxc-exec.exe"
  $escapedMockWxc = $mockWxc.Replace('\', '\\').Replace('"', '\"')
  $gatewayConfig = Join-Path $resultDir "gateway.used.toml"
  $gatewayConfigText = @"
[openshell]
version = 2

[openshell.drivers.mxc]
wxc_exec_path = "$escapedMockWxc"
backend = "process_container"
"@
  [System.IO.File]::WriteAllText($gatewayConfig, $gatewayConfigText, $utf8NoBom)

  Step "Start gateway with isolated state and mock MXC driver"
  $env:OPENSHELL_LOCAL_TLS_DIR = $TlsDir
  $env:OPENSHELL_GATEWAY_CONFIG = $gatewayConfig
  $env:OPENSHELL_COMPUTE_DRIVER = "mxc"
  $env:OPENSHELL_MXC_MOCK_WXC = "1"
  $gw = Start-Process -FilePath $gateway `
    -ArgumentList @("--db-url", "sqlite::memory:", "--port", "$Port", "--enable-mtls-auth", "true", "--log-level", "info") `
    -WorkingDirectory $here -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $gwLog -RedirectStandardError $gwErrLog
  Info "gateway pid $($gw.Id)"

  $deadline = (Get-Date).AddSeconds(30)
  while ((Get-Date) -lt $deadline -and -not (Test-Port $Port)) {
    if ($gw.HasExited) {
      $details = (Get-Content $gwLog, $gwErrLog -Encoding UTF8 -ErrorAction SilentlyContinue) -join "`n"
      throw "gateway exited before listening (code $($gw.ExitCode)): $details"
    }
    Start-Sleep -Milliseconds 250
  }
  if (-not (Test-Port $Port)) { throw "gateway did not start listening on $Port within 30 seconds" }

  Step "CLI over mTLS with isolated registration"
  $add = Invoke-Native $cli @("gateway", "add", "https://127.0.0.1:$Port", "--local", "--name", $GatewayName)
  $add.Out | ForEach-Object { Info $_ }
  $addOk = ($add.Code -eq 0)
  if (-not $addOk) { throw "gateway add failed (exit $($add.Code))" }
  $select = Invoke-Native $cli @("gateway", "select", $GatewayName)
  $select.Out | ForEach-Object { Info $_ }
  if ($select.Code -ne 0) { throw "gateway select failed (exit $($select.Code))" }
  Ok "gateway add/select over HTTPS succeeded"

  $list = Invoke-Native $cli @("sandbox", "list")
  $list.Out | ForEach-Object { Info $_ }
  $listOk = ($list.Code -eq 0)
  $tlsEnabled = $listOk
  if ($listOk) { Ok "sandbox list over mTLS succeeded (decisive round trip)" } else { Bad "sandbox list failed"; $passed = $false }

  Step "Negative: client with NO certificate must be refused"
  $curl = Invoke-Native "curl.exe" @("-sS", "--insecure", "--max-time", "6", "https://127.0.0.1:$Port/")
  $curlExit = $curl.Code
  $curl.Out | ForEach-Object { Info $_ }
  Start-Sleep -Milliseconds 500
  $logNow = (Get-Content $gwLog, $gwErrLog -Encoding UTF8 -ErrorAction SilentlyContinue) -join "`n"
  $noCertRefused = ($curlExit -ne 0) -and ($logNow -match 'handshake failed.*no certificates|peer sent no certificates|certificate required|bad certificate')
  if ($noCertRefused) { Ok "no-cert client refused (curl exit $curlExit + gateway logged the rejection)" } else { Bad "no-cert client was NOT clearly refused (curl exit $curlExit)"; $passed = $false }
  $clientVerify = $noCertRefused
  $mtlsAuth = $tlsEnabled -and $clientVerify
  if ($tlsEnabled) { Ok "TLS enabled: CLI completed a trusted HTTPS RPC" }
  if ($clientVerify) { Ok "client certificate verification enabled: no-cert handshake rejected" }
  if ($mtlsAuth) { Ok "mTLS authentication enabled: certified CLI accepted and no-cert client refused" }
} catch {
  Bad $_.Exception.Message
  $passed = $false
} finally {
  if ($KeepRunning -and $gw -and -not $gw.HasExited) {
    $leftRunning = $true
    Info "leaving gateway pid $($gw.Id) running (-KeepRunning)"
    Info "isolated CLI state is preserved at $stateRoot"
  } elseif ($gw -and -not $gw.HasExited) {
    Step "Cleanup"
    Stop-Process -Id $gw.Id -Force -ErrorAction SilentlyContinue
    try { [void] $gw.WaitForExit(5000) } catch {}
    Info "stopped test-owned gateway pid $($gw.Id)"
  }

  Restore-ProcessEnvironment $environmentSnapshot
  if (-not $leftRunning -and $stateRoot -and (Test-Path -LiteralPath $stateRoot)) {
    Remove-Item -LiteralPath $stateRoot -Recurse -Force -ErrorAction SilentlyContinue
  }

  Step "Gateway log (tail)"
  Get-Content $gwLog, $gwErrLog -Tail 25 -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object { Info $_ }

  Step "RESULT"
  $verdict = if ($passed) { "PASS" } else { "FAIL" }
  $summary = @"
OpenShell CLI<->gateway mTLS test (T2)
======================================
timestamp                 : $stamp
machine                   : $env:COMPUTERNAME
verdict                   : $verdict
tls_enabled               : $tlsEnabled
client_cert_verification  : $clientVerify
mtls_user_auth            : $mtlsAuth
cli_gateway_add_ok        : $addOk
cli_sandbox_list_ok       : $listOk
no_cert_client_refused    : $noCertRefused
gateway_port              : $Port
tls_bundle_dir            : $TlsDir
isolated_cli_state        : $stateRoot
gateway_left_running      : $leftRunning

PASS means the gateway served its management API over mutual TLS, the CLI
completed a real list RPC over that channel, and a client with no certificate
was refused. The in-process MXC mock is startup plumbing only; no sandbox or
inference endpoint is exercised. Existing OpenShell CLI state is not modified.
Throwaway private keys are not included in the result bundle.
"@
  [System.IO.File]::WriteAllText((Join-Path $resultDir "summary.txt"), $summary, $utf8NoBom)
  Write-Host $summary -ForegroundColor ($(if ($passed) { "Green" } else { "Red" }))

  try { Stop-Transcript | Out-Null } catch {}
  try {
    $zip = Join-Path $OutputDir "results-mtls-$stamp-$PID.zip"
    Compress-Archive -Path (Join-Path $resultDir "*") -DestinationPath $zip -Force
    Write-Host "`nBUNDLE: $zip" -ForegroundColor Yellow
  } catch {
    Write-Host "zip failed: $($_.Exception.Message)" -ForegroundColor Red
  }
}

if ($passed) { exit 0 } else { exit 1 }
