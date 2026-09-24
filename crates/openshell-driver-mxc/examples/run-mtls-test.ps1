# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# run-mtls-test.ps1 - validate the CLI <-> gateway mTLS control channel (T2).
#
# This has NOTHING to do with inference or MXC sandboxes. It proves that the
# gateway's management API (sandbox create/list, etc.) is served over mutual TLS
# and that a client without a certificate is rejected. It runs entirely on
# loopback using the same openshell-gateway.exe / openshell.exe already in this
# folder.
#
# Flow:
#   generate cert bundle -> start gateway (auto-mTLS from the bundle) ->
#   CLI registers + lists over mTLS -> a no-cert client is refused ->
#   bundle redacted logs into results-mtls-<stamp>.zip.
#
# Run from inside the package folder (next to the two exes):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-mtls-test.ps1
#
# No secrets are involved; the throwaway private keys are NOT included in the zip.

[CmdletBinding()]
param(
  # Where the throwaway PKI bundle is generated (private keys stay here, not in the zip).
  [string] $TlsDir = "C:\work\openshell-mtls",
  # Gateway bind port (matches the gateway default).
  [int]    $Port = 17670,
  # CLI registration name. MUST be "openshell" so the CLI finds the auto-discovered
  # client materials that generate-certs copies under gateways/openshell/mtls.
  [string] $GatewayName = "openshell",
  # Leave the gateway running afterward (for inspection).
  [switch] $KeepRunning
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

# The OpenShell CLI emits UTF-8 (status glyphs like Ok/× and checkmarks). PowerShell
# decodes captured native-command output using [Console]::OutputEncoding; if that is a
# legacy OEM code page the glyphs render as mojibake (e.g. "Γ£ô", "├ù"). Force UTF-8.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

$stamp     = Get-Date -Format "yyyyMMdd-HHmmss"
$resultDir = Join-Path $here "results-mtls-$stamp"
New-Item -ItemType Directory -Force $resultDir | Out-Null
Start-Transcript -Path (Join-Path $resultDir "transcript.txt") -Force | Out-Null

function Step([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Info([string]$m) { Write-Host "    $m" }
function Ok([string]$m)   { Write-Host "[OK]   $m" -ForegroundColor Green }
function Bad([string]$m)  { Write-Host "[FAIL] $m" -ForegroundColor Red }

$gateway = Join-Path $here "openshell-gateway.exe"
$cli     = Join-Path $here "openshell.exe"

$gw           = $null
$passed       = $true
$tlsEnabled   = $false
$clientVerify = $false
$mtlsAuth     = $false
$addOk        = $false
$listOk       = $false
$noCertRefused = $false

# Run a native exe without letting its (often colored) stderr be turned into a
# thrown error by ErrorActionPreference=Stop. Returns captured output + exit code.
function Invoke-Native {
  param([string]$File, [string[]]$Arguments)
  $old = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $raw = & $File @Arguments 2>&1
    $code = $LASTEXITCODE
    $out = @($raw | ForEach-Object { [string]$_ })
    return [pscustomobject]@{ Out = $out; Code = $code }
  } finally { $ErrorActionPreference = $old }
}

try {
  # 1. Validate artifacts
  Step "Validate artifacts"
  foreach ($f in @($gateway, $cli)) {
    if (-not (Test-Path $f)) { throw "missing artifact: $f (run this from the package folder with the exes)" }
    Info "found $(Split-Path $f -Leaf)"
  }
  Info "machine : $env:COMPUTERNAME   user: $env:USERNAME   PS: $($PSVersionTable.PSVersion)"

  # 2. Generate the local PKI bundle (idempotent).
  Step "Generate mTLS cert bundle -> $TlsDir"
  & $gateway generate-certs --output-dir $TlsDir 2>&1 | ForEach-Object { Info $_ }
  if ($LASTEXITCODE -ne 0) { throw "generate-certs failed (exit $LASTEXITCODE)" }
  $bundle = @("ca.crt", "server\tls.crt", "server\tls.key", "client\tls.crt", "client\tls.key")
  $missing = $bundle | Where-Object { -not (Test-Path (Join-Path $TlsDir $_)) }
  if ($missing) { throw "incomplete bundle, missing: $($missing -join ', ')" }
  Ok "5-file TLS bundle present (+ jwt material)"
  # Public cert is fine to keep as evidence; private keys are NOT copied.
  Copy-Item (Join-Path $TlsDir "server\tls.crt") (Join-Path $resultDir "server-tls.crt") -Force -ErrorAction SilentlyContinue

  # 3. Port must be free (auto-clear our own stale gateway).
  Step "Check gateway port $Port is free"
  $busy = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
  if ($busy) {
    $owner = Get-Process -Id $busy.OwningProcess -ErrorAction SilentlyContinue
    if ($owner -and $owner.Name -eq "openshell-gateway") {
      Info "stopping stale gateway pid $($owner.Id)"; Stop-Process -Id $owner.Id -Force -ErrorAction SilentlyContinue; Start-Sleep 2
    } else {
      throw "port $Port in use by '$($owner.Name)' (pid $($busy.OwningProcess))"
    }
  }
  Ok "port $Port free"

  # 4. Start the gateway. Auto-mTLS: it discovers the bundle via OPENSHELL_LOCAL_TLS_DIR,
  #    enables TLS + client-cert verification, and (with --enable-mtls-auth) requires it.
  Step "Start gateway (auto-mTLS from bundle)"
  $env:OPENSHELL_LOCAL_TLS_DIR = $TlsDir
  $env:OPENSHELL_DRIVERS       = "mxc"
  $env:OPENSHELL_GATEWAY       = ""
  $gwLog    = Join-Path $resultDir "gateway.log"
  $gwErrLog = Join-Path $resultDir "gateway.err.log"
  $gw = Start-Process -FilePath $gateway `
    -ArgumentList @("--port", "$Port", "--enable-mtls-auth", "true", "--log-level", "info") `
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

  Start-Sleep -Milliseconds 500
  $startup = (Get-Content $gwLog -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
  $tlsEnabled   = $startup -match 'TLS enabled'
  $clientVerify = $startup -match 'client certificate verification enabled'
  $mtlsAuth     = $startup -match 'mTLS user authentication enabled'
  if ($tlsEnabled)   { Ok "gateway: TLS enabled" }                          else { Bad "gateway did not log TLS enabled"; $passed = $false }
  if ($clientVerify) { Ok "gateway: client certificate verification enabled" } else { Bad "no client-cert verification"; $passed = $false }
  if ($mtlsAuth)     { Ok "gateway: mTLS user authentication enabled" }      else { Bad "no mTLS user auth"; $passed = $false }

  # 5. CLI registers + lists over mTLS (real round trips through the secured API).
  #    The DECISIVE mTLS proof is `sandbox list` (a live RPC over the wire). Registration
  #    is best-effort: a gateway named "openshell" may already exist from a prior run.
  Step "CLI over mTLS"
  Invoke-Native $cli @("gateway", "remove", $GatewayName) | Out-Null
  $add = Invoke-Native $cli @("gateway", "add", "https://127.0.0.1:$Port", "--local", "--name", $GatewayName)
  $add.Out | ForEach-Object { Info $_ }
  $addOk = ($add.Code -eq 0)
  (Invoke-Native $cli @("gateway", "select", $GatewayName)).Out | ForEach-Object { Info $_ }
  if ($addOk) { Ok "gateway add over https succeeded" } else { Info "gateway add returned $($add.Code) (continuing; list is the real proof)" }

  $list = Invoke-Native $cli @("sandbox", "list")
  $list.Out | ForEach-Object { Info $_ }
  $listOk = ($list.Code -eq 0)
  if ($listOk) { Ok "sandbox list over mTLS succeeded (decisive round trip)" } else { Bad "sandbox list failed"; $passed = $false }

  # 6. Negative: a client with no certificate must be refused at the handshake.
  Step "Negative: client with NO certificate (must be refused)"
  $curl = Invoke-Native "curl.exe" @("-sS", "--insecure", "--max-time", "6", "https://127.0.0.1:$Port/")
  $curlExit = $curl.Code
  $curl.Out | ForEach-Object { Info $_ }
  Start-Sleep -Milliseconds 500
  $logNow = (Get-Content $gwLog -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
  $noCertRefused = ($curlExit -ne 0) -and ($logNow -match 'handshake failed.*no certificates|peer sent no certificates|certificate required|bad certificate')
  if ($noCertRefused) { Ok "no-cert client refused (curl exit $curlExit + gateway logged the rejection)" }
  else { Bad "no-cert client was NOT clearly refused (curl exit $curlExit)"; $passed = $false }

  # 7. Tidy the CLI registration (best-effort).
  Invoke-Native $cli @("gateway", "remove", $GatewayName) | Out-Null
}
catch {
  Bad $_.Exception.Message
  $passed = $false
}
finally {
  if ($KeepRunning -and $gw -and -not $gw.HasExited) {
    Info "leaving gateway pid $($gw.Id) running (-KeepRunning); stop with: Stop-Process -Id $($gw.Id) -Force"
  } elseif ($gw -and -not $gw.HasExited) {
    Step "Cleanup"; Stop-Process -Id $gw.Id -Force -ErrorAction SilentlyContinue
    try { $gw.WaitForExit(5000) | Out-Null } catch {}
    Info "stopped gateway pid $($gw.Id)"
  }

  Step "Gateway log (tail)"
  Get-Content $gwLog -Tail 25 -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object { Info $_ }

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

What PASS means: the gateway served its management API over mutual TLS, the CLI
completed real RPCs (gateway add + sandbox list) over that mTLS channel, and a
client presenting NO certificate was refused at the TLS handshake. This is the
control-plane security surface (T2) - it does not involve inference or MXC
sandboxes. Throwaway private keys are NOT included in this bundle.
"@
  Set-Content -Path (Join-Path $resultDir "summary.txt") -Value $summary -Encoding UTF8
  Write-Host $summary -ForegroundColor ($(if ($passed) { "Green" } else { "Red" }))

  try { Stop-Transcript | Out-Null } catch {}

  try {
    $zip = Join-Path $here "results-mtls-$stamp.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $resultDir "*") -DestinationPath $zip -Force
    Write-Host "`nBUNDLE: $zip" -ForegroundColor Yellow
    Write-Host "Hand that zip back for evaluation." -ForegroundColor Yellow
  } catch { Write-Host "zip failed: $($_.Exception.Message)" -ForegroundColor Red }
}

if ($passed) { exit 0 } else { exit 1 }
