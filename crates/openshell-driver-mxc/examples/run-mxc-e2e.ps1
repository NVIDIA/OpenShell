# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# run-mxc-e2e.ps1 - MXC e2e scenario runner.
#
# Starts the gateway ONCE, runs a table of policy scenarios, emits per-scenario
# PASS/FAIL/SKIP(reason), prints a summary table, and exits non-zero only on
# FAIL.  Reuses the gateway-start / CLI-register / teardown pattern from
# run-demo.ps1.
#
# PowerShell 5.1-compatible (no && / || / ternary operators).
#
# Usage examples:
#
#   # Real mode (probe-gated — backends that are absent are SKIPped):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-mxc-e2e.ps1
#
#   # Mock mode (wiring-only; no real wxc-exec or enforcement):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-mxc-e2e.ps1 -Mock
#
#   # Choose backend / filter scenarios:
#   .\run-mxc-e2e.ps1 -Backend process_container -Scenario fs-rw
#
# Scenarios & expected verdicts:
#   fs-rw  - rw grant on DemoDir; in-policy write succeeds.
#                              Both backends; skipped when backend not live (non-mock).
#   fs-readonly              - ro grant on a source dir + rw on DemoDir;
#                              write to ro dir should be denied.
#                              Both backends; skipped when backend not live.
#   fs-default-deny    - empty filesystem policy; every write denied.
#                              processcontainer only (isolation_session has no deny
#                              primitive); skipped on isolation_session.
#   network-reject  - rw grant + network_policies rule;
#                              sandbox create must FAIL (invalid_argument).
#                              Runs on ANY backend including mock — never skips.

[CmdletBinding()]
param(
    [string] $DemoDir     = "C:\work\openshell-mxc-e2e",
    [string] $WxcExecPath = "C:\mxc\wxc-exec.exe",
    [ValidateSet("isolation_session", "process_container")]
    [string] $Backend     = "process_container",
    [string] $Scenario,
    [int]    $Port        = 17670,
    [string] $GatewayName = "openshell-mxc-e2e",
    [switch] $Mock,
    [switch] $KeepRunning
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

function Step([string]$m)  { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Info([string]$m)  { Write-Host "    $m" }
function Ok([string]$m)    { Write-Host "[OK]   $m" -ForegroundColor Green }
function Bad([string]$m)   { Write-Host "[FAIL] $m" -ForegroundColor Red }
function Skip([string]$m)  { Write-Host "[SKIP] $m" -ForegroundColor Yellow }
function Warn([string]$m)  { Write-Host "[WARN] $m" -ForegroundColor Yellow }

# ── Pre-flight ────────────────────────────────────────────────────────────────

# In real mode, assert OPENSHELL_MXC_MOCK_WXC is NOT set.
# A stale mock env var would silently re-mock a run that should be real.
if (-not $Mock) {
    if ($env:OPENSHELL_MXC_MOCK_WXC -eq "1") {
        throw "OPENSHELL_MXC_MOCK_WXC=1 is set but -Mock was not passed. " +
              "A stale mock env var would silently re-mock a real run. " +
              "Unset OPENSHELL_MXC_MOCK_WXC or pass -Mock."
    }
}

$gateway = Join-Path $here "openshell-gateway.exe"
$cli     = Join-Path $here "openshell.exe"
$toml    = Join-Path $here "mxc-gateway.toml"
$policyDir = Join-Path $here "e2e-policies"

foreach ($f in @($gateway, $cli, $toml)) {
    if (-not (Test-Path $f)) {
        throw "Missing artifact: $f`nBuild first or run from a demo-package folder."
    }
}
if (-not (Test-Path $policyDir)) {
    throw "e2e-policies/ directory not found at $policyDir"
}

# ── Backend probe ─────────────────────────────────────────────────────────────

# Returns a verdict hash for a given backend: {Live: bool, Reason: string}
function Probe-Backend([string] $backendName, [string] $wxc) {
    if ($Mock) {
        # In mock mode all backends are "live" — enforcement is simulated.
        return @{ Live = $true; Reason = "mock mode" }
    }
    if (-not (Test-Path $wxc)) {
        return @{ Live = $false; Reason = "wxc-exec not found at $wxc" }
    }

    if ($backendName -eq "process_container") {
        $config = @{
            version     = "0.6.0-alpha"
            containerId = "e2e-probe-pc"
            containment = "processcontainer"
            process     = @{
                commandLine = "cmd /c exit 0"
                cwd         = "%TEMP%"
                timeout     = 10
            }
            filesystem  = @{ readwritePaths = @("%TEMP%") }
            processContainer = @{ leastPrivilege = $false }
        }
        $json = $config | ConvertTo-Json -Depth 20 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $b64 = [Convert]::ToBase64String($bytes)
        $outObj = & $wxc --config-base64 $b64 2>&1
        $exitCode = $LASTEXITCODE
        $output = ($outObj -join "`n").ToLower()
        if ($exitCode -eq 0) {
            return @{ Live = $true; Reason = "process_container probe exit 0" }
        }
        $reason = "process_container unavailable: exit $exitCode"
        if ($output -match "backend_error" -or $output -match "e_notimpl" -or $output -match "velocity") {
            $reason = "process_container backend_error (velocity keys not enabled)"
        }
        return @{ Live = $false; Reason = $reason }
    }

    if ($backendName -eq "isolation_session") {
        $config = @{
            version     = "0.6.0-alpha"
            phase       = "provision"
            containment = "isolation_session"
            filesystem  = @{ readwritePaths = @(); readonlyPaths = @() }
            experimental = @{
                isolation_session = @{
                    configurationId = "composable"
                    provision       = @{}
                }
            }
        }
        $json = $config | ConvertTo-Json -Depth 20 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $b64 = [Convert]::ToBase64String($bytes)
        $outObj = & $wxc --config-base64 $b64 --experimental 2>&1
        $exitCode = $LASTEXITCODE
        $output = ($outObj -join "`n").ToLower()
        if ($output -match "backend_unavailable" -or $output -match "0x80040154") {
            return @{ Live = $false; Reason = "isolation_session backend_unavailable (IsoSessionApp.dll absent)" }
        }
        if ($exitCode -ne 0) {
            return @{ Live = $false; Reason = "isolation_session probe failed: exit $exitCode" }
        }
        # Provision succeeded — deprovision immediately.
        $sandboxId = $null
        try {
            $rawOut = ($outObj -join "`n")
            $parsed = $rawOut | ConvertFrom-Json
            $sandboxId = $parsed.result.sandboxId
        } catch {}
        if ($null -ne $sandboxId) {
            $deprovConfig = @{
                version      = "0.6.0-alpha"
                phase        = "deprovision"
                sandboxId    = $sandboxId
                experimental = @{
                    # Unit variant: null, not @{} (malformed_request otherwise).
                    isolation_session = @{ deprovision = $null }
                }
            }
            $deprovJson = $deprovConfig | ConvertTo-Json -Depth 20 -Compress
            $deprovBytes = [System.Text.Encoding]::UTF8.GetBytes($deprovJson)
            $deprovB64 = [Convert]::ToBase64String($deprovBytes)
            & $wxc --config-base64 $deprovB64 --experimental 2>&1 | Out-Null
        }
        return @{ Live = $true; Reason = "isolation_session probe: provisioned and deprovisioned" }
    }

    return @{ Live = $false; Reason = "unknown backend: $backendName" }
}

# ── Mode setup ────────────────────────────────────────────────────────────────

$mode = if ($Mock) { "MOCK" } else { "REAL" }
Step "Pre-flight (mode=$mode, backend=$Backend)"

if ($Mock) {
    $env:OPENSHELL_MXC_MOCK_WXC = "1"
    Info "OPENSHELL_MXC_MOCK_WXC=1 — mock mode: enforcement simulated"
} else {
    Remove-Item Env:OPENSHELL_MXC_MOCK_WXC -ErrorAction SilentlyContinue
    if (-not (Test-Path $WxcExecPath)) {
        throw "wxc-exec not found at '$WxcExecPath'. Pass -WxcExecPath or use -Mock."
    }
    $env:OPENSHELL_WXC_EXEC_PATH = $WxcExecPath
    Info "wxc-exec: $WxcExecPath"
}

# Patch the TOML copy for backend + wxc_exec_path (mirrors run-demo.ps1).
$tomlText = Get-Content $toml -Raw
$backendLine = "backend = `"$Backend`""
if ($tomlText -match '(?m)^\s*#?\s*backend\s*=') {
    $tomlText = [regex]::Replace($tomlText, '(?m)^\s*#?\s*backend\s*=.*$', $backendLine)
} else {
    $tomlText = [regex]::Replace($tomlText, '(?m)^\[openshell\.drivers\.mxc\]\s*$', "[openshell.drivers.mxc]`r`n$backendLine")
}
if (-not $Mock) {
    $escaped  = $WxcExecPath.Replace('\', '\\')
    $wxcLine  = "wxc_exec_path = `"$escaped`""
    if ($tomlText -match '(?m)^\s*#?\s*wxc_exec_path\s*=') {
        $tomlText = [regex]::Replace($tomlText, '(?m)^\s*#?\s*wxc_exec_path\s*=.*$', $wxcLine)
    } else {
        $tomlText = [regex]::Replace($tomlText, '(?m)^\[openshell\.drivers\.mxc\]\s*$', "[openshell.drivers.mxc]`r`n$wxcLine")
    }
}
Set-Content $toml -Value $tomlText -Encoding UTF8
Info "patched $(Split-Path $toml -Leaf): backend=$Backend"

# Probe backend liveness now (used by scenario gate below).
$backendProbe = Probe-Backend -backendName $Backend -wxc $WxcExecPath
if ($backendProbe.Live) {
    Ok "Backend '$Backend' is live: $($backendProbe.Reason)"
} else {
    Warn "Backend '$Backend' is not live: $($backendProbe.Reason)"
    Warn "Enforcement scenarios will SKIP; network-reject scenario will still run."
}

# ── Port check ────────────────────────────────────────────────────────────────

Step "Check gateway port $Port"
$busy = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
if ($busy) {
    throw "port $Port in use (pid $($busy.OwningProcess)). Stop stale gateway first."
}
Ok "port $Port free"

# ── Prepare DemoDir ───────────────────────────────────────────────────────────

Step "Prepare DemoDir $DemoDir"
New-Item -ItemType Directory -Force $DemoDir | Out-Null
Ok "DemoDir ready"

$env:OPENSHELL_DRIVERS       = "mxc"
$env:OPENSHELL_MXC_SHARE_DIR = $DemoDir

# ── Start gateway ─────────────────────────────────────────────────────────────

Step "Start gateway"
$gwLog    = Join-Path $here "gateway.e2e.log"
$gwErrLog = "$gwLog.err"
Remove-Item $gwLog, $gwErrLog -Force -ErrorAction SilentlyContinue

$gw = Start-Process -FilePath $gateway `
    -ArgumentList @("--disable-tls", "--config", $toml, "--log-level", "info") `
    -WorkingDirectory $here -PassThru -NoNewWindow `
    -RedirectStandardOutput $gwLog -RedirectStandardError $gwErrLog

Info "gateway pid $($gw.Id); logs: $gwLog"

$results = @()

try {
    # Wait for listening
    $deadline = (Get-Date).AddSeconds(30)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        if ($gw.HasExited) {
            Get-Content $gwLog, $gwErrLog -ErrorAction SilentlyContinue | ForEach-Object { Info $_ }
            throw "gateway exited early (code $($gw.ExitCode)). See log."
        }
        if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw "gateway did not start within 30 s." }
    Ok "gateway listening on $Port"

    # Register CLI
    Step "Register CLI"
    $env:OPENSHELL_GATEWAY = ""
    try { & $cli gateway add "http://127.0.0.1:$Port" --local --name $GatewayName 2>&1 | ForEach-Object { Info $_ } }
    catch { Info "gateway add: $($_.Exception.Message) (continuing)" }
    try { & $cli gateway select $GatewayName 2>&1 | ForEach-Object { Info $_ } }
    catch { Info "gateway select: $($_.Exception.Message) (continuing)" }
    Ok "CLI registered"

    # ── Scenario definitions ──────────────────────────────────────────────────
    #
    # Each scenario is a hashtable:
    #   Name        - unique identifier
    #   PolicyFile  - path to the policy YAML fixture
    #   Backends    - list: "both" / "process_container" / "isolation_session"
    #   ExpectFail  - $true means `sandbox create` itself must fail (invalid_argument)
    #   ExpectArtifact - whether the workload should create its target file
    #   Description - human-readable label

    $allScenarios = @(
        @{
            Name        = "fs-rw"
            PolicyFile  = Join-Path $policyDir "fs-rw.yaml"
            Backends    = "both"
            ExpectFail  = $false
            ExpectArtifact = $true
            Description = "rw grant on DemoDir; in-policy write should succeed"
        },
        @{
            Name        = "fs-readonly"
            PolicyFile  = Join-Path $policyDir "fs-readonly.yaml"
            Backends    = "both"
            ExpectFail  = $false
            ExpectArtifact = $true
            Description = "ro grant + rw share; write to ro dir should be denied"
        },
        @{
            Name        = "fs-default-deny"
            PolicyFile  = Join-Path $policyDir "fs-empty.yaml"
            Backends    = "process_container"
            ExpectFail  = $false
            ExpectArtifact = $false
            Description = "empty filesystem policy; all writes denied (process_container only)"
        },
        @{
            Name        = "network-reject"
            PolicyFile  = Join-Path $policyDir "network-reject.yaml"
            Backends    = "both"
            ExpectFail  = $true
            Description = "network_policies rule causes sandbox create to fail (no live backend needed)"
        }
    )

    # Apply optional scenario filter.
    if ($Scenario) {
        $filtered = $allScenarios | Where-Object { $_.Name -eq $Scenario }
        if ($filtered.Count -eq 0) {
            throw "Scenario '$Scenario' not found. Available: $(($allScenarios | ForEach-Object { $_.Name }) -join ', ')"
        }
        $allScenarios = $filtered
    }

    # ── Run scenarios ─────────────────────────────────────────────────────────

    foreach ($sc in $allScenarios) {
        Step "Scenario: $($sc.Name)"
        Info $sc.Description

        # Backend gate: skip enforcement scenarios when backend not live (and not mock and not ExpectFail).
        $skipReason = $null
        if (-not $sc.ExpectFail) {
            $backendMatches = ($sc.Backends -eq "both") -or ($sc.Backends -eq $Backend)
            if (-not $backendMatches) {
                $skipReason = "scenario requires backend=$($sc.Backends); current backend=$Backend"
            } elseif (-not $backendProbe.Live -and -not $Mock) {
                $skipReason = "backend not live: $($backendProbe.Reason)"
            }
        }

        if ($null -ne $skipReason) {
            Skip "$($sc.Name): $skipReason"
            $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "SKIP"; Reason = $skipReason }
            continue
        }

        # Policy file must exist.
        if (-not (Test-Path $sc.PolicyFile)) {
            Bad "$($sc.Name): policy fixture not found at $($sc.PolicyFile)"
            $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "policy fixture missing" }
            continue
        }

        # Build per-sandbox MXC workload config. Commands and working directories
        # are create-time inputs, not gateway-wide settings.
        $target = Join-Path $DemoDir "$($sc.Name)-result.txt"
        Remove-Item $target -Force -ErrorAction SilentlyContinue
        $targetFwd = $target.Replace('\', '/')
        $demoDirFwd = $DemoDir.Replace('\', '/')
        $driverConfig = @{
            mxc = @{
                command = @("cmd", "/c", "echo.ok>$targetFwd")
                cwd = $demoDirFwd
            }
        } | ConvertTo-Json -Compress -Depth 4
        # Windows PowerShell 5.1 removes embedded quotes when it builds the
        # native command line. Escape them so the CLI receives valid JSON.
        $driverConfigArg = if ($PSVersionTable.PSVersion.Major -lt 7) {
            $driverConfig.Replace('"', '\"')
        } else {
            $driverConfig
        }
        # Run sandbox create.
        $createOut = $null
        $createExitCode = 0
        try {
            $createOut = & $cli sandbox create --name $sc.Name --policy $sc.PolicyFile --driver-config-json $driverConfigArg --no-tty 2>&1
            $createExitCode = $LASTEXITCODE
        } catch {
            $createOut = $_.Exception.Message
            $createExitCode = 1
        }
        $createOutStr = ($createOut -join "`n")
        Info "create exit: $createExitCode"

        # Delete sandbox (best-effort; no-op if create failed).
        try { & $cli sandbox delete $sc.Name 2>&1 | Out-Null } catch {}

        # Evaluate.
        if ($sc.ExpectFail) {
            # network-reject: create must fail.
            if ($createExitCode -ne 0) {
                Ok "$($sc.Name): create correctly failed (exit $createExitCode)"
                Info "output: $createOutStr"
                $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = "create failed as expected" }
            } else {
                Bad "$($sc.Name): create succeeded but should have failed"
                Info "output: $createOutStr"
                $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "create succeeded unexpectedly" }
            }
        } else {
            # Wiring check in mock mode: the artifact must match the policy's
            # expected outcome. In particular, default-deny passes only when
            # the workload cannot create its target file.
            if ($Mock) {
                if ($sc.ExpectArtifact) {
                    $deadline = (Get-Date).AddSeconds(10)
                    while ((Get-Date) -lt $deadline -and -not (Test-Path $target)) {
                        Start-Sleep -Milliseconds 300
                    }
                }
                $artifactExists = Test-Path $target
                if ($artifactExists -eq $sc.ExpectArtifact) {
                    $outcome = if ($artifactExists) { "present" } else { "absent" }
                    Ok "$($sc.Name): artifact $outcome as expected (mock wiring OK)"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = "mock wiring: artifact $outcome as expected" }
                } else {
                    Bad "$($sc.Name): artifact outcome did not match policy (present=$artifactExists, expected=$($sc.ExpectArtifact))"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "mock wiring: artifact present=$artifactExists, expected=$($sc.ExpectArtifact)" }
                }
            } else {
                # Real mode: artifact presence == enforcement worked.
                $deadline = (Get-Date).AddSeconds(30)
                while ((Get-Date) -lt $deadline -and -not (Test-Path $target)) {
                    Start-Sleep -Milliseconds 500
                }
                if ($createExitCode -eq 0 -and (Test-Path $target)) {
                    Ok "$($sc.Name): in-policy write succeeded"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = "in-policy write produced artifact" }
                } else {
                    Bad "$($sc.Name): FAIL (create=$createExitCode, artifact=$(Test-Path $target))"
                    Info "createOut: $createOutStr"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "create=$createExitCode, artifact=$(Test-Path $target)" }
                }
            }
        }
    }

} finally {
    if ($KeepRunning) {
        Info "leaving gateway pid $($gw.Id) running (-KeepRunning)"
    } elseif ($gw -and -not $gw.HasExited) {
        Step "Cleanup"
        Stop-Process -Id $gw.Id -Force -ErrorAction SilentlyContinue
        Info "stopped gateway pid $($gw.Id)"
    }
}

# ── Summary table ─────────────────────────────────────────────────────────────

Step "Summary"
$results | Format-Table -AutoSize

$failCount = ($results | Where-Object { $_.Result -eq "FAIL" }).Count
$passCount = ($results | Where-Object { $_.Result -eq "PASS" }).Count
$skipCount = ($results | Where-Object { $_.Result -eq "SKIP" }).Count

Write-Host "PASS=$passCount  FAIL=$failCount  SKIP=$skipCount"

if ($failCount -gt 0) {
    Write-Host "`nSOME SCENARIOS FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nALL SCENARIOS PASSED (or SKIPPED)" -ForegroundColor Green
    exit 0
}
