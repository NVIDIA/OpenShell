# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# run-mxc-e2e.ps1 - MXC e2e scenario runner.
#
# Runs a table of policy scenarios against the OpenShell MXC driver, emits
# per-scenario PASS/FAIL/SKIP(reason), prints a summary table, and exits non-zero
# only on FAIL.
#
# Every run collects its logs into a timestamped results-e2e-<stamp>\ folder and
# zips it (mirrors the sibling run-*.ps1 scripts). The bundle contains the console
# transcript, the per-scenario gateway stdout/stderr, the exact TOML rendered for
# each scenario, the policy fixture used, and a summary.txt with the verdict table.
#
# The gateway restarts per scenario to keep logs and the in-memory database
# isolated. Workload command/cwd are supplied per sandbox through
# --driver-config-json; they are never patched into gateway configuration.
#
# Scoring (why we do NOT gate on `sandbox create` exit code):
#   The ground truth is the on-disk artifact, so positive scenarios pass on
#   artifact PRESENT and deny scenarios pass on the denied write being ABSENT.
#   A CONTROL write proves the agent ran when the policy grants a writable path;
#   an empty policy instead requires explicit driver-launch evidence.
#
# PowerShell 5.1-compatible (no && / || / ternary operators). ASCII only.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-mxc-e2e.ps1 -WxcExecPath C:\mxc-kit\bin\wxc-exec.exe
#   .\run-mxc-e2e.ps1 -Mock                                  # wiring-only, no real backend
#   .\run-mxc-e2e.ps1 -Scenario fs-rw                        # single scenario
#
# Scenarios & expected verdicts:
#   fs-rw            - in-policy write to DemoDir succeeds.
#   fs-readonly      - write to read-only dir is denied; control write succeeds.
#   fs-default-deny  - ungranted write is denied after the agent launches.
#                      processcontainer only.
#   network-reject   - network_policies rule makes sandbox create fail.

[CmdletBinding()]
param(
    [string] $DemoDir     = "C:\work\openshell-mxc-e2e",
    [string] $WxcExecPath = "C:\mxc-kit\bin\wxc-exec.exe",
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

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# --- Results bundle -----------------------------------------------------------
# Collect every log + the exact rendered config per scenario into a timestamped
# results\ folder, then zip it (mirrors the sibling run-*.ps1 scripts). Created up
# front so the transcript (started inside the guarded region below) captures the
# whole run, including pre-flight failures.
$stamp     = Get-Date -Format "yyyyMMdd-HHmmss"
$resultDir = Join-Path $here "results-e2e-$stamp"
New-Item -ItemType Directory -Force $resultDir | Out-Null
$transcriptStarted = $false

function Step([string]$m)  { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Info([string]$m)  { Write-Host "    $m" }
function Ok([string]$m)    { Write-Host "[OK]   $m" -ForegroundColor Green }
function Bad([string]$m)   { Write-Host "[FAIL] $m" -ForegroundColor Red }
function Skip([string]$m)  { Write-Host "[SKIP] $m" -ForegroundColor Yellow }
function Warn([string]$m)  { Write-Host "[WARN] $m" -ForegroundColor Yellow }

# Double backslashes so a Windows path is a valid TOML/JSON basic-string element.
function Esc([string]$p) { return $p.Replace('\', '\\') }

# Build one CreateProcess-compatible command-line argument. Windows PowerShell
# 5.1 can split JSON values at embedded spaces when invoking native commands
# through the call operator, even when PowerShell holds the JSON as one string.
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

function Invoke-NativeCaptured([string]$filePath, [string[]]$argumentList) {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $filePath
    $startInfo.Arguments = (($argumentList | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "failed to start $filePath" }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()

    return @{
        ExitCode = $process.ExitCode
        Output = @($stdout.Result, $stderr.Result) | Where-Object { $_ }
    }
}

# --- Path variables -----------------------------------------------------------

$gateway   = Join-Path $here "openshell-gateway.exe"
$cli       = Join-Path $here "openshell.exe"
$toml      = Join-Path $here "mxc-gateway.toml"
$policyDir = Join-Path $here "e2e-policies"

$cmdExe     = "C:\Windows\System32\cmd.exe"
$demoDirFwd = $DemoDir.Replace('\', '/')
$roSrc      = "$DemoDir-ro-src"      # matches e2e-policies/fs-readonly.yaml read_only path
$denyProbe  = "$DemoDir-deny-probe"  # ungranted, NOT the share: used to prove default-deny

$script:registered = $false

# Pristine TOML captured once inside the try (below); every scenario renders a
# fresh copy from it. Per-scenario gateway logs are assigned inside the loop so
# each scenario's stdout/stderr lands in its own file under $resultDir.
$tomlBase = $null
$gwLog    = $null
$gwErrLog = $null

# --- Helpers ------------------------------------------------------------------

# Render host-runtime settings from the pristine base. Sandbox workload
# settings are create-time driver config, not gateway-wide TOML.
function Render-Toml {
    $t = $tomlBase
    $t = [regex]::Replace($t, '(?m)^\s*#?\s*backend\s*=.*$', "backend = `"$Backend`"")
    if (-not $Mock) {
        $wxcLine = "wxc_exec_path = `"$(Esc $WxcExecPath)`""
        $t = [regex]::Replace($t, '(?m)^\s*#?\s*wxc_exec_path\s*=.*$', $wxcLine)
    }
    Set-Content $toml -Value $t -Encoding UTF8
}

function Start-Gw {
    Remove-Item $gwLog, $gwErrLog -Force -ErrorAction SilentlyContinue
    # Ephemeral in-memory DB: this is a test harness, so it must NOT write sandbox
    # records to the persistent default store (%LOCALAPPDATA%\openshell\gateway\
    # openshell.db). Without this, sandbox names persist across gateway restarts
    # and across runs, colliding on `create` ("already exists") and leaving orphan
    # records behind. In-memory means every gateway starts clean and leaves nothing.
    # Config path goes through the env var (clap: OPENSHELL_GATEWAY_CONFIG), NOT a
    # --config token: Start-Process -ArgumentList does not quote array elements, so a
    # config path containing a space gets split and the gateway's arg parser rejects it.
    $env:OPENSHELL_GATEWAY_CONFIG = $toml
    $p = Start-Process -FilePath $gateway `
        -ArgumentList @("--disable-tls", "--db-url", "sqlite::memory:", "--log-level", "info") `
        -WorkingDirectory $here -PassThru -NoNewWindow `
        -RedirectStandardOutput $gwLog -RedirectStandardError $gwErrLog
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if ($p.HasExited) {
            Get-Content $gwLog, $gwErrLog -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object { Info $_ }
            throw "gateway exited early (code $($p.ExitCode)). See $gwLog."
        }
        if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
            return $p
        }
        Start-Sleep -Milliseconds 400
    }
    # Timed out but the process is still alive (never bound $Port). $gw is not yet
    # assigned in the caller, so the finally block can't reap it - kill it here to
    # avoid leaving an orphan gateway holding the port for the next run.
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    throw "gateway did not start within 30 s."
}

function Stop-Gw($p) {
    if ($p -and -not $p.HasExited) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 700   # let the listen socket release before the next start
}

function Register-Cli {
    if ($script:registered) { return }
    $env:OPENSHELL_GATEWAY = ""

    $addResult = Invoke-NativeCaptured $cli @(
        "gateway", "add", "http://127.0.0.1:$Port", "--local", "--name", $GatewayName
    )
    $addText = ($addResult.Output -join "`n")
    if ($addText) { $addResult.Output | ForEach-Object { Info $_ } }
    if ($addResult.ExitCode -ne 0 -and $addText -notmatch '(?i)already exists') {
        throw "gateway add failed (exit $($addResult.ExitCode)): $addText"
    }

    $selectResult = Invoke-NativeCaptured $cli @("gateway", "select", $GatewayName)
    $selectText = ($selectResult.Output -join "`n")
    if ($selectText) { $selectResult.Output | ForEach-Object { Info $_ } }
    if ($selectResult.ExitCode -ne 0) {
        throw "gateway select failed (exit $($selectResult.ExitCode)): $selectText"
    }

    $script:registered = $true
}

function Wait-File([string]$path, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline -and -not (Test-Path $path)) {
        Start-Sleep -Milliseconds 400
    }
    return (Test-Path $path)
}

# Detect an agent *launch* failure (binary not found / not implemented) vs a
# legitimate policy denial. Used to avoid false-passing a deny scenario when the
# agent never actually ran.
function Launch-Failed([string]$gwText) {
    if ($null -eq $gwText) { return $false }
    return ($gwText -match 'CreateProcessW failed error:2' `
        -or $gwText -match 'error:2' `
        -or $gwText -match 'exited -1' `
        -or $gwText -match 'The system cannot find the file' `
        -or $gwText -match 'E_NOTIMPL' `
        -or $gwText -match 'velocity')
}

function Launch-Succeeded([string]$gwText) {
    if ($null -eq $gwText) { return $false }
    return ($gwText -match 'MXC agent launched')
}

# --- Backend probe ------------------------------------------------------------

function Probe-Backend([string] $backendName, [string] $wxc) {
    if ($Mock) { return @{ Live = $true; Reason = "mock mode" } }
    if (-not (Test-Path $wxc)) { return @{ Live = $false; Reason = "wxc-exec not found at $wxc" } }

    if ($backendName -eq "process_container") {
        # Use a REAL directory + absolute cmd.exe: the canonical wxc-exec passes
        # cwd straight to CreateProcessW and does NOT expand %TEMP% (that yields
        # 0x8007010B "directory name is invalid").
        $probeDir = Join-Path $env:TEMP "mxc-e2e-probe"
        New-Item -ItemType Directory -Force $probeDir | Out-Null
        $config = @{
            version     = "0.6.0-alpha"
            containerId = "e2e-probe-pc"
            containment = "processcontainer"
            process     = @{ commandLine = "C:\Windows\System32\cmd.exe /c exit 0"; cwd = $probeDir; timeout = 30000 }  # ms (MXC process.timeout is milliseconds)
            filesystem  = @{ readwritePaths = @($probeDir) }
            processContainer = @{ leastPrivilege = $false }
        }
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($config | ConvertTo-Json -Depth 20 -Compress)))
        $outObj = & $wxc --config-base64 $b64 2>&1
        $exitCode = $LASTEXITCODE
        $output = ($outObj -join "`n").ToLower()
        if ($exitCode -eq 0) { return @{ Live = $true; Reason = "process_container probe exit 0" } }
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
        # Provision succeeded - deprovision immediately.
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

# --- Run ----------------------------------------------------------------------
# Everything that can throw runs inside this try so the finally always produces
# the results bundle (summary + transcript + zip), even on a pre-flight failure.

$results      = @()
$gw           = $null
$harnessError = $null
$backendProbe = @{ Live = $false; Reason = "not probed" }
# Unique per-run suffix so a stale sandbox record from an earlier run can never
# collide with this run's `sandbox create` (the gateway persists names on disk).
# Sandbox names are limited to 19 characters, so keep the timestamp compact.
$runId = Get-Date -Format 'MMddHHmmss'

try {
    # Start the transcript inside the guarded region so a Start-Transcript failure
    # is caught and the results bundle is still produced. Pre-flight runs
    # immediately below, so the transcript still captures the whole run.
    Start-Transcript -Path (Join-Path $resultDir "transcript.txt") -Force | Out-Null
    $transcriptStarted = $true

    # --- Pre-flight -----------------------------------------------------------

    if (-not $Mock) {
        if ($env:OPENSHELL_MXC_MOCK_WXC -eq "1") {
            throw "OPENSHELL_MXC_MOCK_WXC=1 is set but -Mock was not passed. " +
                  "Unset OPENSHELL_MXC_MOCK_WXC or pass -Mock."
        }
    }

    # -KeepRunning leaves the gateway up and breaks after the FIRST scenario (so the
    # next one cannot collide on the port). A full-suite run would therefore execute
    # only one scenario yet still report the suite as PASS. Require a single,
    # explicitly-selected scenario so a partial run can never be mislabeled complete.
    if ($KeepRunning -and -not $Scenario) {
        throw "-KeepRunning requires -Scenario: it stops after the first scenario, so a full-suite run would report PASS on partial results. Re-run with e.g. -Scenario fs-rw-positive-negative -KeepRunning."
    }

    foreach ($f in @($gateway, $cli, $toml)) {
        if (-not (Test-Path $f)) {
            throw "Missing artifact: $f`nBuild first or run from a demo-package folder."
        }
    }
    if (-not (Test-Path $policyDir)) {
        throw "e2e-policies/ directory not found at $policyDir"
    }

    # Capture the pristine TOML once; every scenario renders a fresh copy from this.
    $tomlBase = Get-Content $toml -Raw

    # --- Mode setup -----------------------------------------------------------

    Step "Pre-flight (mode=$(if ($Mock) {'MOCK'} else {'REAL'}), backend=$Backend)"

    if ($Mock) {
        $env:OPENSHELL_MXC_MOCK_WXC = "1"
        Info "OPENSHELL_MXC_MOCK_WXC=1 - mock mode: enforcement simulated"
    } else {
        Remove-Item Env:OPENSHELL_MXC_MOCK_WXC -ErrorAction SilentlyContinue
        if (-not (Test-Path $WxcExecPath)) {
            throw "wxc-exec not found at '$WxcExecPath'. Pass -WxcExecPath or use -Mock."
        }
        $env:OPENSHELL_WXC_EXEC_PATH = $WxcExecPath
        Info "wxc-exec: $WxcExecPath"
    }

    $backendProbe = Probe-Backend -backendName $Backend -wxc $WxcExecPath
    if ($backendProbe.Live) {
        Ok "Backend '$Backend' is live: $($backendProbe.Reason)"
    } else {
        Warn "Backend '$Backend' is not live: $($backendProbe.Reason)"
        Warn "Enforcement scenarios will SKIP; network-reject scenario will still run."
    }

    Step "Check gateway port $Port"
    $busy = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if ($busy) { throw "port $Port in use (pid $($busy.OwningProcess)). Stop stale gateway first." }
    Ok "port $Port free"

    Step "Prepare DemoDir + read-only source + deny-probe dir"
    New-Item -ItemType Directory -Force $DemoDir   | Out-Null
    New-Item -ItemType Directory -Force $roSrc     | Out-Null
    New-Item -ItemType Directory -Force $denyProbe | Out-Null
    Set-Content -Path (Join-Path $roSrc "seed.txt") -Value "read-only seed" -Encoding UTF8
    Ok "DemoDir=$DemoDir  roSrc=$roSrc  denyProbe=$denyProbe"

    $env:OPENSHELL_DRIVERS       = "mxc"
    $env:OPENSHELL_MXC_SHARE_DIR = $DemoDir

    # --- Scenario definitions -------------------------------------------------
    #   Kind: positive | deny | create-fail
    #   For deny: ControlTarget (granted, must be PRESENT) + DenyTarget (must be ABSENT).

    $allScenarios = @(
        @{
            Name = "fs-rw"; PolicyFile = Join-Path $policyDir "fs-rw.yaml"
            SandboxId = "rw"
            Backends = "both"; Kind = "positive"
            PosTarget = (Join-Path $DemoDir "fs-rw-result.txt")
            Description = "rw grant on DemoDir; in-policy write should succeed"
        },
        @{
            Name = "fs-readonly"; PolicyFile = Join-Path $policyDir "fs-readonly.yaml"
            SandboxId = "ro"
            Backends = "both"; Kind = "deny"
            ControlTarget = (Join-Path $DemoDir "fs-readonly-control.txt")
            DenyTarget    = (Join-Path $roSrc  "fs-readonly-denied.txt")
            Description = "write to read-only dir denied; control write to rw dir succeeds"
        },
        @{
            Name = "fs-default-deny"; PolicyFile = Join-Path $policyDir "fs-empty.yaml"
            SandboxId = "fd"
            Backends = "process_container"; Kind = "deny"
            DenyTarget    = (Join-Path $denyProbe "fs-default-deny-denied.txt")
            Description = "empty policy; ungranted write denied"
        },
        @{
            Name = "network-reject"; PolicyFile = Join-Path $policyDir "network-reject.yaml"
            SandboxId = "net"
            Backends = "both"; Kind = "create-fail"
            Description = "network_policies rule causes sandbox create to fail (no live backend needed)"
        }
    )

    if ($Scenario) {
        # Wrap in @() so an exact single match stays an array: without it a lone
        # match is a bare hashtable, its .Count is unreliable on PS 5.1, and
        # $allScenarios would no longer be an array for the loop below.
        $filtered = @($allScenarios | Where-Object { $_.Name -eq $Scenario })
        if ($filtered.Count -eq 0) {
            throw "Scenario '$Scenario' not found. Available: $(($allScenarios | ForEach-Object { $_.Name }) -join ', ')"
        }
        $allScenarios = $filtered
    }

    # --- Scenario loop --------------------------------------------------------

    try {
        foreach ($sc in $allScenarios) {
            Step "Scenario: $($sc.Name)"
            Info $sc.Description

            # Backend gate (deny/positive scenarios need a live backend; create-fail does not).
            $skipReason = $null
            if ($sc.Kind -ne "create-fail") {
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

            if (-not (Test-Path $sc.PolicyFile)) {
                Bad "$($sc.Name): policy fixture not found at $($sc.PolicyFile)"
                $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "policy fixture missing" }
                continue
            }

            # Per-scenario gateway logs land in the bundle under their own names.
            $gwLog    = Join-Path $resultDir "gateway.$($sc.Name).log"
            $gwErrLog = Join-Path $resultDir "gateway.$($sc.Name).err.log"

            # Build the per-sandbox workload command and clean prior artifacts.
            if ($sc.Kind -eq "positive") {
                Remove-Item $sc.PosTarget -Force -ErrorAction SilentlyContinue
                $command = @($cmdExe, "/c", "echo ok 1> $($sc.PosTarget.Replace('\', '/'))")
            } elseif ($sc.Kind -eq "deny") {
                Remove-Item $sc.DenyTarget -Force -ErrorAction SilentlyContinue
                $denied = $sc.DenyTarget.Replace('\', '/')
                if ($sc.ControlTarget) {
                    Remove-Item $sc.ControlTarget -Force -ErrorAction SilentlyContinue
                    $control = $sc.ControlTarget.Replace('\', '/')
                    $command = @($cmdExe, "/c", "echo ok 1> $control & echo denied 1> $denied")
                } else {
                    $command = @($cmdExe, "/c", "echo denied 1> $denied")
                }
            } else {
                $command = @($cmdExe, "/c", "exit 0")
            }

            $driverConfig = @{
                mxc = @{
                    command = $command
                    cwd = $demoDirFwd
                }
            } | ConvertTo-Json -Compress -Depth 4

            Render-Toml
            # Preserve the exact rendered config + policy fixture used for this scenario.
            Copy-Item $toml (Join-Path $resultDir "mxc-gateway.$($sc.Name).toml") -Force -ErrorAction SilentlyContinue
            Copy-Item $sc.PolicyFile (Join-Path $resultDir "policy.$($sc.Name).yaml") -Force -ErrorAction SilentlyContinue

            $gw = Start-Gw
            Info "gateway pid $($gw.Id)"
            Register-Cli

            # Unique per-run sandbox name within the 19-character routable-name limit.
            $sandboxName = "mxc-$($sc.SandboxId)-$runId"
            try { Invoke-NativeCaptured $cli @("sandbox", "delete", $sandboxName) | Out-Null } catch {}

            # Run sandbox create. Its exit status is only authoritative for the
            # create-fail scenario; artifacts score workload scenarios.
            $createOut = $null; $createExitCode = 0
            try {
                $createResult = Invoke-NativeCaptured $cli @(
                    "sandbox", "create", "--name", $sandboxName,
                    "--policy", [string]$sc.PolicyFile,
                    "--driver-config-json", $driverConfig,
                    "--no-tty"
                )
                $createOut = $createResult.Output
                $createExitCode = $createResult.ExitCode
            } catch {
                $createOut = $_.Exception.Message; $createExitCode = 1
            }
            $createOutStr = ($createOut -join "`n")
            Info "create exit: $createExitCode (not used for scoring on non-create-fail scenarios)"

            $gwText = (Get-Content $gwLog, $gwErrLog -Raw -ErrorAction SilentlyContinue) -join "`n"

            # Evaluate.
            if ($sc.Kind -eq "create-fail") {
                # A non-zero exit alone is NOT sufficient: gateway-registration,
                # transport, or malformed-fixture errors also exit non-zero and would
                # false-pass this scenario. Require a genuine policy-rejection signal
                # (the driver rejects the network rule with invalid_argument naming
                # network_policies) AND confirm it is not an infrastructure failure.
                $rejected = ($createOutStr -match '(?i)network' `
                    -or $createOutStr -match '(?i)invalid[_ -]?argument' `
                    -or $createOutStr -match '(?i)policy' `
                    -or $gwText -match '(?i)network_policies')
                $infraFail = ($createOutStr -match '(?i)connection refused' `
                    -or $createOutStr -match '(?i)not registered' `
                    -or $createOutStr -match '(?i)transport error' `
                    -or $createOutStr -match '(?i)failed to connect')
                if ($createExitCode -ne 0 -and $rejected -and -not $infraFail) {
                    Ok "$($sc.Name): create correctly rejected by policy (exit $createExitCode)"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = "policy rejection" }
                } elseif ($createExitCode -ne 0) {
                    Bad "$($sc.Name): create failed but not with a policy-rejection signal (possible harness/infra error)"
                    Info "output: $createOutStr"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "non-rejection failure" }
                } else {
                    Bad "$($sc.Name): create succeeded but should have failed"
                    Info "output: $createOutStr"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "create succeeded unexpectedly" }
                }
            } elseif ($sc.Kind -eq "positive") {
                $present = Wait-File $sc.PosTarget 30
                if ($present) {
                    Ok "$($sc.Name): in-policy write produced artifact"
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = "artifact present" }
                } else {
                    Bad "$($sc.Name): artifact absent ($($sc.PosTarget))"
                    Info "createOut: $createOutStr"
                    if (Launch-Failed $gwText) { Info "gateway log shows an agent-launch failure (not a policy result)" }
                    $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "artifact absent" }
                }
            } else {
                # deny
                if ($sc.ControlTarget) {
                    $controlPresent = Wait-File $sc.ControlTarget 30
                    # Snapshot the deny target only AFTER the control artifact lands, so a
                    # late denied write (enforcement regression racing the control write)
                    # cannot be recorded as PASS.
                    $denyPresent = Test-Path $sc.DenyTarget
                    if ($controlPresent -and -not $denyPresent) {
                        Ok "$($sc.Name): control write succeeded; denied write correctly blocked"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = "control present, deny absent" }
                    } elseif (-not $controlPresent) {
                        Bad "$($sc.Name): control write absent - agent did not run correctly (inconclusive denial)"
                        Info "createOut: $createOutStr"
                        if (Launch-Failed $gwText) { Info "gateway log shows an agent-launch failure" }
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "control absent (agent did not run)" }
                    } else {
                        Bad "$($sc.Name): denied write was NOT blocked (artifact present)"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "deny target present (not enforced)" }
                    }
                } else {
                    # An empty policy has no writable control path. Require both an absent
                    # artifact and an explicit driver launch message so launch failures
                    # cannot false-pass the denial.
                    Start-Sleep -Seconds 3
                    $denyPresent = Test-Path $sc.DenyTarget
                    $gwText = (Get-Content $gwLog, $gwErrLog -Raw -ErrorAction SilentlyContinue) -join "`n"
                    if ($denyPresent) {
                        Bad "$($sc.Name): denied write was NOT blocked (artifact present)"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "deny target present (not enforced)" }
                    } elseif (Launch-Failed $gwText) {
                        Bad "$($sc.Name): artifact absent but agent failed to launch - inconclusive"
                        Info "createOut: $createOutStr"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "agent launch failed (inconclusive)" }
                    } elseif (-not (Launch-Succeeded $gwText)) {
                        Bad "$($sc.Name): artifact absent but no agent-launch evidence was recorded - inconclusive"
                        Info "createOut: $createOutStr"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "FAIL"; Reason = "agent launch not confirmed (inconclusive)" }
                    } else {
                        Ok "$($sc.Name): write correctly denied (artifact absent, agent launched)"
                        $results += [pscustomobject]@{ Scenario = $sc.Name; Result = "PASS"; Reason = "deny absent (default-deny enforced)" }
                    }
                }
            }

            if ($KeepRunning) {
                Info "leaving gateway pid $($gw.Id) running (-KeepRunning); stopping after the first scenario so the next one doesn't collide on port $Port"
                break
            } else {
                # Keep the sandbox alive until artifact-based scoring finishes.
                # Real MXC startup is asynchronous and can otherwise be canceled
                # before the workload writes its positive/control proof.
                try { Invoke-NativeCaptured $cli @("sandbox", "delete", $sandboxName) | Out-Null } catch {}
                Stop-Gw $gw
                $gw = $null
            }
        }
    } finally {
        if ($gw -and -not $KeepRunning) { Stop-Gw $gw }
        if ($KeepRunning -and $gw) { Info "gateway pid $($gw.Id) left running (-KeepRunning)" }
    }
}
catch {
    $harnessError = $_.Exception.Message
    Bad "harness error: $harnessError"
}
finally {
    # --- Summary + results bundle ---------------------------------------------
    Step "Summary"
    $results | Format-Table -AutoSize

    # Wrap in @() so a single match still yields an array with a .Count (PS 5.1).
    $failCount = @($results | Where-Object { $_.Result -eq "FAIL" }).Count
    $passCount = @($results | Where-Object { $_.Result -eq "PASS" }).Count
    $skipCount = @($results | Where-Object { $_.Result -eq "SKIP" }).Count
    Write-Host "PASS=$passCount  FAIL=$failCount  SKIP=$skipCount"

    $verdict = if ($harnessError -or $failCount -gt 0) { "FAIL" } else { "PASS" }
    $tableText = ($results | Format-Table -AutoSize | Out-String)
    $summary = @"
OpenShell MXC e2e scenario run
==============================
timestamp    : $stamp
machine      : $env:COMPUTERNAME
verdict      : $verdict
mode         : $(if ($Mock) { 'MOCK' } else { 'REAL' })
backend      : $Backend
backend_live : $($backendProbe.Live)   ($($backendProbe.Reason))
wxc_exec     : $WxcExecPath
gateway_port : $Port
totals       : PASS=$passCount  FAIL=$failCount  SKIP=$skipCount
$(if ($harnessError) { "harness_error: $harnessError" })

Per-scenario results:
$tableText
Files in this bundle ($resultDir):
  summary.txt                        this summary
  transcript.txt                     full console transcript
  gateway.<scenario>.log / .err.log  per-scenario gateway stdout/stderr
  mxc-gateway.<scenario>.toml        the exact gateway config rendered per scenario
  policy.<scenario>.yaml             the exact sandbox policy fixture used per scenario

What PASS means: every non-skipped scenario met its expected verdict - positive
writes produced their artifact, deny writes were blocked with either a control
write or driver-launch evidence, and network-reject was refused by policy.
"@
    Set-Content -Path (Join-Path $resultDir "summary.txt") -Value $summary -Encoding UTF8
    Write-Host $summary -ForegroundColor ($(if ($verdict -eq "PASS") { "Green" } else { "Red" }))

    if ($transcriptStarted) { try { Stop-Transcript | Out-Null } catch {} }

    # Zip the bundle for easy return (defensive; never throw out of finally).
    try {
        $zip = Join-Path $here "results-e2e-$stamp.zip"
        if (Test-Path $zip) { Remove-Item $zip -Force }
        Compress-Archive -Path (Join-Path $resultDir "*") -DestinationPath $zip -Force
        Write-Host "`nResults bundle: $zip" -ForegroundColor Yellow
    } catch { Write-Host "zip failed: $($_.Exception.Message)" -ForegroundColor Red }
}

if ($harnessError -or $failCount -gt 0) {
    Write-Host "`nSOME SCENARIOS FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nALL SCENARIOS PASSED (or SKIPPED)" -ForegroundColor Green
    exit 0
}
