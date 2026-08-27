# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# probe-mxc-host.ps1 - Operator/CI preflight for a prospective MXC host.
# This diagnostic is not invoked by the driver and does not mutate host state.
# It reports OS, wxc-exec, and backend availability so real tests can skip
# unsupported scenarios with an explicit reason.
#
# PowerShell 5.1-compatible (no && / || / ternary operators).
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\probe-mxc-host.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\probe-mxc-host.ps1 -OutFile caps.json
#
# The script is read-only except for a per-run temp directory. It never enables
# OS features or modifies system state.
#
# Exit codes:
#   0 - report emitted (even if backends are unavailable)
#   1 - unexpected error (should not happen on a healthy box)

[CmdletBinding()]
param(
    [string] $WxcExecPath = "C:\mxc\wxc-exec.exe",
    [string] $OutFile,
    # Emit the complete JSON report to stdout. Default output is a short
    # human-readable summary (the full report still goes to -OutFile if set).
    [switch] $Full
)

$ErrorActionPreference = "Stop"
# Prevent PS 7+ from turning native non-zero exits into terminating errors.
$PSNativeCommandUseErrorActionPreference = $false

# ── Helpers ───────────────────────────────────────────────────────────────────

function Invoke-Native([string[]] $ArgList) {
    # Run a native exe and capture all output regardless of exit code.
    # In PowerShell 5.1, a non-zero exit from a native exe can emit
    # ErrorRecord objects into the output stream when $ErrorActionPreference
    # is Stop (via NativeCommandError).  We temporarily relax the preference
    # and collect both String and ErrorRecord outputs into a single string.
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $raw = & $ArgList[0] $ArgList[1..($ArgList.Length - 1)] 2>&1
        $code = $LASTEXITCODE
        $text = ($raw | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                $_.ToString()
            } else {
                $_
            }
        }) -join "`n"
        return @{ ExitCode = $code; Output = $text }
    } finally {
        $ErrorActionPreference = $saved
    }
}

function Invoke-WxcDryRun([string] $wxc, [hashtable] $config) {
    $json = $config | ConvertTo-Json -Depth 20 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $b64 = [Convert]::ToBase64String($bytes)
    return Invoke-Native @($wxc, "--config-base64", $b64, "--dry-run")
}

function Invoke-WxcPhase([string] $wxc, [hashtable] $config, [switch] $Experimental) {
    $json = $config | ConvertTo-Json -Depth 20 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $b64 = [Convert]::ToBase64String($bytes)
    if ($Experimental) {
        return Invoke-Native @($wxc, "--config-base64", $b64, "--experimental")
    } else {
        return Invoke-Native @($wxc, "--config-base64", $b64)
    }
}

function Invoke-WxcProbe([string] $wxc) {
    return Invoke-Native @($wxc, "--probe")
}

# ── OS info ───────────────────────────────────────────────────────────────────

$osVersion = [System.Environment]::OSVersion.Version
$osBuild = $osVersion.Build
$osRevision = 0
try {
    $ubr = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).UBR
    if ($null -ne $ubr) { $osRevision = $ubr }
} catch {}
$osBuildFull = "$osBuild.$osRevision"
$isoSessionMinBuild = 26300
$isoSessionMinRevision = 8553

# ── wxc-exec info ─────────────────────────────────────────────────────────────

$wxcInfo = @{
    path   = $WxcExecPath
    exists = $false
    size   = $null
    mtime  = $null
}

if (Test-Path $WxcExecPath) {
    $item = Get-Item $WxcExecPath
    $wxcInfo.exists = $true
    $wxcInfo.size   = $item.Length
    $wxcInfo.mtime  = $item.LastWriteTime.ToString("o")
}

# ── Probe section ─────────────────────────────────────────────────────────────

$probeOutput = $null
$dryRunExitCode = $null
$dryRunOutput = $null
$pcTrialResult = "absent"
$pcTrialMessage = "wxc-exec not found"
$isoTrialResult = "absent"
$isoTrialMessage = "wxc-exec not found"

if ($wxcInfo.exists) {
    # --probe
    $probeResult = Invoke-WxcProbe -wxc $WxcExecPath
    $probeOutput = $probeResult.Output

    # dry-run trial (minimal processcontainer config)
    $dryConfig = @{
        version     = "0.6.0-alpha"
        containerId = "probe-dryrun"
        containment = "processcontainer"
        process     = @{
            commandLine = "cmd /c exit 0"
            cwd         = "%TEMP%"
            timeout     = 0
        }
        filesystem  = @{
            readwritePaths = @("%TEMP%")
        }
    }
    $dryResult = Invoke-WxcDryRun -wxc $WxcExecPath -config $dryConfig
    $dryRunExitCode = $dryResult.ExitCode
    $dryRunOutput = $dryResult.Output

    # processcontainer one-shot trial
    $pcConfig = @{
        version     = "0.6.0-alpha"
        containerId = "probe-pc-oneshot"
        containment = "processcontainer"
        process     = @{
            commandLine = "cmd /c exit 0"
            cwd         = "%TEMP%"
            timeout     = 10
        }
        filesystem  = @{
            readwritePaths = @("%TEMP%")
        }
        processContainer = @{
            leastPrivilege = $false
        }
    }
    $pcResult = Invoke-WxcPhase -wxc $WxcExecPath -config $pcConfig
    $pcOutput = $pcResult.Output
    $pcOutputLower = $pcOutput.ToLower()

    if ($pcResult.ExitCode -eq 0) {
        $pcTrialResult  = "works"
        $pcTrialMessage = "processcontainer one-shot exited 0"
    } elseif ($pcOutputLower -match "backend_error" -or $pcOutputLower -match "e_notimpl" -or $pcOutputLower -match "velocity") {
        $pcTrialResult  = "backend_error"
        # Try to extract the message from the JSON envelope.
        $pcTrialMessage = "backend_error: velocity keys not enabled (E_NOTIMPL)"
        try {
            $envelope = $pcOutput | ConvertFrom-Json
            if ($null -ne $envelope.error) {
                $pcTrialMessage = "backend_error: $($envelope.error.message)"
            }
        } catch {}
    } else {
        $pcTrialResult  = "error"
        if ([string]::IsNullOrWhiteSpace($pcOutput)) {
            $pcTrialMessage = "exit $($pcResult.ExitCode) with no output captured"
        } else {
            $pcTrialMessage = "exit $($pcResult.ExitCode): $pcOutput"
        }
    }

    # isolation_session provision trial
    $isoConfig = @{
        version     = "0.6.0-alpha"
        phase       = "provision"
        containment = "isolation_session"
        filesystem  = @{
            readwritePaths = @()
            readonlyPaths  = @()
        }
        experimental = @{
            isolation_session = @{
                configurationId = "composable"
                provision       = @{}
            }
        }
    }
    $isoResult = Invoke-WxcPhase -wxc $WxcExecPath -config $isoConfig -Experimental
    $isoOutput = $isoResult.Output
    $isoOutputLower = $isoOutput.ToLower()

    if ($isoOutputLower -match "backend_unavailable" -or $isoOutputLower -match "0x80040154") {
        $isoTrialResult  = "unavailable"
        $isoTrialMessage = "backend_unavailable: IsoSessionApp.dll absent or OS build < 26300.8553"
    } elseif ($isoResult.ExitCode -eq 0) {
        # Provision succeeded — deprovision immediately to avoid orphaning.
        $isoTrialResult  = "live"
        $isoTrialMessage = "isolation_session provision succeeded"
        $sandboxId = $null
        try {
            $envelope = $isoOutput | ConvertFrom-Json
            if ($null -ne $envelope.result) {
                $sandboxId = $envelope.result.sandboxId
            }
        } catch {}

        if ($null -ne $sandboxId) {
            # Stop first (a provisioned-but-unstarted session may still accept it;
            # ignore failures), then deprovision. Surface the deprovision error
            # text — an orphaned session blocks the single-session backend.
            $stopConfig = @{
                version    = "0.6.0-alpha"
                phase      = "stop"
                sandboxId  = $sandboxId
                experimental = @{
                    isolation_session = @{
                        # Unit variant: serialize as null, not {} (malformed_request otherwise).
                        stop = $null
                    }
                }
            }
            Invoke-WxcPhase -wxc $WxcExecPath -config $stopConfig -Experimental | Out-Null
            $deprovConfig = @{
                version    = "0.6.0-alpha"
                phase      = "deprovision"
                sandboxId  = $sandboxId
                experimental = @{
                    isolation_session = @{
                        deprovision = $null
                    }
                }
            }
            $deprovResult = Invoke-WxcPhase -wxc $WxcExecPath -config $deprovConfig -Experimental
            if ($deprovResult.ExitCode -eq 0) {
                $isoTrialMessage = "isolation_session live (provisioned $sandboxId, deprovisioned cleanly)"
            } else {
                $snippet = $deprovResult.Output
                if ($snippet.Length -gt 200) { $snippet = $snippet.Substring(0, 200) }
                $isoTrialMessage = "isolation_session live (provisioned $sandboxId; deprovision FAILED exit $($deprovResult.ExitCode): $snippet -- clean up manually before running lifecycle tests)"
            }
        }
    } else {
        $isoTrialResult  = "error"
        $isoTrialMessage = "exit $($isoResult.ExitCode): $isoOutput"
    }
}

# ── Verdicts ──────────────────────────────────────────────────────────────────

$pcVerdict = $null
if ($pcTrialResult -eq "works") {
    $pcVerdict = "live"
} else {
    $pcVerdict = "unavailable: $pcTrialMessage"
}

$isoVerdict = $null
if ($isoTrialResult -eq "live") {
    $isoVerdict = "live"
} else {
    $isoVerdict = "unavailable: $isoTrialMessage"
}

$dryRunVerdict = $null
if ($null -eq $dryRunExitCode) {
    $dryRunVerdict = "unavailable: wxc-exec not found"
} elseif ($dryRunExitCode -eq 0) {
    $dryRunVerdict = "ok"
} else {
    $dryRunVerdict = "failed: exit $dryRunExitCode"
}

# ── Assemble report ───────────────────────────────────────────────────────────

$report = [ordered]@{
    generatedAt = (Get-Date).ToString("o")
    host        = [ordered]@{
        osBuild        = $osBuildFull
        osBuildNumber  = $osBuild
        osRevision     = $osRevision
        isoSessionBuildRequirement = "${isoSessionMinBuild}.${isoSessionMinRevision}"
        meetsIsoBuildReq = ($osBuild -gt $isoSessionMinBuild) -or
                           ($osBuild -eq $isoSessionMinBuild -and $osRevision -ge $isoSessionMinRevision)
    }
    wxcExec     = $wxcInfo
    probeOutput = $probeOutput
    dryRun      = [ordered]@{
        exitCode = $dryRunExitCode
        output   = $dryRunOutput
    }
    processcontainerTrial = [ordered]@{
        result  = $pcTrialResult
        message = $pcTrialMessage
    }
    isolationSessionTrial = [ordered]@{
        result  = $isoTrialResult
        message = $isoTrialMessage
    }
    verdicts = [ordered]@{
        processcontainer = $pcVerdict
        isolation_session = $isoVerdict
        dryRun           = $dryRunVerdict
    }
}

$json = $report | ConvertTo-Json -Depth 10

if ($Full) {
    Write-Output $json
} else {
    $met = "not met"
    if ($report.host.meetsIsoBuildReq) { $met = "met" }
    Write-Host "MXC host probe - OS build $osBuildFull (isolation_session requires $($report.host.isoSessionBuildRequirement): $met)"
    Write-Host "wxc-exec: $WxcExecPath (exists=$($wxcInfo.exists))"
    Write-Host "verdicts:"
    Write-Host "  processcontainer  : $pcVerdict"
    Write-Host "  isolation_session : $isoVerdict"
    Write-Host "  dry-run           : $dryRunVerdict"
    Write-Host "(re-run with -Full for the complete JSON report, or -OutFile caps.json to save it)"
}

if ($OutFile) {
    $json | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "Report written to $OutFile" -ForegroundColor Cyan
}
