# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the shipped host probe against an explicitly absent wxc-exec. This
# verifies the hosted-runner diagnostic path, not real MXC availability.
[CmdletBinding()]
param(
    [string] $ArtifactRoot,
    [switch] $KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw "windows-mxc-host-probe-e2e.ps1 requires Windows"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$examplesRoot = Join-Path $repoRoot "crates\openshell-driver-mxc\examples"
if (-not $ArtifactRoot) {
    $ArtifactRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
}
$ArtifactRoot = [System.IO.Path]::GetFullPath($ArtifactRoot)
$stageDir = [System.IO.Path]::GetFullPath((Join-Path $ArtifactRoot "openshell-mxc-host-probe-$PID"))
$expectedPrefix = $ArtifactRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $stageDir.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "staging directory is outside artifact root: $stageDir"
}
New-Item -ItemType Directory -Path $stageDir | Out-Null
$passed = $false

try {
    $probe = Join-Path $stageDir "probe-mxc-host.ps1"
    Copy-Item -LiteralPath (Join-Path $examplesRoot "probe-mxc-host.ps1") -Destination $probe
    $report = Join-Path $stageDir "capabilities.json"
    $absentWxc = Join-Path $stageDir "absent-wxc-exec.exe"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -WxcExecPath $absentWxc -OutFile $report
    if ($LASTEXITCODE -ne 0) { throw "MXC host probe failed (exit $LASTEXITCODE)" }

    $capabilities = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
    if ($capabilities.wxcExec.exists -ne $false -or
        $capabilities.processcontainerTrial.result -ne "absent" -or
        $capabilities.isolationSessionTrial.result -ne "absent" -or
        $capabilities.host.osBuildNumber -le 0) {
        throw "host probe did not report the expected absent-backend diagnostic"
    }
    $passed = $true
    Write-Host "MXC host probe CI passed"
} finally {
    if ($passed -and -not $KeepArtifacts -and (Test-Path -LiteralPath $stageDir)) {
        Remove-Item -LiteralPath $stageDir -Recurse -Force
    } else {
        Write-Host "MXC host probe artifacts: $stageDir"
    }
}
