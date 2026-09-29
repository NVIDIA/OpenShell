# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs the shipped MXC OCSF audit example with the in-process wxc mock. The test
# requires the ETW consumer's durable zero-provider-events finding; it does not
# claim real Sandboxing-provider coverage or MXC enforcement.

[CmdletBinding()]
param(
    [string] $GatewayPath,
    [string] $CliPath,
    [string] $ArtifactRoot,
    [switch] $Mock,
    [switch] $KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
. (Join-Path $PSScriptRoot "windows-mxc-e2e-environment.ps1")

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw "windows-mxc-ocsf-audit-e2e.ps1 requires Windows."
}
if (-not $Mock) {
    throw "windows-mxc-ocsf-audit-e2e.ps1 only supports mock mode; pass -Mock."
}

$Target = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    "X64" { "x86_64-pc-windows-msvc" }
    "Arm64" { "aarch64-pc-windows-msvc" }
    default { throw "unsupported native Windows architecture: $($_)" }
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ExamplesRoot = Join-Path $RepoRoot "crates\openshell-driver-mxc\examples"
$TargetDir = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
    Join-Path $RepoRoot "target"
} else {
    [System.IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
}

if ([string]::IsNullOrWhiteSpace($GatewayPath)) {
    $GatewayPath = Join-Path $TargetDir "$Target\release\openshell-gateway.exe"
}
if ([string]::IsNullOrWhiteSpace($CliPath)) {
    $CliPath = Join-Path $TargetDir "$Target\release\openshell.exe"
}
$GatewayPath = [System.IO.Path]::GetFullPath($GatewayPath)
$CliPath = [System.IO.Path]::GetFullPath($CliPath)

foreach ($artifact in @($GatewayPath, $CliPath)) {
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        throw "required release artifact is missing: $artifact"
    }
}

if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
    $ArtifactRoot = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
        [System.IO.Path]::GetTempPath()
    } else {
        $env:RUNNER_TEMP
    }
}
$ArtifactRoot = [System.IO.Path]::GetFullPath($ArtifactRoot)
$StageDir = [System.IO.Path]::GetFullPath((Join-Path $ArtifactRoot "openshell-mxc-ocsf-audit-e2e-$Target"))
$expectedPrefix = $ArtifactRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $StageDir.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "refusing to use staging path outside artifact root: $StageDir"
}
if (Test-Path -LiteralPath $StageDir) {
    Remove-Item -LiteralPath $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $StageDir | Out-Null

foreach ($fixture in @("run-ocsf-audit.ps1", "mxc-ocsf-audit.toml", "ocsf-audit.yaml")) {
    Copy-Item -LiteralPath (Join-Path $ExamplesRoot $fixture) -Destination $StageDir
}

function Get-AvailablePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

$passed = $false
$environmentSnapshot = $null

try {
    $environmentSnapshot = Push-OpenShellMxcE2eEnvironment -StageDir $StageDir

    $runner = Join-Path $StageDir "run-ocsf-audit.ps1"
    $share = Join-Path $StageDir "share"
    $port = Get-AvailablePort
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner `
        -Mock `
        -GatewayPath $GatewayPath `
        -CliPath $CliPath `
        -ShareDir $share `
        -SandboxCount 1 `
        -Port $port `
        -GatewayName "openshell-mxc-ocsf-ci" 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($exitCode -ne 0) {
        throw "shipped OCSF audit example failed in mock mode (exit $exitCode)"
    }

    $resultDir = Get-ChildItem -LiteralPath $StageDir -Directory -Filter "results-*" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $resultDir) { throw "OCSF audit example did not produce a results directory" }

    $summary = Get-Content -LiteralPath (Join-Path $resultDir.FullName "summary.txt") -Raw
    if ($summary -notmatch '(?m)^verdict\s+: PASS\s*$' -or
        $summary -notmatch '(?m)^mode\s+: mock-wiring\s*$' -or
        $summary -notmatch '(?m)^zero-event audit\s+: warning \+ durable finding observed\s*$') {
        throw "OCSF audit summary did not report the expected mock-wiring PASS: $summary"
    }

    $jsonl = Get-ChildItem -LiteralPath $resultDir.FullName -File -Filter "openshell-ocsf*.log" |
        Select-Object -First 1
    if ($null -eq $jsonl) { throw "OCSF audit example did not produce a JSONL audit log" }
    $findingObserved = $false
    foreach ($line in Get-Content -LiteralPath $jsonl.FullName) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $event = $line | ConvertFrom-Json
        $findingInfo = $event.PSObject.Properties["finding_info"]
        if ($findingInfo -and $findingInfo.Value.uid -eq "mxc-etw-zero-events") {
            $findingObserved = $true
        }
    }
    if (-not $findingObserved) {
        throw "OCSF JSONL did not contain the mxc-etw-zero-events finding"
    }

    $passed = $true
    Write-Host "MXC OCSF audit example mock E2E passed for $Target"
} catch {
    Write-Host "MXC OCSF audit example mock E2E failed: $($_.Exception.Message)" -ForegroundColor Red
    Get-ChildItem -LiteralPath $StageDir -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @(".log", ".txt") } |
        ForEach-Object {
            Write-Host "--- $($_.FullName) ---"
            Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
        }
    throw
} finally {
    if ($null -ne $environmentSnapshot) {
        Pop-OpenShellMxcE2eEnvironment -Snapshot $environmentSnapshot
    }
    if ($passed -and -not $KeepArtifacts -and (Test-Path -LiteralPath $StageDir)) {
        Remove-Item -LiteralPath $StageDir -Recurse -Force
    } else {
        Write-Host "MXC OCSF audit example artifacts: $StageDir"
    }
}
