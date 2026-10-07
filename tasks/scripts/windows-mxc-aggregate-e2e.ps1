# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs the shipped aggregate MXC scenario runner with the in-process wxc mock.
# This validates example, CLI, gateway, and driver wiring; it does not claim
# native MXC or Windows isolation enforcement coverage.

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
    throw "windows-mxc-aggregate-e2e.ps1 requires Windows."
}
if (-not $Mock) {
    throw "windows-mxc-aggregate-e2e.ps1 only supports mock mode; pass -Mock."
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
$StageDir = [System.IO.Path]::GetFullPath((Join-Path $ArtifactRoot "openshell mxc aggregate e2e-$Target"))
$expectedPrefix = $ArtifactRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $StageDir.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "refusing to use staging path outside artifact root: $StageDir"
}
if (Test-Path -LiteralPath $StageDir) {
    Remove-Item -LiteralPath $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $StageDir | Out-Null

foreach ($fixture in @("run-mxc-e2e.ps1", "mxc-gateway.toml")) {
    Copy-Item -LiteralPath (Join-Path $ExamplesRoot $fixture) -Destination $StageDir
}
Copy-Item -LiteralPath (Join-Path $ExamplesRoot "e2e-policies") -Destination $StageDir -Recurse

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

    $runner = Join-Path $StageDir "run-mxc-e2e.ps1"
    $demoDir = Join-Path $StageDir "demo"
    $gatewayName = "openshell-mxc-aggregate-ci"
    $sentinelEndpoint = "http://127.0.0.1:9"
    $inheritedEndpoint = "http://127.0.0.1:1"
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $sentinelAdd = & $CliPath gateway add $sentinelEndpoint --local --name $gatewayName 2>&1
        $sentinelAddExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($sentinelAddExitCode -ne 0) {
        throw "failed to seed sentinel gateway '$gatewayName': $($sentinelAdd -join [Environment]::NewLine)"
    }
    $env:OPENSHELL_GATEWAY_ENDPOINT = $inheritedEndpoint
    foreach ($powerShell in @("powershell.exe", "pwsh.exe")) {
        $port = Get-AvailablePort
        $output = & $powerShell -NoProfile -ExecutionPolicy Bypass -File $runner `
            -Mock `
            -GatewayPath $GatewayPath `
            -CliPath $CliPath `
            -DemoDir $demoDir `
            -Port $port `
            -GatewayName $gatewayName 2>&1
        $exitCode = $LASTEXITCODE
        $output | ForEach-Object { Write-Host $_ }
        if ($exitCode -ne 0) {
            throw "shipped aggregate MXC example failed under $powerShell in mock mode (exit $exitCode)"
        }

        $gateways = & $CliPath gateway list -o json | ConvertFrom-Json
        $sentinel = $gateways | Where-Object { $_.name -eq $gatewayName } | Select-Object -First 1
        if ($null -eq $sentinel -or $sentinel.endpoint -ne $sentinelEndpoint -or -not $sentinel.active) {
            throw "aggregate runner changed the caller's sentinel gateway registration or active selection under $powerShell"
        }
        if ($env:OPENSHELL_GATEWAY_ENDPOINT -ne $inheritedEndpoint) {
            throw "aggregate runner changed the caller's OPENSHELL_GATEWAY_ENDPOINT under $powerShell"
        }
    }

    $resultDir = Get-ChildItem -LiteralPath $StageDir -Directory -Filter "results-e2e-*" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $resultDir) { throw "aggregate MXC example did not produce a results directory" }

    $summary = Get-Content -LiteralPath (Join-Path $resultDir.FullName "summary.txt") -Raw
    if ($summary -notmatch '(?m)^verdict\s+: PASS\s*$' -or
        $summary -notmatch '(?m)^mode\s+: MOCK\s*$' -or
        $summary -notmatch '(?m)^totals\s+: PASS=4\s+FAIL=0\s+SKIP=0\s*$' -or
        $summary -notmatch '(?m)^Mock mode validates runner/gateway/driver wiring') {
        throw "aggregate MXC summary did not report the expected four-scenario mock PASS: $summary"
    }

    if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) {
        throw "aggregate MXC example left gateway port $port listening"
    }

    $passed = $true
    Write-Host "MXC aggregate example mock E2E passed for $Target"
} catch {
    Write-Host "MXC aggregate example mock E2E failed: $($_.Exception.Message)" -ForegroundColor Red
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
        Write-Host "MXC aggregate example artifacts: $StageDir"
    }
}
