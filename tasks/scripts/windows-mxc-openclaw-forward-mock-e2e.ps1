# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the shipped OpenClaw forward example with the in-process wxc shim and
# an in-policy proof command. This does not launch OpenClaw or a relay.
[CmdletBinding()]
param(
    [string] $GatewayPath,
    [string] $CliPath,
    [string] $ArtifactRoot,
    [switch] $KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw "windows-mxc-openclaw-forward-mock-e2e.ps1 requires Windows"
}
$target = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    "X64" { "x86_64-pc-windows-msvc" }
    "Arm64" { "aarch64-pc-windows-msvc" }
    default { throw "unsupported native Windows architecture: $($_)" }
}
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$examplesRoot = Join-Path $repoRoot "crates\openshell-driver-mxc\examples"
$targetDir = if ($env:CARGO_TARGET_DIR) { [System.IO.Path]::GetFullPath($env:CARGO_TARGET_DIR) } else { Join-Path $repoRoot "target" }
if (-not $GatewayPath) { $GatewayPath = Join-Path $targetDir "$target\release\openshell-gateway.exe" }
if (-not $CliPath) { $CliPath = Join-Path $targetDir "$target\release\openshell.exe" }
$GatewayPath = [System.IO.Path]::GetFullPath($GatewayPath)
$CliPath = [System.IO.Path]::GetFullPath($CliPath)
foreach ($binary in @($GatewayPath, $CliPath)) {
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "required release binary is missing: $binary" }
}

if (-not $ArtifactRoot) {
    $ArtifactRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
}
$ArtifactRoot = [System.IO.Path]::GetFullPath($ArtifactRoot)
$stageDir = [System.IO.Path]::GetFullPath((Join-Path $ArtifactRoot "openshell-mxc-openclaw-forward-$target-$PID"))
$expectedPrefix = $ArtifactRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $stageDir.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "staging directory is outside artifact root: $stageDir"
}
New-Item -ItemType Directory -Path $stageDir | Out-Null
$passed = $false
$oldAppData = $env:APPDATA
$oldLocalAppData = $env:LOCALAPPDATA
$oldXdgConfigHome = $env:XDG_CONFIG_HOME
$oldXdgStateHome = $env:XDG_STATE_HOME
$oldXdgDataHome = $env:XDG_DATA_HOME

function Get-AvailablePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally { $listener.Stop() }
}

try {
    $env:APPDATA = Join-Path $stageDir "appdata"
    $env:LOCALAPPDATA = Join-Path $stageDir "localappdata"
    $env:XDG_CONFIG_HOME = Join-Path $stageDir "xdg-config"
    $env:XDG_STATE_HOME = Join-Path $stageDir "xdg-state"
    $env:XDG_DATA_HOME = Join-Path $stageDir "xdg-data"
    New-Item -ItemType Directory -Force -Path @(
        $env:APPDATA, $env:LOCALAPPDATA,
        $env:XDG_CONFIG_HOME, $env:XDG_STATE_HOME, $env:XDG_DATA_HOME
    ) | Out-Null

    New-Item -ItemType Directory -Path (Join-Path $stageDir "e2e-policies") | Out-Null
    foreach ($fixture in @("run-openclaw-forward-test.ps1", "run-openclaw-forward-mock.ps1", "mxc-openclaw-gateway.toml")) {
        Copy-Item -LiteralPath (Join-Path $examplesRoot $fixture) -Destination $stageDir
    }
    Copy-Item -LiteralPath (Join-Path $examplesRoot "e2e-policies\openclaw-gateway.yaml") -Destination (Join-Path $stageDir "e2e-policies")

    $port = Get-AvailablePort
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $stageDir "run-openclaw-forward-test.ps1") `
        -Mock -GatewayPath $GatewayPath -CliPath $CliPath -ShareDir (Join-Path $stageDir "share") -Port $port
    if ($LASTEXITCODE -ne 0) { throw "MXC OpenClaw forward example failed (exit $LASTEXITCODE)" }

    $result = Get-ChildItem -LiteralPath $stageDir -Directory -Filter "results-openclaw-forward-mock-*" |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($null -eq $result) { throw "OpenClaw example produced no result bundle" }
    $summary = Get-Content -LiteralPath (Join-Path $result.FullName "summary.txt") -Raw
    if ($summary -notmatch '(?m)^verdict=PASS\s*$' -or
        $summary -notmatch '(?m)^mode=mock-wiring\s*$') {
        throw "OpenClaw example did not report a mock-wiring PASS"
    }

    $passed = $true
    Write-Host "MXC OpenClaw forward example mock CI passed for $target"
} finally {
    $env:APPDATA = $oldAppData
    $env:LOCALAPPDATA = $oldLocalAppData
    $env:XDG_CONFIG_HOME = $oldXdgConfigHome
    $env:XDG_STATE_HOME = $oldXdgStateHome
    $env:XDG_DATA_HOME = $oldXdgDataHome
    if ($passed -and -not $KeepArtifacts -and (Test-Path -LiteralPath $stageDir)) {
        Remove-Item -LiteralPath $stageDir -Recurse -Force
    } else {
        Write-Host "MXC OpenClaw forward example artifacts: $stageDir"
    }
}
