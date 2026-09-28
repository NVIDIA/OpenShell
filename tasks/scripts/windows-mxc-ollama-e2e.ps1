# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs the shipped MXC Ollama demo through the real gateway and CLI against the
# in-process wxc mock and a local Ollama-compatible HTTP stub. This proves demo
# wiring only; it is not evidence of MXC or AppContainer enforcement.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")]
    [string] $Target,

    [string] $GatewayPath,
    [string] $CliPath,
    [string] $ArtifactRoot,
    [switch] $KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw "windows-mxc-ollama-e2e.ps1 requires Windows."
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
$StageDir = [System.IO.Path]::GetFullPath((Join-Path $ArtifactRoot "openshell-mxc-ollama-e2e-$Target"))
$expectedPrefix = $ArtifactRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $StageDir.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "refusing to use staging path outside artifact root: $StageDir"
}
if (Test-Path -LiteralPath $StageDir) {
    Remove-Item -LiteralPath $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $StageDir | Out-Null

foreach ($fixture in @("run-ollama-test.ps1", "mxc-ollama.toml", "ollama.yaml")) {
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

function Test-Listener([int] $Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(250)) { return $false }
        $client.EndConnect($pending)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

$ApiPort = Get-AvailablePort
$RequestLog = Join-Path $StageDir "mock-ollama-requests.log"
$ServerReady = Join-Path $StageDir "mock-ollama.ready"
$ServerOutLog = Join-Path $StageDir "mock-ollama.out.log"
$ServerErrLog = Join-Path $StageDir "mock-ollama.err.log"
$ServerScript = Join-Path $PSScriptRoot "windows-mxc-ollama-stub.ps1"
$serverProcess = $null
$passed = $false
$oldAppData = $env:APPDATA
$oldLocalAppData = $env:LOCALAPPDATA

try {
    $serverProcess = Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$ServerScript`"",
        "-Port", "$ApiPort",
        "-RequestLog", "`"$RequestLog`"",
        "-ReadyPath", "`"$ServerReady`""
    ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $ServerOutLog -RedirectStandardError $ServerErrLog

    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline -and (-not (Test-Path -LiteralPath $ServerReady) -or -not (Test-Listener $ApiPort))) {
        if ($serverProcess.HasExited) {
            $details = (Get-Content $ServerOutLog, $ServerErrLog -ErrorAction SilentlyContinue) -join [Environment]::NewLine
            throw "mock Ollama server stopped before listening: $details"
        }
        Start-Sleep -Milliseconds 200
    }
    if (-not (Test-Listener $ApiPort)) {
        throw "mock Ollama server did not listen on port $ApiPort within 15 seconds"
    }

    $env:APPDATA = Join-Path $StageDir "appdata"
    $env:LOCALAPPDATA = Join-Path $StageDir "localappdata"
    New-Item -ItemType Directory -Force -Path $env:APPDATA, $env:LOCALAPPDATA | Out-Null

    $runner = Join-Path $StageDir "run-ollama-test.ps1"
    $share = Join-Path $StageDir "share"
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner `
        -Mock `
        -GatewayPath $GatewayPath `
        -CliPath $CliPath `
        -ShareDir $share `
        -OllamaPort $ApiPort `
        -Model "openshell-ci-mock" `
        -Prompt "Return the CI mock response." `
        -KeepArtifacts 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($exitCode -ne 0) {
        throw "shipped Ollama demo failed in mock mode (exit $exitCode)"
    }

    $resultDir = Get-ChildItem -LiteralPath $StageDir -Directory -Filter "results-ollama-*" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $resultDir) { throw "Ollama demo did not produce a results directory" }

    $summary = Get-Content -LiteralPath (Join-Path $resultDir.FullName "summary.txt") -Raw
    if ($summary -notmatch '(?m)^verdict=PASS\s*$' -or $summary -notmatch '(?m)^mode=mock-wiring\s*$') {
        throw "Ollama demo summary did not report a mock-wiring PASS: $summary"
    }
    $response = Get-Content -LiteralPath (Join-Path $resultDir.FullName "ollama-response.json") -Raw | ConvertFrom-Json
    if ($response.response -ne "Hello from the CI mock.") {
        throw "Ollama demo did not retain the expected mock completion"
    }

    $requests = Get-Content -LiteralPath $RequestLog -Raw
    if ($requests -notmatch 'GET /api/tags ' -or $requests -notmatch 'POST /api/generate ') {
        throw "mock Ollama server did not observe both demo API calls: $requests"
    }

    $passed = $true
    Write-Host "MXC Ollama example mock E2E passed for $Target"
} catch {
    Write-Host "MXC Ollama example mock E2E failed: $($_.Exception.Message)" -ForegroundColor Red
    Get-ChildItem -LiteralPath $StageDir -File -Recurse -Include "*.log", "summary.txt" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Host "--- $($_.FullName) ---"
            Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
        }
    throw
} finally {
    $env:APPDATA = $oldAppData
    $env:LOCALAPPDATA = $oldLocalAppData
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
        try { [void] $serverProcess.WaitForExit(5000) } catch {}
    }
    if ($passed -and -not $KeepArtifacts -and (Test-Path -LiteralPath $StageDir)) {
        Remove-Item -LiteralPath $StageDir -Recurse -Force
    } else {
        Write-Host "MXC Ollama example artifacts: $StageDir"
    }
}
