# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs both shipped MXC inference demos through the real gateway and CLI
# against the in-process wxc mock and a local HTTP API stub. This proves demo
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
    throw "windows-mxc-inference-examples-e2e.ps1 requires Windows."
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
$StageDir = [System.IO.Path]::GetFullPath((Join-Path $ArtifactRoot "openshell-mxc-inference-examples-e2e-$Target"))
$expectedPrefix = $ArtifactRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $StageDir.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "refusing to use staging path outside artifact root: $StageDir"
}
if (Test-Path -LiteralPath $StageDir) {
    Remove-Item -LiteralPath $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $StageDir | Out-Null

foreach ($fixture in @(
    "run-ollama-test.ps1",
    "mxc-ollama.toml",
    "ollama.yaml",
    "run-inference-test.ps1",
    "mxc-inference.toml",
    "inference.yaml"
)) {
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
$MockToken = "openshell-ci-mock-token"
$RequestLog = Join-Path $StageDir "mock-inference-requests.log"
$ServerReady = Join-Path $StageDir "mock-inference.ready"
$ServerOutLog = Join-Path $StageDir "mock-inference.out.log"
$ServerErrLog = Join-Path $StageDir "mock-inference.err.log"
$ServerScript = Join-Path $PSScriptRoot "windows-mxc-inference-stub.ps1"
$serverProcess = $null
$passed = $false
$oldAppData = $env:APPDATA
$oldLocalAppData = $env:LOCALAPPDATA
$oldNvApiKey = $env:NV_API_KEY

try {
    $serverProcess = Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$ServerScript`"",
        "-Port", "$ApiPort",
        "-RequestLog", "`"$RequestLog`"",
        "-ReadyPath", "`"$ServerReady`"",
        "-ExpectedBearerToken", $MockToken
    ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $ServerOutLog -RedirectStandardError $ServerErrLog

    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline -and (-not (Test-Path -LiteralPath $ServerReady) -or -not (Test-Listener $ApiPort))) {
        if ($serverProcess.HasExited) {
            $details = (Get-Content $ServerOutLog, $ServerErrLog -ErrorAction SilentlyContinue) -join [Environment]::NewLine
            throw "mock inference server stopped before listening: $details"
        }
        Start-Sleep -Milliseconds 200
    }
    if (-not (Test-Listener $ApiPort)) {
        throw "mock inference server did not listen on port $ApiPort within 15 seconds"
    }

    $env:APPDATA = Join-Path $StageDir "appdata"
    $env:LOCALAPPDATA = Join-Path $StageDir "localappdata"
    New-Item -ItemType Directory -Force -Path $env:APPDATA, $env:LOCALAPPDATA | Out-Null

    $ollamaRunner = Join-Path $StageDir "run-ollama-test.ps1"
    $ollamaShare = Join-Path $StageDir "ollama-share"
    $ollamaArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $ollamaRunner,
        "-Mock",
        "-GatewayPath", $GatewayPath,
        "-CliPath", $CliPath,
        "-ShareDir", $ollamaShare,
        "-OllamaPort", "$ApiPort",
        "-Model", "openshell-ci-mock",
        "-Prompt", "Return the CI mock response.",
        "-KeepArtifacts"
    )
    $output = & powershell.exe @ollamaArgs 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($exitCode -ne 0) {
        throw "shipped Ollama demo failed in mock mode (exit $exitCode)"
    }

    $ollamaResultDir = Get-ChildItem -LiteralPath $StageDir -Directory -Filter "results-ollama-*" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $ollamaResultDir) { throw "Ollama demo did not produce a results directory" }

    $ollamaSummary = Get-Content -LiteralPath (Join-Path $ollamaResultDir.FullName "summary.txt") -Raw
    if ($ollamaSummary -notmatch '(?m)^verdict=PASS\s*$' -or $ollamaSummary -notmatch '(?m)^mode=mock-wiring\s*$') {
        throw "Ollama demo summary did not report a mock-wiring PASS: $ollamaSummary"
    }
    $ollamaResponse = Get-Content -LiteralPath (Join-Path $ollamaResultDir.FullName "ollama-response.json") -Raw | ConvertFrom-Json
    if ($ollamaResponse.response -ne "Hello from the CI mock.") {
        throw "Ollama demo did not retain the expected mock completion"
    }

    $env:NV_API_KEY = $MockToken
    $cloudRunner = Join-Path $StageDir "run-inference-test.ps1"
    $cloudShare = Join-Path $StageDir "cloud-share"
    $cloudApiUrl = "http://127.0.0.1:$ApiPort/v1/chat/completions"
    $cloudArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $cloudRunner,
        "-Mock",
        "-GatewayPath", $GatewayPath,
        "-CliPath", $CliPath,
        "-ShareDir", $cloudShare,
        "-ApiUrl", $cloudApiUrl,
        "-Model", "openshell-ci-mock",
        "-Prompt", "Return the CI mock response.",
        "-KeepArtifacts"
    )
    $output = & powershell.exe @cloudArgs 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($exitCode -ne 0) {
        throw "shipped cloud-inference demo failed in mock mode (exit $exitCode)"
    }

    $cloudResultDir = Get-ChildItem -LiteralPath $StageDir -Directory -Filter "results-inference-*" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $cloudResultDir) { throw "cloud-inference demo did not produce a results directory" }

    $cloudSummary = Get-Content -LiteralPath (Join-Path $cloudResultDir.FullName "summary.txt") -Raw
    if ($cloudSummary -notmatch '(?m)^verdict=PASS\s*$' -or $cloudSummary -notmatch '(?m)^mode=mock-wiring\s*$') {
        throw "cloud-inference demo summary did not report a mock-wiring PASS: $cloudSummary"
    }
    $cloudResponse = Get-Content -LiteralPath (Join-Path $cloudResultDir.FullName "inference-response.json") -Raw | ConvertFrom-Json
    if ($cloudResponse.choices[0].message.content -ne "Hello from the CI mock.") {
        throw "cloud-inference demo did not retain the expected mock completion"
    }

    $requestLines = @([System.IO.File]::ReadAllLines($RequestLog))
    $expectedRequests = @(
        @{ Pattern = '^GET /api/tags HTTP/\S+ authorization=absent$'; Count = 2; Description = 'host prerequisite and sandbox Ollama tag requests' },
        @{ Pattern = '^POST /api/generate HTTP/\S+ authorization=absent$'; Count = 1; Description = 'sandbox Ollama generation request' },
        @{ Pattern = '^POST /v1/chat/completions HTTP/\S+ authorization=synthetic$'; Count = 1; Description = 'sandbox cloud-inference request with the synthetic CI credential' }
    )
    foreach ($expected in $expectedRequests) {
        $actualCount = @($requestLines | Where-Object { $_ -match $expected.Pattern }).Count
        if ($actualCount -ne $expected.Count) {
            throw "mock inference server observed $actualCount $($expected.Description); expected $($expected.Count): $($requestLines -join '; ')"
        }
    }

    $passed = $true
    Write-Host "MXC inference examples mock E2E passed for $Target"
} catch {
    Write-Host "MXC inference examples mock E2E failed: $($_.Exception.Message)" -ForegroundColor Red
    Get-ChildItem -LiteralPath $StageDir -File -Recurse -Include "*.log", "summary.txt" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Host "--- $($_.FullName) ---"
            Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
        }
    throw
} finally {
    $env:APPDATA = $oldAppData
    $env:LOCALAPPDATA = $oldLocalAppData
    if ([string]::IsNullOrWhiteSpace($oldNvApiKey)) {
        Remove-Item Env:NV_API_KEY -ErrorAction SilentlyContinue
    } else {
        $env:NV_API_KEY = $oldNvApiKey
    }
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
        try { [void] $serverProcess.WaitForExit(5000) } catch {}
    }
    if ($passed -and -not $KeepArtifacts -and (Test-Path -LiteralPath $StageDir)) {
        Remove-Item -LiteralPath $StageDir -Recurse -Force
    } else {
        Write-Host "MXC inference example artifacts: $StageDir"
    }
}
