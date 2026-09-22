# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Hello World local-inference demo for OpenShell on MXC. PowerShell 5.1 compatible.

[CmdletBinding()]
param(
    [string] $WxcExecPath,
    [string] $GatewayPath,
    [string] $CliPath,
    [string] $ShareDir,
    [string] $OllamaHost = "127.0.0.1",
    [ValidateRange(1, 65535)] [int] $OllamaPort = 11434,
    [string] $Model = "qwen3.5:0.8b",
    [string] $Prompt = "Say hello in exactly five words.",
    [ValidateRange(0, 65535)] [int] $Port = 0,
    [string] $SandboxName,
    [switch] $KeepArtifacts
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8
$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$resultDir = Join-Path $here "results-ollama-$stamp-$PID"
New-Item -ItemType Directory -Path $resultDir | Out-Null

function Info([string]$message) { Write-Host "    $message" }
function Ok([string]$message) { Write-Host "[OK]   $message" -ForegroundColor Green }
function Bad([string]$message) { Write-Host "[FAIL] $message" -ForegroundColor Red }

function Resolve-Executable([string]$explicit, [string]$leaf, [string]$environmentName) {
    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($explicit)) { [void]$candidates.Add($explicit) }
    if (-not [string]::IsNullOrWhiteSpace($environmentName)) {
        $fromEnvironment = [Environment]::GetEnvironmentVariable($environmentName)
        if (-not [string]::IsNullOrWhiteSpace($fromEnvironment)) { [void]$candidates.Add($fromEnvironment) }
    }
    [void]$candidates.Add((Join-Path $here $leaf))
    [void]$candidates.Add((Join-Path (Join-Path $here "bin") $leaf))
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }
    $command = Get-Command $leaf -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
    if ($environmentName) {
        throw "$leaf was not found. Pass -WxcExecPath, set $environmentName, place $leaf beside this script, or add it to PATH."
    }
    throw "$leaf was not found. Pass its path explicitly or place it beside this script."
}

function Get-AvailablePort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Test-Port([int]$candidate) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect("127.0.0.1", $candidate, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(250)) { return $false }
        $client.EndConnect($pending)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Quote-NativeArgument([string]$value) {
    if ($value.Length -gt 0 -and $value -notmatch '[\s"]') { return $value }
    $quoted = New-Object System.Text.StringBuilder
    [void]$quoted.Append('"')
    $backslashes = 0
    foreach ($ch in $value.ToCharArray()) {
        if ($ch -eq '\') { $backslashes++; continue }
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

function Invoke-Cli([string[]]$CommandArgs, [switch]$AllowFailure) {
    $allArgs = @("--gateway-endpoint", $endpoint) + $CommandArgs
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $cli
    $startInfo.Arguments = (($allArgs | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "failed to start OpenShell CLI '$cli'" }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $text = (@($stdout.Result, $stderr.Result) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine
    $text = $text.Trim()
    if (-not $AllowFailure -and $process.ExitCode -ne 0) {
        throw "openshell $($CommandArgs -join ' ') failed (exit $($process.ExitCode)): $text"
    }
    return @{ ExitCode = $process.ExitCode; Text = $text }
}

function Write-Utf8([string]$path, [string]$contents) {
    [System.IO.File]::WriteAllText($path, $contents, $utf8NoBom)
}

$gateway = $null
$cli = $null
$wxc = $null
$gatewayProcess = $null
$createdShare = $false
$success = $false
$failure = $null
$oldGatewayConfig = $env:OPENSHELL_GATEWAY_CONFIG
$oldComputeDriver = $env:OPENSHELL_COMPUTE_DRIVER

try {
    $gateway = Resolve-Executable $GatewayPath "openshell-gateway.exe" ""
    $cli = Resolve-Executable $CliPath "openshell.exe" ""
    $wxc = Resolve-Executable $WxcExecPath "wxc-exec.exe" "OPENSHELL_WXC_EXEC_PATH"
    foreach ($fixture in @("mxc-ollama.toml", "ollama.yaml")) {
        if (-not (Test-Path -LiteralPath (Join-Path $here $fixture) -PathType Leaf)) {
            throw "required demo fixture '$fixture' is missing beside the runner"
        }
    }
    if ($OllamaHost -notmatch '^[A-Za-z0-9.-]+$') {
        throw "OllamaHost '$OllamaHost' is invalid; use an IPv4 address or DNS name"
    }
    if ($Port -eq 0) { $Port = Get-AvailablePort }
    $endpoint = "http://127.0.0.1:$Port"
    if ([string]::IsNullOrWhiteSpace($SandboxName)) { $SandboxName = "ollama-$PID" }
    if ([string]::IsNullOrWhiteSpace($ShareDir)) {
        $ShareDir = Join-Path ([System.IO.Path]::GetTempPath()) "openshell-mxc-ollama-$PID-$([Guid]::NewGuid().ToString('N'))"
        $createdShare = $true
    }
    $ShareDir = [System.IO.Path]::GetFullPath($ShareDir).TrimEnd('\', '/')
    if ($ShareDir.Contains('"') -or $ShareDir.Contains("`n") -or $ShareDir.Contains("`r")) {
        throw "ShareDir contains a quote or newline and cannot be rendered safely"
    }
    New-Item -ItemType Directory -Path $ShareDir -Force | Out-Null

    Info "gateway: $gateway"
    Info "CLI: $cli"
    Info "wxc-exec: $wxc"
    Info "share: $ShareDir"
    Info "Ollama: http://${OllamaHost}:$OllamaPort"

    try {
        $probe = Invoke-WebRequest -UseBasicParsing -Uri "http://${OllamaHost}:$OllamaPort/api/tags" -TimeoutSec 8
        if ([int]$probe.StatusCode -ne 200) { throw "HTTP $($probe.StatusCode)" }
    } catch {
        throw "Ollama prerequisite is unavailable at http://${OllamaHost}:$OllamaPort/api/tags. Start Ollama or pass -OllamaHost/-OllamaPort. $($_.Exception.Message)"
    }
    Ok "host-side Ollama prerequisite returned HTTP 200"

    $cmdExe = Join-Path $env:SystemRoot "System32\cmd.exe"
    $curlExe = Join-Path $env:SystemRoot "System32\curl.exe"
    $findStrExe = Join-Path $env:SystemRoot "System32\findstr.exe"
    foreach ($systemTool in @($cmdExe, $curlExe, $findStrExe)) {
        if (-not (Test-Path -LiteralPath $systemTool -PathType Leaf)) {
            throw "required Windows tool was not found at '$systemTool'"
        }
    }

    $tomlUsed = Join-Path $resultDir "mxc-ollama.used.toml"
    $tomlText = [System.IO.File]::ReadAllText((Join-Path $here "mxc-ollama.toml"))
    $escapedWxc = $wxc.Replace('\', '\\').Replace('"', '\"')
    $tomlText = $tomlText.Replace('wxc_exec_path = "wxc-exec.exe"', "wxc_exec_path = `"$escapedWxc`"")
    Write-Utf8 $tomlUsed $tomlText

    $policyUsed = Join-Path $resultDir "ollama.used.yaml"
    $sharePolicy = $ShareDir.Replace('\', '/')
    $policyText = [System.IO.File]::ReadAllText((Join-Path $here "ollama.yaml"))
    $policyText = $policyText.Replace("__OPENSHELL_DEMO_SHARE__", $sharePolicy)
    $policyText = $policyText.Replace("__OLLAMA_HOST__", $OllamaHost)
    $policyText = $policyText.Replace("__OLLAMA_PORT__", [string]$OllamaPort)
    $policyText = $policyText.Replace("__CMD_EXE__", $cmdExe)
    Write-Utf8 $policyUsed $policyText

    $requestPath = Join-Path $ShareDir "ollama-request.json"
    $responsePath = Join-Path $ShareDir "ollama-response.json"
    $tagsPath = Join-Path $ShareDir "ollama-tags.json"
    $donePath = Join-Path $ShareDir "ollama-pass.txt"
    $errorPath = Join-Path $ShareDir "ollama-error.txt"
    $requestJson = @{ model = $Model; prompt = $Prompt; stream = $false } | ConvertTo-Json -Compress
    Write-Utf8 $requestPath $requestJson

    $probePath = Join-Path $ShareDir "ollama-probe.cmd"
    $probeLines = @(
        "@echo off",
        # MXC's governed path permits only host loopback at the OS boundary. The
        # CONNECT proxy deliberately blocks loopback as SSRF, so this local-only
        # demo bypasses proxy variables for precisely the requested Ollama host.
        "`"$curlExe`" --noproxy `"$OllamaHost`" --silent --show-error --fail --max-time 15 -o `"$tagsPath`" `"http://${OllamaHost}:$OllamaPort/api/tags`" 2> `"$errorPath`" || exit /b 21",
        "`"$curlExe`" --noproxy `"$OllamaHost`" --silent --show-error --fail --max-time 120 -H `"Content-Type: application/json`" --data-binary `"@$requestPath`" -o `"$responsePath`" `"http://${OllamaHost}:$OllamaPort/api/generate`" 2>> `"$errorPath`" || exit /b 22",
        "`"$findStrExe`" /C:`"response`" `"$responsePath`" >nul || exit /b 23",
        "echo PASS> `"$donePath`""
    )
    Write-Utf8 $probePath ($probeLines -join "`r`n")

    $driverConfig = @{ mxc = @{ command = @($cmdExe, "/d", "/s", "/c", $probePath); cwd = $ShareDir } } | ConvertTo-Json -Compress -Depth 8

    $gwLog = Join-Path $resultDir "gateway.log"
    $gwErrLog = Join-Path $resultDir "gateway.err.log"
    $env:OPENSHELL_GATEWAY_CONFIG = $tomlUsed
    $env:OPENSHELL_COMPUTE_DRIVER = "mxc"
    $gatewayProcess = Start-Process -FilePath $gateway -ArgumentList @("--disable-tls", "--db-url", "sqlite::memory:", "--port", "$Port", "--log-level", "info") -WorkingDirectory $here -PassThru -WindowStyle Hidden -RedirectStandardOutput $gwLog -RedirectStandardError $gwErrLog
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and -not (Test-Port $Port)) {
        if ($gatewayProcess.HasExited) {
            $details = (Get-Content $gwLog, $gwErrLog -ErrorAction SilentlyContinue) -join "`n"
            throw "gateway exited before listening: $details"
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Port $Port)) { throw "gateway did not listen on $endpoint within 30 seconds" }
    Ok "gateway is listening at $endpoint"

    $create = Invoke-Cli @("sandbox", "create", "--name", $SandboxName, "--policy", $policyUsed, "--driver-config-json", $driverConfig, "--no-tty", "--output", "json")
    Ok "sandbox '$SandboxName' created"
    $deadline = (Get-Date).AddSeconds(150)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $donePath)) {
        $status = Invoke-Cli @("sandbox", "get", $SandboxName, "--output", "json") -AllowFailure
        if ($status.ExitCode -eq 0 -and $status.Text -match '"phase"\s*:\s*"Error"') {
            $probeError = if (Test-Path -LiteralPath $errorPath) { ([System.IO.File]::ReadAllText($errorPath)).Trim() } else { "no curl diagnostic was produced" }
            throw "sandbox was created, but local inference failed: $probeError"
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not (Test-Path -LiteralPath $donePath)) { throw "sandbox did not finish local inference within 150 seconds" }
    $response = [System.IO.File]::ReadAllText($responsePath)
    $parsed = $response | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$parsed.response)) { throw "Ollama response did not contain a nonempty 'response' field" }
    Copy-Item -LiteralPath $requestPath, $responsePath, $tagsPath, $probePath -Destination $resultDir -Force
    $success = $true
    Ok "local inference returned a completion from inside the sandbox"
} catch {
    $failure = $_.Exception.Message
    Bad $failure
} finally {
    if ($cli -and $endpoint -and $SandboxName) {
        try { [void](Invoke-Cli @("sandbox", "delete", $SandboxName) -AllowFailure) } catch {}
    }
    if ($gatewayProcess -and -not $gatewayProcess.HasExited) {
        Stop-Process -Id $gatewayProcess.Id -Force -ErrorAction SilentlyContinue
        try { [void]$gatewayProcess.WaitForExit(5000) } catch {}
    }
    $env:OPENSHELL_GATEWAY_CONFIG = $oldGatewayConfig
    $env:OPENSHELL_COMPUTE_DRIVER = $oldComputeDriver
    if (-not $KeepArtifacts -and $createdShare -and $ShareDir -and (Test-Path -LiteralPath $ShareDir)) {
        Remove-Item -LiteralPath $ShareDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$verdict = if ($success) { "PASS" } else { "FAIL" }
$summary = "verdict=$verdict`r`nbase=local-ollama`r`nsandbox=$SandboxName`r`ngateway=$endpoint`r`nbackend=process_container`r`nresult=$failure`r`n"
Write-Utf8 (Join-Path $resultDir "summary.txt") $summary
Write-Host "`n$summary"
Write-Host "Results: $resultDir"
if ($success) { exit 0 } else { exit 1 }
