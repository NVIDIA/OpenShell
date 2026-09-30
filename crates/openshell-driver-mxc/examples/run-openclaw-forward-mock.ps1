# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Called by run-openclaw-forward-test.ps1 -Mock. Exercise its shipped gateway
# config and policy with a proof command; the wxc shim has no relay channel.
[CmdletBinding()]
param(
    [string] $GatewayPath,
    [string] $CliPath,
    [Parameter(Mandatory = $true)] [string] $ShareDir,
    [int] $Port = 17670,
    [string] $SandboxName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$here = $PSScriptRoot
$gateway = if ($GatewayPath) { [System.IO.Path]::GetFullPath($GatewayPath) } else { Join-Path $here "openshell-gateway.exe" }
$cli = if ($CliPath) { [System.IO.Path]::GetFullPath($CliPath) } else { Join-Path $here "openshell.exe" }
$ShareDir = [System.IO.Path]::GetFullPath($ShareDir)
if ([string]::IsNullOrWhiteSpace($SandboxName)) { $SandboxName = "oc-mock-$PID" }
$resultDir = Join-Path $here "results-openclaw-forward-mock-$PID"
$proof = Join-Path $ShareDir "mock-workload-pass.txt"
$gatewayProcess = $null
$created = $false
$passed = $false
$failure = ""
$oldConfig = $env:OPENSHELL_GATEWAY_CONFIG
$oldComputeDriver = $env:OPENSHELL_COMPUTE_DRIVER
$oldMock = $env:OPENSHELL_MXC_MOCK_WXC

function Quote-NativeArgument([string]$value) {
    if ($value.Length -gt 0 -and $value -notmatch '[\s"]') { return $value }
    $quoted = New-Object System.Text.StringBuilder
    [void]$quoted.Append('"')
    $slashes = 0
    foreach ($ch in $value.ToCharArray()) {
        if ($ch -eq '\') { $slashes++; continue }
        if ($ch -eq '"') {
            [void]$quoted.Append(('\' * (2 * $slashes + 1)))
            [void]$quoted.Append('"')
        } else {
            if ($slashes -gt 0) { [void]$quoted.Append(('\' * $slashes)) }
            [void]$quoted.Append($ch)
        }
        $slashes = 0
    }
    if ($slashes -gt 0) { [void]$quoted.Append(('\' * (2 * $slashes))) }
    [void]$quoted.Append('"')
    return $quoted.ToString()
}

function Invoke-Cli([string[]]$CommandArgs, [switch]$AllowFailure) {
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $cli
    $start.Arguments = ((@("--gateway-endpoint", "http://127.0.0.1:$Port") + $CommandArgs | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    if (-not $process.Start()) { throw "failed to start OpenShell CLI" }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $output = (@($stdout.Result, $stderr.Result) | Where-Object { $_ }) -join [Environment]::NewLine
    if (-not $AllowFailure -and $process.ExitCode -ne 0) {
        throw "openshell $($CommandArgs -join ' ') failed (exit $($process.ExitCode)): $output"
    }
    return @{ ExitCode = $process.ExitCode; Output = $output; Stdout = $stdout.Result }
}

function Test-Port([int]$Candidate) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect("127.0.0.1", $Candidate, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(250)) { return $false }
        $client.EndConnect($pending)
        return $true
    } catch { return $false } finally { $client.Dispose() }
}

try {
    foreach ($file in @($gateway, $cli, (Join-Path $here "mxc-openclaw-gateway.toml"),
            (Join-Path $here "e2e-policies\openclaw-gateway.yaml"))) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "missing mock demo asset: $file" }
    }
    if (Test-Port $Port) { throw "gateway port $Port is already in use" }
    New-Item -ItemType Directory -Force -Path $resultDir, $ShareDir | Out-Null
    Remove-Item -LiteralPath $proof -Force -ErrorAction SilentlyContinue

    $shareFwd = $ShareDir.Replace('\', '/')
    $toml = Get-Content -LiteralPath (Join-Path $here "mxc-openclaw-gateway.toml") -Raw
    $mockWxc = (Join-Path $here "mock-wxc-exec.exe").Replace('\', '\\')
    $toml = [regex]::Replace($toml, '(?m)^wxc_exec_path\s*=.*$', "wxc_exec_path = `"$mockWxc`"")
    $toml = $toml.Replace('C:/openshell-openclaw', $shareFwd)
    $toml = [regex]::Replace($toml, '(?m)^pc_relay_spawner_path\s*=.*$', 'pc_relay_spawner_path = ""')
    $tomlUsed = Join-Path $resultDir "mxc-openclaw-gateway.used.toml"
    [System.IO.File]::WriteAllText($tomlUsed, $toml, [System.Text.UTF8Encoding]::new($false))

    $policy = Get-Content -LiteralPath (Join-Path $here "e2e-policies\openclaw-gateway.yaml") -Raw
    $policy = $policy.Replace('C:/openshell-openclaw', $shareFwd)
    $policyUsed = Join-Path $resultDir "openclaw-gateway.used.yaml"
    [System.IO.File]::WriteAllText($policyUsed, $policy, [System.Text.UTF8Encoding]::new($false))

    $env:OPENSHELL_GATEWAY_CONFIG = $tomlUsed
    $env:OPENSHELL_COMPUTE_DRIVER = "mxc"
    $env:OPENSHELL_MXC_MOCK_WXC = "1"
    $gwLog = Join-Path $resultDir "gateway.log"
    $gwErrLog = Join-Path $resultDir "gateway.err.log"
    $gatewayProcess = Start-Process -FilePath $gateway -ArgumentList @(
        "--disable-tls", "--db-url", "sqlite::memory:", "--port", "$Port", "--log-level", "info"
    ) -WorkingDirectory $here -PassThru -WindowStyle Hidden -RedirectStandardOutput $gwLog -RedirectStandardError $gwErrLog
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and -not (Test-Port $Port)) {
        if ($gatewayProcess.HasExited) { throw "gateway exited before listening" }
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Port $Port)) { throw "gateway did not listen within 30 seconds" }

    $cmd = Join-Path $env:SystemRoot "System32\cmd.exe"
    $driverConfig = @{ mxc = @{
        command = @($cmd, "/d", "/s", "/c", "echo PASS 1> `"$proof`"")
        cwd = $shareFwd
    } } | ConvertTo-Json -Compress -Depth 5
    $created = $true
    $create = Invoke-Cli @("sandbox", "create", "--name", $SandboxName,
        "--policy", $policyUsed, "--driver-config-json", $driverConfig,
        "--no-tty", "--output", "json")
    $deadline = (Get-Date).AddSeconds(30)
    $proofText = ""
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $proof) {
            $proofText = Get-Content -LiteralPath $proof -Raw
            if ($null -ne $proofText -and $proofText.Trim() -eq "PASS") { break }
        }
        Start-Sleep -Milliseconds 250
    }
    if ($null -eq $proofText -or $proofText.Trim() -ne "PASS") {
        throw "mock workload did not finish proof (create exit $($create.ExitCode)): $($create.Output)"
    }
    $get = Invoke-Cli @("sandbox", "get", $SandboxName, "--output", "json")
    $sandbox = ConvertFrom-Json -InputObject $get.Stdout -ErrorAction Stop
    if ($sandbox.name -cne $SandboxName) {
        throw "sandbox get returned '$($sandbox.name)' instead of '$SandboxName'"
    }
    if ($sandbox.phase -cne "Ready") {
        throw "sandbox '$SandboxName' is not Ready (phase: $($sandbox.phase))"
    }
    $delete = Invoke-Cli @("sandbox", "delete", $SandboxName)
    $created = $false
    if ($delete.ExitCode -ne 0) { throw "sandbox deletion failed" }
    $passed = $true
    Write-Host "OpenClaw example mock wiring passed for $SandboxName"
} catch {
    $failure = $_.Exception.Message
    Write-Host "OpenClaw example mock wiring failed: $failure ($($_.ScriptStackTrace))" -ForegroundColor Red
} finally {
    if ($created) {
        try { [void](Invoke-Cli @("sandbox", "delete", $SandboxName) -AllowFailure) } catch {}
    }
    if ($gatewayProcess -and -not $gatewayProcess.HasExited) {
        Stop-Process -Id $gatewayProcess.Id -Force -ErrorAction SilentlyContinue
        try { [void]$gatewayProcess.WaitForExit(5000) } catch {}
    }
    $env:OPENSHELL_GATEWAY_CONFIG = $oldConfig
    $env:OPENSHELL_COMPUTE_DRIVER = $oldComputeDriver
    if ($null -eq $oldMock) {
        Remove-Item Env:OPENSHELL_MXC_MOCK_WXC -ErrorAction SilentlyContinue
    } else {
        $env:OPENSHELL_MXC_MOCK_WXC = $oldMock
    }
    $verdict = if ($passed) { "PASS" } else { "FAIL" }
    $summary = "verdict=$verdict`r`nmode=mock-wiring`r`nsandbox=$SandboxName`r`nresult=$failure`r`n" +
        "Mock mode validates the shipped config, policy, gateway, CLI, driver, and proof command. " +
        "It does not validate OpenClaw, WebSocket forwarding, proxy behavior, or MXC enforcement.`r`n"
    [System.IO.File]::WriteAllText((Join-Path $resultDir "summary.txt"), $summary, [System.Text.UTF8Encoding]::new($false))
    Write-Host $summary
    Write-Host "Results: $resultDir"
}

if ($passed) { exit 0 } else { exit 1 }
