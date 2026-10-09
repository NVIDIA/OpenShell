# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Remote half of test-mxc-remote.ps1. No source checkout or build tools required.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PSNativeCommandUseErrorActionPreference = $false
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$export = Join-Path $repo 'result-export'
New-Item -ItemType Directory -Path $export | Out-Null
$manifest = Get-Content -Raw (Join-Path $repo 'manifest.json') | ConvertFrom-Json
Copy-Item -LiteralPath (Join-Path $repo 'manifest.json') -Destination $export
$code = 1
$transcript = $false
function Get-PeMachine([string] $Path) {
    $stream = [IO.File]::OpenRead($Path)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw "Not a PE executable: $Path" }
        $stream.Position = 0x3c
        $offset = $reader.ReadInt32()
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550) { throw "Invalid PE signature: $Path" }
        return $reader.ReadUInt16()
    } finally { $reader.Dispose() }
}
try {
    Start-Transcript -Path (Join-Path $export 'remote-transcript.txt') | Out-Null
    $transcript = $true
    $native = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' PROCESSOR_ARCHITECTURE
    $expected = if ($manifest.target -eq 'aarch64-pc-windows-msvc') { 0xaa64 } else { 0x8664 }
    if (($expected -eq 0xaa64 -and $native -ne 'ARM64') -or ($expected -eq 0x8664 -and $native -ne 'AMD64')) { throw 'Native host architecture changed.' }
    foreach ($name in @('openshell.exe', 'openshell-gateway.exe', 'openshell-supervisor.exe', 'openshell-windows-sandbox.exe', 'mxc-forwarding-agent.exe', 'libz3.dll')) {
        if ((Get-PeMachine (Join-Path $repo "bin/$name")) -ne $expected) { throw "Wrong executable architecture: $name" }
    }
    $wxc = $manifest.wxcExecPath
    # Check loader dependencies before the harness starts a gateway.
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = Join-Path $repo 'bin/openshell-gateway.exe'
    $startInfo.Arguments = '--version'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) { $process.Kill(); throw 'Gateway loader check timed out.' }
        @($stdout.Result, $stderr.Result) | Set-Content (Join-Path $export 'gateway-version.txt') -Encoding UTF8
        if ($process.ExitCode -ne 0) { throw "Gateway loader check failed: exit $($process.ExitCode). Check the packaged DLLs and native Visual C++ runtime." }
        Write-Host "Gateway loader check passed: $($stdout.Result.Trim())"
    } finally { $process.Dispose() }
    if (-not $wxc) { $wxc = (Get-Command wxc-exec.exe -ErrorAction Stop).Source }
    $openssl = (Get-Command openssl.exe -ErrorAction Stop).Source
    $probe = @(& $wxc --probe)
    $probeCode = $LASTEXITCODE
    $probe | Set-Content -LiteralPath (Join-Path $export 'wxc-probe.json') -Encoding UTF8
    [ordered]@{ hostName = $env:COMPUTERNAME; nativeArchitecture = $native; shellArchitecture = $env:PROCESSOR_ARCHITECTURE;
        windowsVersion = [Environment]::OSVersion.Version.ToString(); wxcExecPath = $wxc;
        wxcVersion = (Get-Item -LiteralPath $wxc).VersionInfo.ProductVersion;
        wxcSha256 = (Get-FileHash -LiteralPath $wxc).Hash; wxcPeMachine = (Get-PeMachine $wxc);
        probeExitCode = $probeCode; openssl = $openssl } | ConvertTo-Json | Set-Content (Join-Path $export 'host.json') -Encoding UTF8
    if ($probeCode -ne 0) { throw "MXC probe failed: exit $probeCode" }
    Write-Host "Native host: $native; MXC: $wxc; running unchanged REAL E2E"
    $harness = Join-Path $repo 'crates/openshell-driver-mxc/examples/run-mxc-e2e.ps1'
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $harness,
        '-BinaryDir', (Join-Path $repo 'bin'), '-WxcExecPath', $wxc, '-Backend', 'process_container', '-Port', "$($manifest.gatewayPort)")
    if ($manifest.scenario) { $arguments += @('-Scenario', $manifest.scenario) }
    & powershell.exe @arguments
    $code = $LASTEXITCODE
} catch {
    Write-Warning $_.Exception.Message
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $export 'error.txt')
} finally {
    Set-Content -LiteralPath (Join-Path $export 'exit-code.txt') -Value $code
    $resultsRoot = Join-Path $repo 'target/windows-e2e-results'
    if (Test-Path $resultsRoot) {
        # Only copy completed harness bundles and summaries, never sibling keys-*.
        Get-ChildItem $resultsRoot -Filter 'results-e2e-*.zip' -File | Copy-Item -Destination $export
        foreach ($dir in Get-ChildItem $resultsRoot -Filter 'results-e2e-*' -Directory) {
            $summary = Join-Path $dir.FullName 'summary.txt'
            if (Test-Path $summary) { Copy-Item -LiteralPath $summary -Destination (Join-Path $export "$($dir.Name)-summary.txt") }
        }
    }
    if ($transcript) { Stop-Transcript | Out-Null }
    Compress-Archive -Path (Join-Path $export '*') -DestinationPath (Join-Path $repo 'results.zip')
}
exit $code
