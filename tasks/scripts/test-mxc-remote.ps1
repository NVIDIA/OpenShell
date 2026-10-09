# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build locally, upload content-addressed artifacts, run unchanged real E2E,
# and download diagnostic bundles even when tests return a nonzero exit code.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $HostName,
    [Parameter(Mandatory = $true)] [string] $UserName,
    [string] $IdentityFile = (Join-Path $env:USERPROFILE '.ssh/openshell-mxc-test'),
    [ValidateSet('auto', 'arm64', 'x64')] [string] $Architecture = 'auto',
    [string] $BuildDirectory,
    [string] $Z3DllPath,
    [string] $RemoteRoot,
    [string] $WxcExecPath,
    [string] $Scenario,
    [ValidateRange(1, 65535)] [int] $SshPort = 22,
    [ValidateRange(1, 65535)] [int] $GatewayPort = 17670,
    [switch] $SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if ($HostName -notmatch '^[A-Za-z0-9.-]+$' -or $UserName -notmatch '^[A-Za-z0-9_.-]+$') {
    throw 'Use a hostname/IP and a simple SSH username (or configure an SSH alias).'
}
if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) { throw "Missing SSH key: $IdentityFile" }
$ssh = (Get-Command ssh.exe -ErrorAction Stop).Source
$scp = (Get-Command scp.exe -ErrorAction Stop).Source
$peer = "$UserName@$HostName"
$sshOptions = @('-i', $IdentityFile, '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
    '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15',
    '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', '-p', "$SshPort")
$scpOptions = @('-i', $IdentityFile, '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
    '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15', '-P', "$SshPort")
function Quote-PS([string] $Value) { return "'" + $Value.Replace("'", "''") + "'" }
function Find-Z3Runtime([string] $BuildRoot, [string] $RustTarget, [string] $ExplicitPath) {
    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) { throw "Missing Z3 runtime: $ExplicitPath" }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }
    $release = Join-Path $BuildRoot "$RustTarget/release"
    $adjacent = Join-Path $release 'libz3.dll'
    if (Test-Path -LiteralPath $adjacent -PathType Leaf) { return $adjacent }
    # Windows prebuilt-z3 links an import library rather than a static library.
    $candidates = @(Get-ChildItem -Path (Join-Path $release 'build/z3-sys-*/out/z3-*/bin/libz3.dll') -File -ErrorAction SilentlyContinue)
    if ($candidates.Count -eq 0) { throw 'libz3.dll not found in the target build cache. Supply -Z3DllPath matching the linked Z3 build.' }
    $hashes = @($candidates | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName).Hash } | Select-Object -Unique)
    if ($hashes.Count -ne 1) { throw 'Multiple different Z3 runtimes found. Supply -Z3DllPath matching the linked Z3 build.' }
    return $candidates[0].FullName
}
function Read-CacheHashes([string] $Json) {
    # Windows PowerShell 5.1 emits decoded JSON arrays as one pipeline object.
    # Explicitly enumerate so callers do not get a nested array with -contains.
    $decoded = $Json | ConvertFrom-Json
    foreach ($hash in $decoded) {
        if ($hash -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid hash in remote cache response.' }
        Write-Output $hash
    }
}
function Remote-Command([string] $Code) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(
        '$ProgressPreference="SilentlyContinue"; $ErrorActionPreference="Stop"; ' + $Code))
    & $ssh @sshOptions $peer "powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded"
}

# Registry architecture is native even if the SSH shell runs under emulation.
$hostJson = @(Remote-Command @'
[pscustomobject]@{
    name = $env:COMPUTERNAME
    architecture = (Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' PROCESSOR_ARCHITECTURE)
    profile = $env:USERPROFILE
    os = [Environment]::OSVersion.Version.ToString()
} | ConvertTo-Json -Compress
'@)
if ($LASTEXITCODE -ne 0) { throw 'Remote host inspection failed.' }
$hostInfo = ($hostJson -join "`n") | ConvertFrom-Json
$native = switch ($hostInfo.architecture) { 'ARM64' { 'arm64' } 'AMD64' { 'x64' } default { throw 'Unsupported remote architecture.' } }
if ($Architecture -eq 'auto') { $Architecture = $native }
if ($Architecture -ne $native) { throw "Requested $Architecture does not match native remote $native." }
$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $repo 'target/remote-mxc-build' }
$BuildDirectory = [IO.Path]::GetFullPath($BuildDirectory)
if (-not $RemoteRoot) { $RemoteRoot = Join-Path $hostInfo.profile 'openshell-mxc-tests' }
if ($RemoteRoot -notmatch '^[A-Za-z]:[\\/]' -or $RemoteRoot -match '[\r\n]') { throw 'RemoteRoot must be an absolute Windows directory.' }
$RemoteRoot = $RemoteRoot.Replace('/', '\').TrimEnd('\')
$commit = (& git -C $repo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot determine checkout commit.' }
$dirty = @(& git -C $repo status --porcelain)
$runId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $commit.Substring(0, 12) + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6)
$localRun = Join-Path $repo "target/windows-remote-results/$runId"
New-Item -ItemType Directory -Force -Path $localRun | Out-Null
$transcript = $false
$exitCode = 1
try {
    Start-Transcript -Path (Join-Path $localRun 'local-transcript.txt') | Out-Null
    $transcript = $true
    Write-Host "Host: $($hostInfo.name), $native, Windows $($hostInfo.os); checkout: $commit"
    if (-not $SkipBuild) {
        $previousTarget = $env:CARGO_TARGET_DIR
        Push-Location $repo
        try {
            $env:CARGO_TARGET_DIR = $BuildDirectory
            & mise run --skip-tools "windows:build:$Architecture"
            if ($LASTEXITCODE -ne 0) { throw 'Local Windows build failed; no tests launched.' }
            & mise run --skip-tools "windows:build:mxc-fixtures:$Architecture"
            if ($LASTEXITCODE -ne 0) { throw 'MXC E2E fixture build failed; no tests launched.' }
        } finally {
            $env:CARGO_TARGET_DIR = $previousTarget
            Pop-Location
            foreach ($logName in @("build-$target-release.log", "build-$target-mxc-fixtures.log")) {
                $buildLog = Join-Path $repo $logName
                if (Test-Path $buildLog) { Copy-Item -LiteralPath $buildLog -Destination $localRun }
            }
        }
    } else { Write-Warning 'SkipBuild: using existing binaries, not claiming they were rebuilt from this checkout.' }

    $files = @()
    foreach ($name in @('openshell.exe', 'openshell-gateway.exe', 'openshell-supervisor.exe', 'openshell-windows-sandbox.exe')) {
        $files += @{ source = (Join-Path $BuildDirectory "$target/release/$name"); path = "bin/$name" }
    }
    $examples = 'crates/openshell-driver-mxc/examples'
    $files += @{ source = (Join-Path $BuildDirectory "$target/release/examples/mxc-forwarding-agent.exe"); path = 'bin/mxc-forwarding-agent.exe' }
    $files += @{ source = (Find-Z3Runtime $BuildDirectory $target $Z3DllPath); path = 'bin/libz3.dll' }
    foreach ($path in @("$examples/run-mxc-e2e.ps1", "$examples/mxc-gateway.toml", 'tasks/scripts/run-mxc-remote.ps1')) {
        $files += @{ source = (Join-Path $repo $path); path = $path }
    }
    foreach ($policy in Get-ChildItem (Join-Path $repo "$examples/e2e-policies") -File) {
        $files += @{ source = $policy.FullName; path = "$examples/e2e-policies/$($policy.Name)" }
    }
    $entries = @($files | ForEach-Object {
        if (-not (Test-Path -LiteralPath $_.source -PathType Leaf)) { throw "Missing artifact: $($_.source)" }
        [pscustomobject]@{ source = $_.source; path = $_.path; sha256 = (Get-FileHash -LiteralPath $_.source -Algorithm SHA256).Hash.ToLowerInvariant(); bytes = (Get-Item -LiteralPath $_.source).Length }
    })
    $manifest = [ordered]@{ runId = $runId; commit = $commit; dirty = $dirty; buildSkipped = [bool]$SkipBuild;
        target = $target; hostInfo = $hostInfo; wxcExecPath = $WxcExecPath; scenario = $Scenario; gatewayPort = $GatewayPort;
        files = @($entries | Select-Object path, sha256, bytes) }
    $manifestPath = Join-Path $localRun 'manifest.json'
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $remoteRun = "$RemoteRoot\runs\$runId"
    $cache = "$RemoteRoot\cache"
    Remote-Command "New-Item -ItemType Directory -Force -Path $(Quote-PS $remoteRun),$(Quote-PS $cache) | Out-Null"
    if ($LASTEXITCODE -ne 0) { throw 'Could not create remote test directories.' }
    & $scp @scpOptions $manifestPath "${peer}:$($remoteRun.Replace('\', '/'))/manifest.json"
    if ($LASTEXITCODE -ne 0) { throw 'Manifest transfer failed.' }
    $missingJson = @(Remote-Command @"
`$m = Get-Content -Raw $(Quote-PS "$remoteRun\manifest.json") | ConvertFrom-Json
`$missing = @(`$m.files | Where-Object { `$p = Join-Path $(Quote-PS $cache) `$_.sha256; !(Test-Path -LiteralPath `$p) -or (Get-FileHash -LiteralPath `$p).Hash -ne `$_.sha256 } | ForEach-Object { `$_.sha256 })
ConvertTo-Json -InputObject `$missing -Compress
"@)
    if ($LASTEXITCODE -ne 0) { throw 'Remote artifact cache inspection failed.' }
    $missing = @(Read-CacheHashes ($missingJson -join "`n"))
    foreach ($entry in $entries) {
        if ($missing -contains $entry.sha256) {
            Write-Host "Uploading $($entry.path) ($($entry.bytes) bytes)"
            & $scp @scpOptions $entry.source "${peer}:$($cache.Replace('\', '/'))/$($entry.sha256)"
            if ($LASTEXITCODE -ne 0) { throw "Transfer failed: $($entry.path)" }
        } else { Write-Host "Cached: $($entry.path)" }
    }
    Remote-Command @"
`$m = Get-Content -Raw $(Quote-PS "$remoteRun\manifest.json") | ConvertFrom-Json
foreach (`$f in `$m.files) {
    `$src = Join-Path $(Quote-PS $cache) `$f.sha256
    if ((Get-FileHash -LiteralPath `$src).Hash -ne `$f.sha256) { throw 'Remote artifact hash mismatch' }
    `$dst = Join-Path $(Quote-PS $remoteRun) `$f.path
    New-Item -ItemType Directory -Force -Path (Split-Path `$dst) | Out-Null
    Copy-Item -LiteralPath `$src -Destination `$dst
}
"@
    if ($LASTEXITCODE -ne 0) { throw 'Remote payload verification failed.' }
    $command = "& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $(Quote-PS "$remoteRun\tasks\scripts\run-mxc-remote.ps1"); exit `$LASTEXITCODE"
    Remote-Command $command | Tee-Object -FilePath (Join-Path $localRun 'ssh-console.log')
    $exitCode = $LASTEXITCODE
    # Download independently of test status. Never include the harness key directory.
    & $scp @scpOptions "${peer}:$($remoteRun.Replace('\', '/'))/results.zip" (Join-Path $localRun 'results.zip')
    if ($LASTEXITCODE -ne 0) { throw "Results download failed (remote test exit $exitCode). Artifacts remain in $remoteRun" }
    Expand-Archive -LiteralPath (Join-Path $localRun 'results.zip') -DestinationPath (Join-Path $localRun 'results')
    Write-Host "Remote test exit: $exitCode; results: $localRun"
} catch {
    Write-Warning $_.Exception.Message
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $localRun 'error.txt')
    $exitCode = 1
} finally {
    if ($transcript) { Stop-Transcript | Out-Null }
    Write-Host "Local logs: $localRun"
}
exit $exitCode
