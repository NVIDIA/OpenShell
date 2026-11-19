# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Pure helper regressions. This does not replace real remote E2E coverage.
$ErrorActionPreference = 'Stop'
$count = 0
foreach ($name in @('test-mxc-remote.ps1', 'run-mxc-remote.ps1')) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
    # Load pure functions only; do not start builds or SSH sessions.
    foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        if ($function.Name -in @('Quote-PS', 'Find-Z3Runtime', 'Read-CacheHashes', 'Get-PeMachine')) { Invoke-Expression $function.Extent.Text }
    }
    $count++
}
if ((Quote-PS "C:\Users\O'Brien\file") -ne "'C:\Users\O''Brien\file'") { throw 'PowerShell literal quoting regression.' }
$count++
$hashA = 'a' * 64
$hashB = 'b' * 64
$hashes = @(Read-CacheHashes ('["' + $hashA + '","' + $hashB + '"]'))
if ($hashes.Count -ne 2 -or $hashes -notcontains $hashA -or $hashes -notcontains $hashB) { throw 'JSON cache array enumeration regression.' }
$count++
if (@(Read-CacheHashes '[]').Count -ne 0) { throw 'Empty cache response regression.' }
$count++
if (@(Read-CacheHashes ('["' + $hashA + '"]')).Count -ne 1) { throw 'Single cache hash regression.' }
$count++
function Pe-Bytes([int] $Machine) {
    $bytes = New-Object byte[] 128
    $bytes[0] = 0x4d; $bytes[1] = 0x5a; $bytes[0x3c] = 0x40
    $bytes[0x40] = 0x50; $bytes[0x41] = 0x45
    $bytes[0x44] = $Machine -band 255; $bytes[0x45] = ($Machine -shr 8) -band 255
    return ,$bytes
}
$fixture = [IO.Path]::GetTempFileName()
try {
    if ((Find-Z3Runtime '' '' $fixture) -ne $fixture) { throw 'Explicit Z3 DLL path regression.' }
    $count++
    $rejected = $false
    try { Find-Z3Runtime ([IO.Path]::GetTempPath()) ('missing-' + [guid]::NewGuid().ToString('N')) '' | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Missing Z3 DLL accepted.' }
    $count++
    foreach ($machine in @(0xaa64, 0x8664)) {
        [IO.File]::WriteAllBytes($fixture, (Pe-Bytes $machine))
        if ((Get-PeMachine $fixture) -ne $machine) { throw 'PE architecture regression.' }
        $count++
    }
    [IO.File]::WriteAllBytes($fixture, [byte[]]@(1, 2, 3, 4))
    $rejected = $false
    try { Get-PeMachine $fixture | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid executable accepted.' }
    $count++
    # Reader cleanup must permit rewriting/deleting even after rejection.
} finally { Remove-Item -LiteralPath $fixture }
$cacheFixture = Join-Path ([IO.Path]::GetTempPath()) ('openshell-z3-test-' + [guid]::NewGuid().ToString('N'))
$target = 'aarch64-pc-windows-msvc'
$first = Join-Path $cacheFixture "$target/release/build/z3-sys-first/out/z3-5.1.0/bin/libz3.dll"
$second = Join-Path $cacheFixture "$target/release/build/z3-sys-second/out/z3-5.1.0/bin/libz3.dll"
try {
    New-Item -ItemType Directory -Path (Split-Path $first), (Split-Path $second) -Force | Out-Null
    [IO.File]::WriteAllBytes($first, (Pe-Bytes 0xaa64))
    if ((Find-Z3Runtime $cacheFixture $target '') -ne $first) { throw 'Target-specific Z3 discovery regression.' }
    $count++
    Copy-Item -LiteralPath $first -Destination $second
    if (-not (Find-Z3Runtime $cacheFixture $target '')) { throw 'Identical cached Z3 runtimes rejected.' }
    $count++
    [IO.File]::WriteAllBytes($second, (Pe-Bytes 0x8664))
    $rejected = $false
    try { Find-Z3Runtime $cacheFixture $target '' | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Ambiguous Z3 runtimes accepted.' }
    $count++
} finally {
    # Only tear down the explicitly created fixture paths, not a recursive root.
    foreach ($path in @($first, $second)) { if (Test-Path $path) { Remove-Item -LiteralPath $path } }
    Get-ChildItem -LiteralPath $cacheFixture -Directory -Recurse | Sort-Object { $_.FullName.Length } -Descending | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
    Remove-Item -LiteralPath $cacheFixture
}
# Graceful-stop decision used by the gateway-restart E2E scenario (pure function).
$e2eRunner = Join-Path $PSScriptRoot '../../crates/openshell-driver-mxc/examples/run-mxc-e2e.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($e2eRunner, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if ($function.Name -eq 'Get-GracefulStopFailure') { Invoke-Expression $function.Extent.Text }
}
if (-not (Get-Command Get-GracefulStopFailure -ErrorAction SilentlyContinue)) { throw 'Get-GracefulStopFailure not found in the E2E runner.' }
if ($null -ne (Get-GracefulStopFailure 0 $true)) { throw 'Clean graceful stop rejected.' }
$count++
if ((Get-GracefulStopFailure 1 $true) -notmatch 'code 1') { throw 'Nonzero exit after the shutdown message accepted.' }
$count++
if ((Get-GracefulStopFailure -1073741510 $true) -notmatch 'code -1073741510') { throw 'Ctrl-C default-handler exit (0xC000013A) accepted as graceful.' }
$count++
if (-not (Get-GracefulStopFailure 0 $false)) { throw 'Exit 0 without the shutdown message accepted.' }
$count++
if ((Get-GracefulStopFailure $null $true) -notmatch 'unavailable') { throw 'Missing exit code accepted.' }
$count++
if ((Get-GracefulStopFailure 1 $false) -notmatch 'code 1') { throw 'Nonzero exit must be reported before the missing log line.' }
$count++
# The decision only protects the scenario if it is consulted after Ctrl-C, fails the
# scenario, and does so before the replacement gateway is started. Check that order
# in the runner's syntax tree so moving or dropping the call fails here.
function Get-CommandOffsets($Root, [string] $Name) {
    return @($Root.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq $Name }, $true) |
        ForEach-Object { $_.Extent.StartOffset })
}
$ctrlC = @(Get-CommandOffsets $ast 'Send-CtrlC')
$checks = @(Get-CommandOffsets $ast 'Get-GracefulStopFailure')
$starts = @(Get-CommandOffsets $ast 'Start-Gw')
if ($ctrlC.Count -ne 1) { throw 'Expected exactly one Send-CtrlC call in the E2E runner.' }
if ($checks.Count -ne 1) { throw 'Expected exactly one Get-GracefulStopFailure call in the E2E runner.' }
if ($checks[0] -lt $ctrlC[0]) { throw 'The graceful-stop check must come after Ctrl-C is sent.' }
$restart = @($starts | Where-Object { $_ -gt $ctrlC[0] } | Select-Object -First 1)
if ($restart.Count -ne 1) { throw 'No replacement gateway start found after Ctrl-C.' }
if ($checks[0] -gt $restart[0]) { throw 'The graceful-stop check must come before the replacement gateway starts.' }
$throws = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.ThrowStatementAst] -and $node.Extent.Text -match 'stopFailure' }, $true) |
    Where-Object { $_.Extent.StartOffset -gt $checks[0] -and $_.Extent.StartOffset -lt $restart[0] })
if ($throws.Count -ne 1) { throw 'The graceful-stop check result must fail the scenario before the replacement gateway starts.' }
$count++
Write-Host "$count remote-script regression checks passed. No runtime qualification claimed."
