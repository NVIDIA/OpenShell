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
Write-Host "$count remote-script regression checks passed. No runtime qualification claimed."
