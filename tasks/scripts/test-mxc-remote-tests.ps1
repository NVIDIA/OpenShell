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
    if ($name -eq 'test-mxc-remote.ps1') {
        # Bind the real parameter block without running builds, SSH, or key checks.
        $binding = [scriptblock]::Create($ast.ParamBlock.Extent.Text + '; $PSBoundParameters.Z3DllPath')
        if ((& $binding -HostName localhost -UserName test -Z3DllPath 'legacy/libz3.dll') -ne 'legacy/libz3.dll') {
            throw 'Legacy -Z3DllPath argument no longer binds.'
        }
        $count++
    }
    # Load pure functions only; do not start builds or SSH sessions.
    foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        if ($function.Name -in @('Quote-PS', 'Read-CacheHashes', 'Get-PeMachine')) { Invoke-Expression $function.Extent.Text }
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
Write-Host "$count remote-script regression checks passed. No runtime qualification claimed."
