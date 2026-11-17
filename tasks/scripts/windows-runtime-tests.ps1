# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows-runtime.ps1')

function New-Image([int] $Machine, [string] $Dependency, [switch] $Delay) {
    $bytes = New-Object byte[] 1024
    function Set-U16([int] $Offset, [uint16] $Value) { [BitConverter]::GetBytes($Value).CopyTo($bytes, $Offset) }
    function Set-U32([int] $Offset, [uint32] $Value) { [BitConverter]::GetBytes($Value).CopyTo($bytes, $Offset) }
    Set-U16 0 0x5a4d
    Set-U32 60 64
    Set-U32 64 0x4550
    Set-U16 68 $Machine
    Set-U16 70 1
    Set-U16 84 240
    Set-U16 88 0x20b
    Set-U32 196 16
    # One section maps RVAs 0x1000..0x11ff to file offsets 512..1023.
    Set-U32 336 512
    Set-U32 340 0x1000
    Set-U32 344 512
    Set-U32 348 512
    if ($Dependency) {
        if ($Delay) {
            Set-U32 304 0x1000
            Set-U32 308 64
            Set-U32 512 1
            Set-U32 516 0x1080
        } else {
            Set-U32 208 0x1000
            Set-U32 212 40
            Set-U32 524 0x1080
        }
        [Text.Encoding]::ASCII.GetBytes($Dependency).CopyTo($bytes, 640)
    }
    return ,$bytes
}

$fixture = [IO.Path]::GetTempFileName()
$count = 0
try {
    foreach ($entry in @(@(0xaa64, 'aarch64-pc-windows-msvc'), @(0x8664, 'x86_64-pc-windows-msvc'))) {
        [IO.File]::WriteAllBytes($fixture, (New-Image $entry[0] 'KERNEL32.dll'))
        Assert-StaticWindowsRuntime $fixture $entry[1]
        $count++
    }
    foreach ($dependency in @('libz3.dll', 'VCRUNTIME140.dll', 'VCRUNTIME140_1.dll', 'MSVCP140.dll', 'MSVCP140_ATOMIC_WAIT.dll', 'ucrtbase.dll', 'api-ms-win-crt-heap-l1-1-0.dll')) {
        foreach ($delay in @($false, $true)) {
            [IO.File]::WriteAllBytes($fixture, (New-Image 0xaa64 $dependency -Delay:$delay))
            $image = Get-WindowsImageDependencies $fixture
            if ($image.Dependencies -notcontains $dependency) { throw "Import not detected: $dependency" }
            $rejected = $false
            try { Assert-StaticWindowsRuntime $fixture 'aarch64-pc-windows-msvc' } catch {
                if ($_.Exception.Message -notmatch 'Dynamic Z3/CRT') { throw }
                $rejected = $true
            }
            if (-not $rejected) { throw "Dynamic dependency accepted: $dependency" }
            $count++
        }
    }
    [IO.File]::WriteAllBytes($fixture, (New-Image 0x8664 ''))
    $rejected = $false
    try { Assert-StaticWindowsRuntime $fixture 'aarch64-pc-windows-msvc' } catch { $rejected = $true }
    if (-not $rejected) { throw 'Wrong PE architecture accepted.' }
    $count++
    [IO.File]::WriteAllBytes($fixture, [byte[]]@(1, 2, 3, 4))
    $rejected = $false
    try { Get-WindowsImageDependencies $fixture | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Truncated PE image accepted.' }
    $count++
} finally { Remove-Item -LiteralPath $fixture }
Write-Host "$count static-runtime regression checks passed. No MXC qualification claimed."
