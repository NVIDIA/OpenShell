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

# Exercise cold source preparation without network access, including the legacy
# shared-Z3 environment used by the ARM64 CI host.
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'windows-msvc.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in @('Get-Sha256', 'Resolve-Z3Source', 'Configure-Z3', 'Reset-WindowsCMakeGeneratorCache')) {
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if ($null -eq $function) { throw "Missing build helper: $name" }
    Invoke-Expression $function.Extent.Text
}
$sourceFixture = Join-Path ([IO.Path]::GetTempPath()) ('openshell-source-test-' + [guid]::NewGuid().ToString('N'))
try {
    $scripts = Join-Path $sourceFixture 'input/z3-z3-5.1.0/scripts'
    New-Item -ItemType Directory -Path $scripts -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $scripts 'VERSION.txt') -Value '5.1.0.0' -Encoding ASCII
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $sourceArchive = Join-Path $sourceFixture 'source.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory((Join-Path $sourceFixture 'input'), $sourceArchive)
    function Invoke-WebRequest([switch] $UseBasicParsing, [string] $Uri, [string] $OutFile) {
        Copy-Item -LiteralPath $sourceArchive -Destination $OutFile
    }
    $Z3Version = '5.1.0'
    $Z3SourceSha256 = Get-Sha256 $sourceArchive
    $Z3WorkspaceFeatures = '--features openshell-prover/vendored-z3'
    $Z3ServerFeatures = '--features openshell-server/vendored-z3,openshell-prover/vendored-z3'
    $WindowsBuildJobs = 2
    $RepoRoot = $sourceFixture
    $TargetDir = Join-Path $sourceFixture 'target'
    $oldBuild = Join-Path $TargetDir 'aarch64-pc-windows-msvc/release/build/z3-sys-old/out/build'
    $newBuild = Join-Path $TargetDir 'aarch64-pc-windows-msvc/debug/build/z3-sys-new/out/build'
    $otherTarget = Join-Path $TargetDir 'x86_64-pc-windows-msvc/release/build/z3-sys-old/out/build'
    foreach ($build in @($oldBuild, $newBuild, $otherTarget)) {
        New-Item -ItemType Directory -Path $build -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $build 'CMakeCache.txt') -Value 'CMAKE_GENERATOR:INTERNAL=Visual Studio 17 2022'
    }
    Set-Content -LiteralPath (Join-Path $newBuild 'CMakeCache.txt') -Value 'CMAKE_GENERATOR:INTERNAL=Ninja'
    $installed = Join-Path (Split-Path $oldBuild) 'libz3.lib'
    Set-Content -LiteralPath $installed -Value 'installed library'
    Reset-WindowsCMakeGeneratorCache 'aarch64-pc-windows-msvc'
    if (Test-Path -LiteralPath $oldBuild) { throw 'Stale Visual Studio build files retained.' }
    if (-not (Test-Path -LiteralPath $newBuild) -or -not (Test-Path -LiteralPath $otherTarget) -or -not (Test-Path -LiteralPath $installed)) { throw 'Unrelated build files removed.' }
    $count++
    $env:Z3_SRC_SOURCE_DIR = $null
    $env:Z3_LIBRARY_PATH_OVERRIDE = $sourceFixture
    Set-Content -LiteralPath (Join-Path $sourceFixture 'libz3.dll') -Value 'legacy shared runtime'
    $features = Configure-Z3
    if ($features.WorkspaceFeatures -notmatch 'vendored-z3' -or $env:Z3_LIBRARY_PATH_OVERRIDE) { throw 'Legacy shared override selected instead of static Z3.' }
    $count++
    if ($env:Z3_SRC_SOURCE_DIR.StartsWith($TargetDir, [StringComparison]::OrdinalIgnoreCase)) { throw 'Source cache is inside the pruned Cargo target directory.' }
    $count++
    if (-not (Test-Path -LiteralPath (Join-Path $env:Z3_SRC_SOURCE_DIR 'scripts/VERSION.txt'))) { throw 'Cold source extraction failed.' }
    $count++
    $env:Z3_SRC_SOURCE_DIR = $null
    $Z3SourceSha256 = '0' * 64
    # A verified cache can be reused without downloading another archive.
    if (-not (Resolve-Z3Source)) { throw 'Source cache reuse failed.' }
    $count++
    $RepoRoot = Join-Path $sourceFixture 'bad-checksum'
    $rejected = $false
    try { Resolve-Z3Source | Out-Null } catch {
        if ($_.Exception.Message -notmatch 'checksum') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Unverified Z3 source archive accepted.' }
    $count++
    $env:Z3_SRC_SOURCE_DIR = Split-Path $scripts
    Set-Content -LiteralPath (Join-Path $scripts 'VERSION.txt') -Value '5.3.2.0'
    $rejected = $false
    try { Resolve-Z3Source | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Wrong solver source version accepted.' }
    $count++
} finally { Remove-Item -LiteralPath $sourceFixture -Recurse -Force }
Write-Host "$count static-runtime regression checks passed. No MXC qualification claimed."
