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
            if ((Test-SharedWindowsZ3 $fixture) -ne ($dependency -eq 'libz3.dll')) { throw 'Shared Z3 detection disagrees with imports.' }
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

# Exercise prebuilt selection and source fallback without network access.
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'windows-msvc.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in @('Get-Sha256', 'Resolve-Z3HeaderPath', 'Resolve-Z3Source', 'Test-PinnedZ3Available', 'Configure-Z3', 'Reset-WindowsCMakeGeneratorCache')) {
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
    Add-Type @'
public sealed class OpenShellZ3TestResponse { public int StatusCode; }
public sealed class OpenShellZ3TestException : System.Exception {
    public OpenShellZ3TestResponse Response;
    public OpenShellZ3TestException(int status) { Response = new OpenShellZ3TestResponse(); Response.StatusCode = status; }
}
'@
    $script:headStatus = 200
    $script:headCalls = @()
    $script:sourceDownloads = 0
    function Invoke-WebRequest([switch] $UseBasicParsing, [string] $Uri, [string] $OutFile, [string] $Method, [int] $TimeoutSec) {
        if ($Method -eq 'Head') {
            $script:headCalls += $Uri
            if ($script:headStatus -eq 0) { throw [IO.IOException]::new('Transport unavailable') }
            if ($script:headStatus -ne 200) { throw [OpenShellZ3TestException]::new($script:headStatus) }
        } else {
            $script:sourceDownloads++
            Copy-Item -LiteralPath $sourceArchive -Destination $OutFile
        }
    }
    $Z3Version = '5.1.0'
    $Z3SourceSha256 = Get-Sha256 $sourceArchive
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
    $script:cleanCalls = @()
    function cargo {
        $script:cleanCalls += ,@($args)
        $global:LASTEXITCODE = 0
    }
    Reset-WindowsCMakeGeneratorCache 'aarch64-pc-windows-msvc'
    $expected = @('clean', '-p', 'z3-sys', '--target', 'aarch64-pc-windows-msvc', '--profile', 'release', '--target-dir', $TargetDir)
    if ($script:cleanCalls.Count -ne 1 -or ($script:cleanCalls[0] -join '|') -ne ($expected -join '|')) { throw 'Cargo was not asked to invalidate precisely the stale solver profile and target.' }
    if (-not (Test-Path -LiteralPath $newBuild) -or -not (Test-Path -LiteralPath $otherTarget)) { throw 'Unrelated build files removed.' }
    $count++
    $archiveDir = Join-Path (Split-Path $oldBuild) 'lib'
    New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $archiveDir 'libz3.lib') -Value 'old cached archive'
    Remove-Item -LiteralPath (Join-Path $oldBuild 'CMakeCache.txt')
    Reset-WindowsCMakeGeneratorCache 'aarch64-pc-windows-msvc'
    if ($script:cleanCalls.Count -ne 2) { throw 'Cached solver archive without build rules was reused.' }
    $count++

    $script:staticPackage = $null
    function Resolve-Z3Package([string] $RustTarget) { return $script:staticPackage }
    $Z3Source = $false
    $StaticRuntime = $false
    $env:Z3_SRC_SOURCE_DIR = $null
    $env:Z3_LIBRARY_PATH_OVERRIDE = $null
    $env:Z3_SYS_Z3_HEADER = $null
    $features = Configure-Z3 @('aarch64-pc-windows-msvc', 'x86_64-pc-windows-msvc')
    if ($features.WorkspaceFeatures -notmatch 'prebuilt-z3' -or $features.FromSource -or $script:sourceDownloads) { throw 'Default no longer reuses pinned prebuilts.' }
    if ($script:headCalls.Count -ne 2 -or $script:headCalls[0] -notmatch 'z3-5.1.0-arm64-win.zip$' -or $script:headCalls[1] -notmatch 'z3-5.1.0-x64-win.zip$') { throw 'Prebuilt architecture/version mapping changed.' }
    $count++
    $cache = Join-Path $TargetDir 'aarch64-pc-windows-msvc/debug/build/z3-sys-cached/out/z3-5.1.0/bin'
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    Set-Content -LiteralPath (Join-Path $cache 'libz3.lib') -Value 'cached prebuilt'
    $script:headStatus = 500
    if (-not (Test-PinnedZ3Available 'aarch64-pc-windows-msvc') -or $script:headCalls.Count -ne 2) { throw 'Cached prebuilt was not reused offline.' }
    $count++
    $features = Configure-Z3 @('x86_64-pc-windows-msvc')
    if ($features.FromSource -or $features.WorkspaceFeatures -notmatch 'prebuilt-z3' -or $script:sourceDownloads) { throw 'Inconclusive HEAD changed the original prebuilt path.' }
    $count++
    $script:headStatus = 0
    if (-not (Test-PinnedZ3Available 'x86_64-pc-windows-msvc')) { throw 'Transport failure disabled the original downloader or offline non-Z3 commands.' }
    $count++

    $env:Z3_LIBRARY_PATH_OVERRIDE = $sourceFixture
    Set-Content -LiteralPath (Join-Path $sourceFixture 'libz3.lib') -Value 'supplied library'
    $env:Z3_SYS_Z3_HEADER = Join-Path $sourceFixture 'z3.h'
    Set-Content -LiteralPath $env:Z3_SYS_Z3_HEADER -Value '// header'
    Set-Content -LiteralPath (Join-Path $sourceFixture 'libz3.dll') -Value 'legacy shared runtime'
    $features = Configure-Z3 @('aarch64-pc-windows-msvc')
    if ($features.WorkspaceFeatures -or $features.FromSource -or $script:sourceDownloads) { throw 'Shared library override no longer works by default.' }
    $count++
    $StaticRuntime = $true
    $features = Configure-Z3 @('aarch64-pc-windows-msvc')
    if (-not $features.FromSource -or $env:Z3_LIBRARY_PATH_OVERRIDE -or $script:sourceDownloads -ne 1) { throw 'Legacy shared override defeated the default static package/source selection.' }
    $count++
    Remove-Item -LiteralPath (Join-Path $sourceFixture 'libz3.dll')
    $env:Z3_LIBRARY_PATH_OVERRIDE = $sourceFixture
    $env:Z3_SYS_Z3_HEADER = Join-Path $sourceFixture 'z3.h'
    $env:Z3_SRC_SOURCE_DIR = Join-Path $sourceFixture 'source-must-not-be-used'
    $features = Configure-Z3 @('aarch64-pc-windows-msvc')
    if ($features.WorkspaceFeatures -or $features.FromSource -or $script:sourceDownloads -ne 1) { throw 'Supplied static library unexpectedly rebuilt source.' }
    $count++
    $env:Z3_LIBRARY_PATH_OVERRIDE = $null
    $env:Z3_SRC_SOURCE_DIR = $null
    $script:staticPackage = Join-Path $sourceFixture 'ghcr-package'
    New-Item -ItemType Directory -Path (Join-Path $script:staticPackage 'lib'), (Join-Path $script:staticPackage 'include') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $sourceFixture 'libz3.lib') -Destination (Join-Path $script:staticPackage 'lib/libz3.lib')
    Copy-Item -LiteralPath (Join-Path $sourceFixture 'z3.h') -Destination (Join-Path $script:staticPackage 'include/z3.h')
    $features = Configure-Z3 @('aarch64-pc-windows-msvc')
    if ($features.WorkspaceFeatures -or $features.FromSource -or $env:Z3_SRC_SOURCE_DIR -or $script:sourceDownloads -ne 1) { throw 'Available static package unexpectedly selected source compilation.' }
    $count++
    $script:staticPackage = $null
    $env:Z3_LIBRARY_PATH_OVERRIDE = $null
    $features = Configure-Z3 @('aarch64-pc-windows-msvc')
    if ($features.WorkspaceFeatures -notmatch 'vendored-z3' -or -not $features.FromSource -or $script:sourceDownloads -ne 1) { throw 'Unavailable static package did not reuse pinned source.' }
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
    $StaticRuntime = $false
    $script:headStatus = 404
    $env:Z3_SRC_SOURCE_DIR = $null
    $features = Configure-Z3 @('x86_64-pc-windows-msvc')
    if (-not $features.FromSource -or $script:sourceDownloads -ne 1) { throw 'Missing pinned prebuilt did not reuse source fallback.' }
    $count++
    $env:Z3_SRC_SOURCE_DIR = $null
    $Z3Source = $true
    $script:headStatus = 500
    $features = Configure-Z3 @('x86_64-pc-windows-msvc')
    if (-not $features.FromSource -or $script:sourceDownloads -ne 1) { throw 'Explicit source request queried a prebuilt or missed the cache.' }
    $count++
    $env:Z3_SRC_SOURCE_DIR = $null
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
Write-Host "$count Windows dependency/runtime regression checks passed. No MXC qualification claimed."
