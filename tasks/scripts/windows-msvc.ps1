# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Windows MSVC build wrapper used by the `windows:*` mise tasks.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("check", "lint", "build", "package-z3", "build-mxc-fixtures", "test", "test-precommit", "test-unsupported", "test-mxc-real", "test-mxc-boundary", "test-mxc-loopback", "test-mxc-network", "test-mxc-audit", "artifacts", "ci")]
    [string] $Action,

    [Parameter(Position = 1)]
    [ValidateSet("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc", "native", "all")]
    [string] $Target = "all",

    [string] $LogDir,

    [switch] $StaticRuntime = ($env:OPENSHELL_WINDOWS_STATIC_RUNTIME -ne '0'),

    [switch] $Z3Source = ($env:OPENSHELL_WINDOWS_Z3_SOURCE -eq '1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw "windows-msvc.ps1 requires a Windows MSVC host."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
. (Join-Path $PSScriptRoot 'windows-runtime.ps1')
. (Join-Path $PSScriptRoot 'windows-z3.ps1')
if (-not $LogDir) {
    $LogDir = $RepoRoot
}
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}
$LogDir = (Resolve-Path $LogDir).Path

$TargetDir = $env:CARGO_TARGET_DIR
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    $TargetDir = Join-Path $RepoRoot "target"
}
$TargetDir = [IO.Path]::GetFullPath($TargetDir)

$BuildJobsValue = $env:OPENSHELL_WINDOWS_BUILD_JOBS
if ([string]::IsNullOrWhiteSpace($BuildJobsValue)) {
    $BuildJobsValue = $env:CARGO_BUILD_JOBS
}
if ([string]::IsNullOrWhiteSpace($BuildJobsValue)) {
    $BuildJobsValue = "4"
}
[int] $WindowsBuildJobs = 0
if (-not [int]::TryParse($BuildJobsValue, [ref] $WindowsBuildJobs) -or $WindowsBuildJobs -lt 1) {
    throw "OPENSHELL_WINDOWS_BUILD_JOBS or CARGO_BUILD_JOBS must be a positive integer."
}
$WindowsCargoMutex = [System.Threading.Mutex]::new($false, "Local\OpenShellWindowsMsvcCargo")

$UnsupportedDriverPackageExcludes = "--exclude openshell-driver-docker --exclude openshell-driver-kubernetes --exclude openshell-driver-kubernetes-secrets --exclude openshell-driver-podman --exclude openshell-driver-vault --exclude openshell-driver-vm --exclude openshell-sandbox --exclude openshell-vfio"
$WindowsClippyPackageExcludes = $UnsupportedDriverPackageExcludes
$WindowsClippyLintArgs = "-D warnings -A dead-code -A unused-imports -A clippy::unused-async"
$Z3Pin = Get-Content -LiteralPath (Join-Path $RepoRoot 'tasks/windows-z3.json') -Raw | ConvertFrom-Json
$Z3Version = $Z3Pin.version
$Z3SourceSha256 = $Z3Pin.sourceSha256
$PrebuiltZ3Version = $Z3Version
# Each Cargo invocation restores the caller's overrides before resolving its
# target. A preceding x64 build must never supply its library to ARM64.
$UserZ3Environment = @{}
foreach ($name in @('Z3_LIBRARY_PATH_OVERRIDE', 'Z3_SYS_Z3_HEADER', 'Z3_SRC_SOURCE_DIR', 'Z3_SYS_Z3_VERSION')) {
    $UserZ3Environment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Get-VsInstallRoots {
    $programFiles = @(
        [Environment]::GetEnvironmentVariable("ProgramFiles"),
        [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    ) | Where-Object { $_ }
    $editions = @("Enterprise", "Professional", "Community", "BuildTools")
    $candidates = @()

    foreach ($programFilesRoot in $programFiles) {
        $vsRoot = Join-Path $programFilesRoot "Microsoft Visual Studio"
        if (-not (Test-Path $vsRoot -PathType Container)) {
            continue
        }
        foreach ($releaseDir in Get-ChildItem $vsRoot -Directory) {
            foreach ($edition in $editions) {
                $installRoot = Join-Path $releaseDir.FullName $edition
                $vsDevCmd = Join-Path $installRoot "Common7\Tools\VsDevCmd.bat"
                if (-not (Test-Path $vsDevCmd -PathType Leaf)) {
                    continue
                }

                $toolsetVersion = [version] "0.0"
                $versionFile = Join-Path $installRoot "VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt"
                if (Test-Path $versionFile -PathType Leaf) {
                    try {
                        $toolsetVersion = [version] ((Get-Content $versionFile -Raw).Trim())
                    } catch {
                        $toolsetVersion = [version] "0.0"
                    }
                }
                $candidates += [pscustomobject]@{
                    Root = $installRoot
                    ToolsetVersion = $toolsetVersion
                }
            }
        }
    }

    return @($candidates | Sort-Object ToolsetVersion -Descending | Select-Object -ExpandProperty Root -Unique)
}

function Get-DefaultMsvcToolsetRoot([string] $VsInstallRoot) {
    $versionFile = Join-Path $VsInstallRoot "VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt"
    if (Test-Path $versionFile -PathType Leaf) {
        $version = (Get-Content $versionFile -Raw).Trim()
        $toolsetRoot = Join-Path $VsInstallRoot "VC\Tools\MSVC\$version"
        if (Test-Path $toolsetRoot -PathType Container) {
            return (Resolve-Path $toolsetRoot).Path
        }
    }

    $toolsetsRoot = Join-Path $VsInstallRoot "VC\Tools\MSVC"
    if (Test-Path $toolsetsRoot -PathType Container) {
        $toolset = Get-ChildItem $toolsetsRoot -Directory |
            Sort-Object { try { [version] $_.Name } catch { [version] "0.0" } } -Descending |
            Select-Object -First 1
        if ($toolset) {
            return $toolset.FullName
        }
    }

    return $null
}

function Test-VsInstanceSupportsTarget([string] $VsInstallRoot, [string] $RustTarget) {
    $toolsetRoot = Get-DefaultMsvcToolsetRoot $VsInstallRoot
    if (-not $toolsetRoot) {
        return $false
    }

    $hostToolsDir = switch (Get-HostArch) {
        "arm64" { "Hostarm64" }
        default { "Hostx64" }
    }
    $targetToolsDir = switch (Get-VsTargetArch $RustTarget) {
        "arm64" { "arm64" }
        default { "x64" }
    }
    $compiler = Join-Path $toolsetRoot "bin\$hostToolsDir\$targetToolsDir\cl.exe"
    if (-not (Test-Path $compiler -PathType Leaf)) {
        return $false
    }

    if ($RustTarget -eq "aarch64-pc-windows-msvc") {
        $spectreLibs = Join-Path $toolsetRoot "lib\spectre\arm64"
        if (-not (Test-Path $spectreLibs -PathType Container)) {
            return $false
        }
    }

    return $true
}

function Resolve-VsDevCmd([string] $RustTarget) {
    if ($env:OPENSHELL_VSDEVCMD -and (Test-Path $env:OPENSHELL_VSDEVCMD)) {
        return (Resolve-Path $env:OPENSHELL_VSDEVCMD).Path
    }

    $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    if ($programFilesX86) {
        $vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
    } else {
        $vswhere = $null
    }
    if ($vswhere -and (Test-Path $vswhere)) {
        $requiredComponents = switch ($RustTarget) {
            "x86_64-pc-windows-msvc" { @("Microsoft.VisualStudio.Component.VC.Tools.x86.x64") }
            "aarch64-pc-windows-msvc" {
                @(
                    "Microsoft.VisualStudio.Component.VC.Tools.ARM64",
                    "Microsoft.VisualStudio.Component.VC.Runtimes.ARM64.Spectre"
                )
            }
            default { throw "Unsupported target: $RustTarget" }
        }
        $found = & $vswhere -latest -products * -requires $requiredComponents -find "Common7\Tools\VsDevCmd.bat" | Select-Object -First 1
        if ($found -and (Test-Path $found)) {
            $resolved = (Resolve-Path $found).Path
            $installRoot = (Resolve-Path (Join-Path (Split-Path -Parent $resolved) "..\..")).Path
            if (Test-VsInstanceSupportsTarget $installRoot $RustTarget) {
                return $resolved
            }
        }
    }

    foreach ($installRoot in Get-VsInstallRoots) {
        if (Test-VsInstanceSupportsTarget $installRoot $RustTarget) {
            $candidate = Join-Path $installRoot "Common7\Tools\VsDevCmd.bat"
            return (Resolve-Path $candidate).Path
        }
    }

    if ($RustTarget -eq "aarch64-pc-windows-msvc") {
        throw "Could not find a Visual Studio instance with the ARM64 compiler and ARM64 Spectre-mitigated libraries. Install Microsoft.VisualStudio.Component.VC.Tools.ARM64 and Microsoft.VisualStudio.Component.VC.Runtimes.ARM64.Spectre, or set OPENSHELL_VSDEVCMD."
    }
    throw "Could not find a Visual Studio instance with the x64 compiler. Install Microsoft.VisualStudio.Component.VC.Tools.x86.x64, or set OPENSHELL_VSDEVCMD."
}

function Get-LibclangBinSubdir {
    return ([System.Runtime.InteropServices.RuntimeInformation, mscorlib]::OSArchitecture.ToString())
}

function Resolve-LibclangPath {
    $subdir = Get-LibclangBinSubdir

    if ($env:LIBCLANG_PATH) {
        $candidate = Join-Path $env:LIBCLANG_PATH "libclang.dll"
        if (Test-Path $candidate) {
            return (Resolve-Path $env:LIBCLANG_PATH).Path
        }
        throw "LIBCLANG_PATH is set but libclang.dll was not found at: $candidate"
    }

    $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    if ($programFilesX86) {
        $vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
    } else {
        $vswhere = $null
    }
    if ($vswhere -and (Test-Path $vswhere)) {
        $found = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Llvm.Clang -find "VC\Tools\Llvm\$subdir\bin\libclang.dll" | Select-Object -First 1
        if ($found -and (Test-Path $found)) {
            return (Split-Path -Parent (Resolve-Path $found).Path)
        }
    }

    foreach ($installRoot in Get-VsInstallRoots) {
        $candidateDir = Join-Path $installRoot "VC\Tools\Llvm\$subdir\bin"
        $candidate = Join-Path $candidateDir "libclang.dll"
        if (Test-Path $candidate -PathType Leaf) {
            return (Resolve-Path $candidateDir).Path
        }
    }

    $llvmDir = "C:\Program Files\LLVM\bin"
    if (Test-Path (Join-Path $llvmDir "libclang.dll")) {
        return (Resolve-Path $llvmDir).Path
    }

    throw "Could not find libclang.dll. Install Visual Studio C++ Clang tools, or set LIBCLANG_PATH to the directory containing libclang.dll."
}

function Resolve-NinjaPath {
    $fromPath = Get-Command ninja.exe -ErrorAction SilentlyContinue
    if ($fromPath) {
        return $fromPath.Source
    }

    $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    if ($programFilesX86) {
        $vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
    } else {
        $vswhere = $null
    }
    if ($vswhere -and (Test-Path $vswhere)) {
        $found = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.CMake.Project -find "Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" | Select-Object -First 1
        if ($found -and (Test-Path $found -PathType Leaf)) {
            return (Resolve-Path $found).Path
        }
    }

    foreach ($installRoot in Get-VsInstallRoots) {
        $candidate = Join-Path $installRoot "Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
        if (Test-Path $candidate -PathType Leaf) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw "Could not find ninja.exe. Install Microsoft.VisualStudio.Component.VC.CMake.Project."
}

function Add-PathEntry([string] $Directory) {
    if (($env:PATH -split ";") -notcontains $Directory) {
        $env:PATH = "$Directory;$env:PATH"
    }
}

function Configure-Arm64CrossBuild([string[]] $RustTargets) {
    if ((Get-HostArch) -ne "amd64" -or $RustTargets -notcontains "aarch64-pc-windows-msvc") {
        return
    }

    $clangCl = Join-Path $env:LIBCLANG_PATH "clang-cl.exe"
    if (-not (Test-Path $clangCl -PathType Leaf)) {
        throw "ARM64 cross-compilation requires host-native clang-cl.exe next to libclang.dll. Install Microsoft.VisualStudio.Component.VC.Llvm.Clang."
    }
    Add-PathEntry $env:LIBCLANG_PATH

    $ninja = Resolve-NinjaPath
    Add-PathEntry (Split-Path -Parent $ninja)

    Write-Host "==> ARM64 cross-build toolchain"
    Write-Host "    clang-cl: $clangCl"
    Write-Host "    ninja:    $ninja"
    Write-Host "    Z3:       pinned prebuilt, or MSVC cl.exe with Ninja for source builds"
}

function Get-HostArch {
    switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
        "Arm64" { "arm64" }
        default { "amd64" }
    }
}

function Get-VsTargetArch([string] $RustTarget) {
    switch ($RustTarget) {
        "x86_64-pc-windows-msvc" { "amd64" }
        "aarch64-pc-windows-msvc" { "arm64" }
        default { throw "Unsupported target: $RustTarget" }
    }
}

function Get-NativeHostArch {
    # SSH may launch an emulated PowerShell; select the machine's native target.
    switch ([Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', 'Machine')) {
        'ARM64' { return 'arm64' }
        'AMD64' { return 'amd64' }
        default { throw 'Windows validation requires a native ARM64 or x64 machine.' }
    }
}

function Assert-NativeTestTarget([string] $RustTarget) {
    $targetArch = Get-VsTargetArch $RustTarget
    $hostArch = Get-NativeHostArch
    if ($targetArch -ne $hostArch) {
        throw "Windows tests require a native runner. Target $RustTarget maps to $targetArch, but the host is $hostArch."
    }
}

function Get-SelectedTargets([string] $RequestedTarget) {
    if ($RequestedTarget -eq "native") {
        switch (Get-NativeHostArch) {
            "arm64" { return @("aarch64-pc-windows-msvc") }
            default { return @("x86_64-pc-windows-msvc") }
        }
    }
    if ($RequestedTarget -eq "all") {
        $targets = @("x86_64-pc-windows-msvc")
        if ($env:OPENSHELL_MXC_SKIP_ARM64 -ne "1") {
            $targets += "aarch64-pc-windows-msvc"
        }
        return $targets
    }
    return @($RequestedTarget)
}

function Resolve-Z3HeaderPath([string] $HeaderPath) {
    if ([string]::IsNullOrWhiteSpace($HeaderPath)) {
        throw "Z3_LIBRARY_PATH_OVERRIDE is set. Set Z3_SYS_Z3_HEADER to the full path of z3.h."
    }

    if (-not (Test-Path $HeaderPath -PathType Leaf)) {
        throw "Z3_SYS_Z3_HEADER is set but z3.h was not found at: $HeaderPath"
    }
    if ((Split-Path -Leaf $HeaderPath) -ne "z3.h") {
        throw "Z3_SYS_Z3_HEADER must point to z3.h. Got: $HeaderPath"
    }

    return (Resolve-Path $HeaderPath).Path
}

function Resolve-Z3Source {
    if ($env:Z3_SRC_SOURCE_DIR) {
        $source = (Resolve-Path -LiteralPath $env:Z3_SRC_SOURCE_DIR).Path
    } else {
        # rust-cache prunes non-Cargo files under target, including VERSION.txt.
        # Keep the complete source tree outside that cache's ownership.
        $sourceRoot = Join-Path $RepoRoot '.cache/windows-z3-source'
        $source = Join-Path $sourceRoot "z3-z3-$Z3Version"
        if (-not (Test-Path -LiteralPath $source -PathType Container)) {
            $staging = Join-Path $sourceRoot ("download-" + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $staging -Force | Out-Null
            try {
                $archive = Join-Path $staging 'source.zip'
                # Keep the existing Windows solver version. The z3-src crate's
                # bundled source can advance independently of this release pin.
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/Z3Prover/z3/archive/refs/tags/z3-$Z3Version.zip" -OutFile $archive
                if ((Get-Sha256 $archive) -ne $Z3SourceSha256) { throw 'Z3 source archive checksum mismatch.' }
                # Hosted ARM64 runners can expose a PowerShell 7 archive module
                # to Windows PowerShell 5.1. Use the .NET API shared by both.
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [IO.Compression.ZipFile]::ExtractToDirectory($archive, $staging)
                New-Item -ItemType Directory -Path (Split-Path $source) -Force | Out-Null
                Move-Item -LiteralPath (Join-Path $staging "z3-z3-$Z3Version") -Destination $source
            } finally { Remove-Item -LiteralPath $staging -Recurse -Force }
        }
    }
    $versionFile = Join-Path $source 'scripts/VERSION.txt'
    if (-not (Test-Path -LiteralPath $versionFile) -or ([version](Get-Content -LiteralPath $versionFile -Raw).Trim()).ToString(3) -ne $Z3Version) {
        throw "Z3 source must be version $Z3Version at $source."
    }
    return $source
}

function Test-PinnedZ3Available([string] $RustTarget) {
    foreach ($profile in @('debug', 'release')) {
        $cached = Join-Path $TargetDir "$RustTarget/$profile/build/z3-sys-*/out/z3-$Z3Version/bin/libz3.lib"
        if (Get-Item -Path $cached -ErrorAction SilentlyContinue) { return $true }
    }
    $arch = switch ($RustTarget) {
        'aarch64-pc-windows-msvc' { 'arm64' }
        'x86_64-pc-windows-msvc' { 'x64' }
        default { return $false }
    }
    # z3-sys still owns downloading and caching the release. Only probe a cold
    # target so a genuinely missing release asset can select the source fallback.
    $url = "https://github.com/Z3Prover/z3/releases/download/z3-$Z3Version/z3-$Z3Version-$arch-win.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Method Head -Uri $url -TimeoutSec 30 | Out-Null
        return $true
    } catch {
        $response = $_.Exception.PSObject.Properties['Response']
        if ($response -and $response.Value -and [int]$response.Value.StatusCode -eq 404) { return $false }
        # Keep the original z3-sys download/error handling for inconclusive
        # probes. HEAD may be blocked even when GET works, and commands whose
        # Cargo graph does not use Z3 must still work offline.
        return $true
    }
}

function Configure-Z3([string[]] $RustTargets) {
    $sourceRequested = $Z3Source -or ([string]::IsNullOrWhiteSpace($env:Z3_LIBRARY_PATH_OVERRIDE) -and -not [string]::IsNullOrWhiteSpace($env:Z3_SRC_SOURCE_DIR))
    if ($sourceRequested) {
        $env:Z3_LIBRARY_PATH_OVERRIDE = $null
        $env:Z3_SYS_Z3_HEADER = $null
    }
    if ($StaticRuntime -and $env:Z3_LIBRARY_PATH_OVERRIDE -and (Test-Path -LiteralPath (Join-Path $env:Z3_LIBRARY_PATH_OVERRIDE 'libz3.dll'))) {
        Write-Warning 'Ignoring the legacy shared Z3 override for the default static build. Set OPENSHELL_WINDOWS_STATIC_RUNTIME=0 to use shared CRT/Z3 explicitly.'
        $env:Z3_LIBRARY_PATH_OVERRIDE = $null
        $env:Z3_SYS_Z3_HEADER = $null
    }
    if ([string]::IsNullOrWhiteSpace($env:Z3_LIBRARY_PATH_OVERRIDE)) {
        $useSource = $sourceRequested
        if ($StaticRuntime -and -not $useSource) {
            if ($RustTargets.Count -ne 1) { throw 'Resolve static Z3 separately for each Cargo target.' }
            $package = Resolve-Z3Package $RustTargets[0]
            if ($package) {
                $env:Z3_LIBRARY_PATH_OVERRIDE = Join-Path $package 'lib'
                $env:Z3_SYS_Z3_HEADER = Join-Path $package 'include/z3.h'
                $env:Z3_SYS_Z3_VERSION = $Z3Version
            } else { $useSource = $true }
        }
        if (-not $StaticRuntime -and -not $useSource) {
            foreach ($rustTarget in $RustTargets) {
                if (-not (Test-PinnedZ3Available $rustTarget)) {
                    Write-Warning "Pinned Z3 $Z3Version prebuilt unavailable for $rustTarget; building pinned source."
                    $useSource = $true
                }
            }
        }
        if (-not $useSource -and -not $env:Z3_LIBRARY_PATH_OVERRIDE) {
            $env:Z3_SYS_Z3_VERSION = $Z3Version
            Write-Host "==> Z3: pinned prebuilt $Z3Version (z3-sys download/cache)"
            return [pscustomobject]@{
                WorkspaceFeatures = '--features openshell-prover/prebuilt-z3'
                ServerFeatures = '--features openshell-server/prebuilt-z3,openshell-prover/prebuilt-z3'
                GatewayFeatures = '--features prebuilt-z3'
                FromSource = $false
            }
        }
        if ($useSource) {
            $env:Z3_SRC_SOURCE_DIR = Resolve-Z3Source
            $env:Z3_SYS_Z3_VERSION = $Z3Version
            $env:CMAKE_BUILD_PARALLEL_LEVEL = "$WindowsBuildJobs"
            Write-Host "==> Z3: source $env:Z3_SRC_SOURCE_DIR (static CRT: $StaticRuntime)"
            return [pscustomobject]@{
                WorkspaceFeatures = '--features openshell-prover/vendored-z3'
                ServerFeatures = '--features openshell-server/vendored-z3,openshell-prover/vendored-z3'
                GatewayFeatures = '--features vendored-z3'
                FromSource = $true
            }
        }
    }

    if (-not (Test-Path $env:Z3_LIBRARY_PATH_OVERRIDE -PathType Container)) {
        throw "Z3_LIBRARY_PATH_OVERRIDE is set but the directory does not exist: $env:Z3_LIBRARY_PATH_OVERRIDE"
    }

    $libDir = (Resolve-Path $env:Z3_LIBRARY_PATH_OVERRIDE).Path
    $importLib = Join-Path $libDir "libz3.lib"
    if (-not (Test-Path $importLib -PathType Leaf)) {
        throw "Z3_LIBRARY_PATH_OVERRIDE is set but libz3.lib was not found at: $importLib"
    }

    $env:Z3_LIBRARY_PATH_OVERRIDE = $libDir
    $env:Z3_SYS_Z3_HEADER = Resolve-Z3HeaderPath $env:Z3_SYS_Z3_HEADER
    if ($StaticRuntime -and (Test-Path -LiteralPath (Join-Path $libDir 'libz3.dll'))) {
        throw 'StaticRuntime requires a genuine static libz3.lib built with /MT. Remove the shared override to build pinned source, or supply a static library.'
    }

    if (($env:PATH -split ";") -notcontains $libDir) {
        $env:PATH = "$libDir;$env:PATH"
    }

    Write-Host "==> Z3: supplied MSVC library (static packages require /MT)"
    Write-Host "    Z3_LIBRARY_PATH_OVERRIDE=$env:Z3_LIBRARY_PATH_OVERRIDE"
    Write-Host "    Z3_SYS_Z3_HEADER=$env:Z3_SYS_Z3_HEADER"

    return [pscustomobject]@{
        WorkspaceFeatures = ""
        ServerFeatures = ""
        GatewayFeatures = ""
        FromSource = $false
    }
}

function Reset-WindowsCMakeGeneratorCache([string] $RustTarget) {
    foreach ($profile in @('debug', 'release')) {
        $buildRoot = Join-Path $TargetDir "$RustTarget/$profile/build"
        if (-not (Test-Path -LiteralPath $buildRoot)) { continue }
        $stale = @(Get-ChildItem -LiteralPath $buildRoot -Filter 'z3-sys-*' -Directory | Where-Object {
            $cache = Join-Path $_.FullName 'out/build/CMakeCache.txt'
            if (Test-Path -LiteralPath $cache) {
                Select-String -LiteralPath $cache -Pattern '^CMAKE_GENERATOR:INTERNAL=(?!Ninja$)' -Quiet
            } else {
                # A pruned cache can retain the archive without its build rules.
                Test-Path -LiteralPath (Join-Path $_.FullName 'out/lib/libz3.lib')
            }
        })
        if ($stale.Count) {
            # Cargo must invalidate its build-script fingerprint and the linked
            # archive too; deleting only CMake files can reuse an old solver.
            $cargoProfile = if ($profile -eq 'debug') { 'dev' } else { 'release' }
            Write-Host "==> Rebuilding cached $cargoProfile Z3 with Ninja"
            & cargo clean -p z3-sys --target $RustTarget --profile $cargoProfile --target-dir $TargetDir
            if ($LASTEXITCODE -ne 0) { throw 'Could not invalidate the old Z3 build cache.' }
        }
    }
}

function Invoke-Z3Package([string] $RustTarget) {
    $source = Resolve-Z3Source
    $vsDevCmd = Resolve-VsDevCmd $RustTarget
    $ninja = Resolve-NinjaPath
    $cmake = Get-Command cmake.exe -ErrorAction SilentlyContinue
    $cmakePath = if ($cmake) { $cmake.Source } else { Join-Path (Split-Path (Split-Path $ninja)) 'CMake/bin/cmake.exe' }
    if (-not (Test-Path -LiteralPath $cmakePath)) { throw 'Install Visual Studio CMake tools to package Z3.' }
    $build = Join-Path $TargetDir "z3-build/$Z3Version-msvc$($Z3Pin.msvcToolset)-v$($Z3Pin.packageRevision)/$RustTarget"
    $output = Join-Path $TargetDir 'windows-z3-packages'
    $install = Join-Path $build 'install'
    $package = Join-Path $build 'package'
    $toolsetRecord = Join-Path $build 'msvc-toolset.txt'
    New-Item -ItemType Directory -Path $build, $output -Force | Out-Null
    if (Test-Path -LiteralPath $package) { Remove-Item -LiteralPath $package -Recurse -Force }
    $flags = @(
        '-G Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_CXX_COMPILER=cl.exe', '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded',
        '-DZ3_BUILD_LIBZ3_SHARED=OFF', '-DZ3_BUILD_LIBZ3_MSVC_STATIC=ON',
        '-DZ3_LINK_TIME_OPTIMIZATION=OFF', '-DZ3_BUILD_EXECUTABLE=ON',
        '-DZ3_BUILD_TEST_EXECUTABLES=OFF', '-DZ3_ENABLE_EXAMPLE_TARGETS=OFF',
        '-DZ3_BUILD_PYTHON_BINDINGS=OFF', '-DZ3_BUILD_DOTNET_BINDINGS=OFF', '-DZ3_BUILD_JAVA_BINDINGS=OFF'
    )
    $log = Join-Path $LogDir "package-z3-$RustTarget.log"
    $cmd = @(
        "call `"$vsDevCmd`" -arch=$(Get-VsTargetArch $RustTarget) -host_arch=$(Get-HostArch) -vcvars_ver=$($Z3Pin.msvcToolset)",
        "set VCToolsVersion>`"$toolsetRecord`"",
        "findstr /i /b /l /c:`"VCToolsVersion=$($Z3Pin.msvcToolset).`" `"$toolsetRecord`"",
        "`"$cmakePath`" -S `"$source`" -B `"$build`" $($flags -join ' ') -DCMAKE_MAKE_PROGRAM=`"$ninja`" -DCMAKE_INSTALL_PREFIX=`"$install`"",
        "`"$cmakePath`" --build `"$build`" --target install --parallel $WindowsBuildJobs"
    ) -join ' && '
    Write-Host "==> Building pinned Z3 $Z3Version /MT package for $RustTarget (one-time dependency build)"
    & cmd /d /c "$cmd > `"$log`" 2>&1"
    if ($LASTEXITCODE -ne 0) {
        if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 100 }
        throw "Z3 package build requires MSVC $($Z3Pin.msvcToolset), CMake, and Ninja. See $log"
    }
    $solver = Join-Path $install 'bin/z3.exe'
    Assert-StaticWindowsRuntime $solver $RustTarget
    $version = & $solver -version
    if ($LASTEXITCODE -ne 0 -or $version -notmatch "^Z3 version $([regex]::Escape($Z3Version))( |$)") { throw "Wrong packaged Z3 version: $version" }
    $query = Join-Path $build 'smoke.smt2'
    Set-Content -LiteralPath $query -Encoding ASCII -Value '(declare-const x Int) (assert (> x 0)) (check-sat) (assert (< x 0)) (check-sat)'
    $answers = @(& $solver $query)
    if ($LASTEXITCODE -ne 0 -or ($answers -join ',') -ne 'sat,unsat') { throw "Z3 solver smoke failed: $answers" }
    if (Select-String -LiteralPath (Join-Path $build 'build.ninja') -Pattern '(?i)(?:/GL|-flto)(?:\s|$)' -Quiet) { throw 'Portable Z3 archives must not contain compiler-specific LTO objects.' }
    New-Item -ItemType Directory -Path $package -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $install 'lib'), (Join-Path $install 'include') -Destination $package -Recurse
    Copy-Item -LiteralPath (Join-Path $source 'LICENSE.txt') -Destination $package
    $files = @(Get-ChildItem -LiteralPath $package -File -Recurse | ForEach-Object {
        [ordered]@{ path = $_.FullName.Substring($package.Length + 1).Replace('\', '/'); sha256 = (Get-Sha256 $_.FullName).ToLowerInvariant(); size = $_.Length }
    })
    [ordered]@{
        version = $Z3Version; target = $RustTarget; runtime = 'MT'; configuration = 'Release'; lto = $false
        msvcToolset = (Get-Content -LiteralPath $toolsetRecord -Raw).Trim().Split('=')[1]
        sourceUrl = "https://github.com/Z3Prover/z3/archive/refs/tags/z3-$Z3Version.zip"
        sourceSha256 = $Z3SourceSha256; buildRevision = (& git -C $RepoRoot rev-parse HEAD)
        cmakeFlags = $flags; solverSmoke = $answers; staticRuntimeAudit = 'passed'; files = $files
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $package 'build.json') -Encoding UTF8
    $archive = Join-Path $output "z3-$Z3Version-$RustTarget-mt-v$($Z3Pin.packageRevision).zip"
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($package, $archive, [IO.Compression.CompressionLevel]::Optimal, $false)
    "$(Get-Sha256 $archive)  $(Split-Path -Leaf $archive)" | Set-Content -LiteralPath "$archive.sha256" -Encoding ASCII
    Write-Host "==> Z3 package: $archive ($((Get-Item -LiteralPath $archive).Length) bytes)"
}

function Invoke-VsCargo {
    param(
        [Parameter(Mandatory = $true)] [string] $RustTarget,
        [Parameter(Mandatory = $true)] [string] $CargoArgs,
        [Parameter(Mandatory = $true)] [string] $LogName,
        [ValidateSet('Workspace', 'Server', 'Gateway', 'None')] [string] $Z3Scope = 'Workspace'
    )

    $Z3FromSource = $false
    foreach ($name in $UserZ3Environment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $UserZ3Environment[$name], 'Process')
    }
    if ($Z3Scope -ne 'None') {
        $z3 = Configure-Z3 @($RustTarget)
        $Z3FromSource = $z3.FromSource
        $features = $z3."${Z3Scope}Features"
        if ($features) {
            # Cargo feature options must precede test-harness arguments.
            $separator = $CargoArgs.IndexOf(' -- ')
            if ($separator -ge 0) { $CargoArgs = $CargoArgs.Insert($separator, " $features") }
            else { $CargoArgs += " $features" }
        }
    }
    # cmake-rs clears MSVC's configuration optimization flags when it selects
    # the Visual Studio generator implicitly. Ninja preserves /O2 for Release
    # Z3, including the dependency profile used by development/test builds.
    if ($Z3FromSource) {
        $ninja = Resolve-NinjaPath
        Add-PathEntry (Split-Path -Parent $ninja)
    }

    if (($Z3FromSource -or $StaticRuntime) -and $CargoArgs.StartsWith('cargo ')) {
        # The old prebuilt solver was optimized even in debug/test builds.
        # An unoptimized native Z3 can exhaust otherwise unchanged solver budgets.
        $configs = @()
        if ($Z3FromSource -and $CargoArgs -notmatch '--manifest-path') {
            $configs += '--config "' + (Join-Path $RepoRoot '.cargo/windows-msvc.toml') + '"'
        }
        if ($StaticRuntime) {
            $configs += '--config "' + (Join-Path $RepoRoot '.cargo/windows-static.toml') + '"'
        }
        $configArgs = $configs -join ' '
        if ($CargoArgs.StartsWith('cargo nextest run ')) {
            # Nextest starts Cargo itself; global Cargo options are not forwarded.
            $CargoArgs = 'cargo nextest run ' + $configArgs + ' ' + $CargoArgs.Substring(18)
        } else {
            $CargoArgs = 'cargo ' + $configArgs + ' ' + $CargoArgs.Substring(6)
        }
    }

    & rustup target add $RustTarget
    if ($LASTEXITCODE -ne 0) {
        throw "rustup target add $RustTarget failed"
    }

    $vsDevCmd = Resolve-VsDevCmd $RustTarget
    $targetArch = Get-VsTargetArch $RustTarget
    $hostArch = Get-HostArch
    $logPath = Join-Path $LogDir $LogName
    $rustcWrapper = ""
    if (-not [string]::IsNullOrWhiteSpace($env:RUSTC_WRAPPER)) {
        $wrapperCommand = Get-Command $env:RUSTC_WRAPPER -ErrorAction SilentlyContinue
        if ($wrapperCommand) {
            $rustcWrapper = $wrapperCommand.Source
        } else {
            Write-Warning "RUSTC_WRAPPER '$env:RUSTC_WRAPPER' was not found; continuing without it."
        }
    }
    $environmentSetup = @(
        "set `"CARGO_TARGET_DIR=$TargetDir`"",
        "set `"CARGO_BUILD_JOBS=$WindowsBuildJobs`"",
        "set `"CARGO_INCREMENTAL=0`"",
        "set `"RUSTC_WRAPPER=$rustcWrapper`""
    )
    if ($Z3FromSource) {
        $environmentSetup += @(
            'set "CMAKE_GENERATOR=Ninja"',
            # z3-src otherwise adds MSBuild's -m argument to Ninja.
            'if not defined CMAKE_CXX_COMPILER_LAUNCHER (set "CMAKE_CXX_COMPILER_LAUNCHER=cmake;-E;env")'
        )
    }
    if ($hostArch -eq "amd64" -and $RustTarget -eq "aarch64-pc-windows-msvc") {
        # Native ARM64 dependencies select their own compilers. Clear inherited
        # overrides so AWS-LC can select clang-cl inside its build script.
        $environmentSetup += @(
            "set `"CC=`"",
            "set `"CXX=`"",
            "set `"CC_aarch64-pc-windows-msvc=`"",
            "set `"CXX_aarch64-pc-windows-msvc=`"",
            "set `"CC_aarch64_pc_windows_msvc=`"",
            "set `"CXX_aarch64_pc_windows_msvc=`""
        )
    }
    $cmd = "call `"$vsDevCmd`" -arch=$targetArch -host_arch=$hostArch && $($environmentSetup -join ' && ') && $CargoArgs"

    Write-Host "==> $CargoArgs"
    Write-Host "    target: $RustTarget"
    Write-Host "    log:    $logPath"

    $lockAcquired = $false
    try {
        try {
            $lockAcquired = $WindowsCargoMutex.WaitOne(0)
            if (-not $lockAcquired) {
                Write-Host "    waiting for another Windows Cargo task"
                $lockAcquired = $WindowsCargoMutex.WaitOne([TimeSpan]::FromHours(2))
            }
        } catch [System.Threading.AbandonedMutexException] {
            $lockAcquired = $true
        }
        if (-not $lockAcquired) {
            throw "Timed out waiting for another Windows Cargo task to finish."
        }

        if ($Z3FromSource) { Reset-WindowsCMakeGeneratorCache $RustTarget }
        $cmdWithLog = "$cmd > `"$logPath`" 2>&1"
        & cmd /v:on /d /c $cmdWithLog
        $exitCode = $LASTEXITCODE
        if (Test-Path $logPath) {
            Get-Content $logPath
        }
        if ($exitCode -ne 0) {
            throw "Command failed with exit code $exitCode. See $logPath"
        }
    } finally {
        if ($lockAcquired) {
            $WindowsCargoMutex.ReleaseMutex()
        }
    }
}

function Invoke-Check([string] $RustTarget) {
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -CargoArgs "cargo check --workspace $UnsupportedDriverPackageExcludes --target $RustTarget" `
        -LogName "build-$RustTarget-check.log"
    Assert-GatewayExcludesUnsupportedDriverCrates $RustTarget
}

function Assert-GatewayExcludesUnsupportedDriverCrates([string] $RustTarget) {
    $logName = "build-$RustTarget-driver-tree.log"
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -Z3Scope None -CargoArgs "cargo tree -p openshell-gateway --target $RustTarget --prefix none" `
        -LogName $logName

    $logPath = Join-Path $LogDir $logName
    $unexpected = @(Select-String `
        -Path $logPath `
        -Pattern '^openshell-driver-(docker|kubernetes|podman|vm)\s')
    if ($unexpected.Count -gt 0) {
        $packages = ($unexpected.Line | Sort-Object -Unique) -join ", "
        throw "Unsupported driver crates entered the Windows gateway dependency graph: $packages"
    }
}

function Invoke-Lint([string] $RustTarget) {
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -CargoArgs "cargo clippy --workspace --all-targets --no-deps $WindowsClippyPackageExcludes --target $RustTarget -- $WindowsClippyLintArgs" `
        -LogName "lint-$RustTarget-workspace.log"
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -Z3Scope None -CargoArgs "cargo clippy --manifest-path e2e/rust/Cargo.toml --all-targets --no-deps --target $RustTarget -- $WindowsClippyLintArgs" `
        -LogName "lint-$RustTarget-e2e.log"
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -Z3Scope None -CargoArgs "cargo check --manifest-path examples/governance-interceptor/Cargo.toml --all-targets --target $RustTarget" `
        -LogName "lint-$RustTarget-governance-interceptor.log"
}

function Invoke-Build([string] $RustTarget) {
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -CargoArgs "cargo build --release --target $RustTarget --bin openshell-gateway --bin openshell --bin openshell-supervisor --bin openshell-windows-sandbox" `
        -LogName "build-$RustTarget-release.log"
    if ($StaticRuntime) {
        foreach ($binary in @('openshell-gateway.exe', 'openshell.exe', 'openshell-supervisor.exe', 'openshell-windows-sandbox.exe')) {
            Assert-StaticWindowsRuntime (Join-Path $TargetDir "$RustTarget/release/$binary") $RustTarget
        }
    }
    if (Test-SharedWindowsZ3 (Join-Path $TargetDir "$RustTarget/release/openshell-gateway.exe")) {
        Stage-Z3Runtime $RustTarget
        return
    }
    # Do not leave a previously staged DLL in a directory used for ZIP packages.
    $staleDll = Join-Path $TargetDir "$RustTarget/release/libz3.dll"
    if (Test-Path -LiteralPath $staleDll) { Remove-Item -LiteralPath $staleDll }
}

function Stage-Z3Runtime([string] $RustTarget) {
    $release = Join-Path $TargetDir "$RustTarget/release"
    if ($env:Z3_LIBRARY_PATH_OVERRIDE) {
        $candidates = @(Get-Item -LiteralPath (Join-Path $env:Z3_LIBRARY_PATH_OVERRIDE 'libz3.dll') -ErrorAction SilentlyContinue)
    } else {
        # Only use the pinned release from this target's build cache. Never pick
        # the newest arbitrary DLL, or trust a stale adjacent runtime.
        $candidates = @(Get-ChildItem -Path (Join-Path $release "build/z3-sys-*/out/z3-$PrebuiltZ3Version/bin/libz3.dll") -File -ErrorAction SilentlyContinue)
    }
    if ($candidates.Count -eq 0) { throw "Matching libz3.dll not found for $RustTarget." }
    $hashes = @($candidates | ForEach-Object { Get-Sha256 $_.FullName } | Select-Object -Unique)
    if ($hashes.Count -ne 1) { throw "Ambiguous Z3 runtimes for $RustTarget; use a clean target cache or Z3_LIBRARY_PATH_OVERRIDE." }
    $source = $candidates[0].FullName
    $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($source))
    try {
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "Invalid Z3 DLL: $source" }
        $reader.BaseStream.Position = 0x3C
        $offset = $reader.ReadInt32()
        if ($offset -lt 64 -or $offset -gt $reader.BaseStream.Length - 6) { throw 'Invalid Z3 PE offset.' }
        $reader.BaseStream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw 'Invalid Z3 PE signature.' }
        $expected = if ($RustTarget -eq 'aarch64-pc-windows-msvc') { 0xAA64 } else { 0x8664 }
        if ($reader.ReadUInt16() -ne $expected) { throw "Z3 DLL architecture does not match $RustTarget." }
    } finally { $reader.Dispose() }
    $destination = Join-Path $release 'libz3.dll'
    if ([IO.Path]::GetFullPath($source) -ne [IO.Path]::GetFullPath($destination)) {
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }
    if ((Get-Sha256 $destination) -ne $hashes[0]) { throw 'Staged Z3 DLL hash mismatch.' }
    Write-Host "==> Staged $destination (SHA256=$($hashes[0]))"
}

function Invoke-Test([string] $RustTarget) {
    Assert-NativeTestTarget $RustTarget
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -CargoArgs "cargo nextest run --profile ci --workspace $UnsupportedDriverPackageExcludes --target $RustTarget" `
        -LogName "test-$RustTarget.log"
}

function Invoke-PreCommitTest([string] $RustTarget) {
    Assert-NativeTestTarget $RustTarget
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -Z3Scope Server -CargoArgs "cargo nextest run --profile ci --workspace $UnsupportedDriverPackageExcludes --target $RustTarget --features openshell-server/test-support" `
        -LogName "test-$RustTarget-precommit.log"
}

function Invoke-UnsupportedContractTests([string] $RustTarget) {
    Assert-NativeTestTarget $RustTarget

    $tests = @(
        "windows_builtin_compute_drivers_report_unsupported",
        "default_registry_contains_exactly_the_enabled_compute_drivers"
    )
    foreach ($test in $tests) {
        Invoke-VsCargo `
            -RustTarget $RustTarget `
            -Z3Scope Gateway -CargoArgs "cargo test -p openshell-gateway --target $RustTarget $test" `
            -LogName "test-$RustTarget-unsupported-$test.log"
    }

    foreach ($features in @("", "compute-driver-mxc", "compute-driver-docker", "compute-driver-mxc,compute-driver-docker")) {
        $featureArgs = if ($features) { "--features $features" } else { "" }
        $variant = if ($features) { $features.Replace(",", "-") } else { "protocol-only" }
        Invoke-VsCargo `
            -RustTarget $RustTarget `
            -Z3Scope Gateway -CargoArgs "cargo test -p openshell-gateway --lib --target $RustTarget --no-default-features $featureArgs" `
            -LogName "test-$RustTarget-selective-$variant.log"
    }
}

function Invoke-MxcRealTests([string] $RustTarget) {
    Assert-NativeTestTarget $RustTarget
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -Z3Scope None -CargoArgs "cargo test -p openshell-driver-mxc --test wxc_exec_real --target $RustTarget -- --ignored --test-threads=1 --nocapture" `
        -LogName "test-$RustTarget-mxc-real.log"
}

function Get-Sha256([string] $Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace("-", "")
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Show-Artifacts([string[]] $RustTargets) {
    $rows = @()
    foreach ($rustTarget in $RustTargets) {
        foreach ($binary in @("openshell-gateway.exe", "openshell.exe", "openshell-supervisor.exe", "openshell-windows-sandbox.exe")) {
            $path = Join-Path $TargetDir "$rustTarget\release\$binary"
            if (-not (Test-Path $path)) {
                continue
            }
            $item = Get-Item $path
            $rows += [pscustomobject]@{
                Target = $rustTarget
                Binary = $binary
                Size = $item.Length
                SHA256 = Get-Sha256 $item.FullName
                Path = $item.FullName
            }
        }
    }
    if ($rows.Count -eq 0) {
        Write-Warning "No release artifacts found under $TargetDir"
        return
    }
    $rows | Format-Table -AutoSize
}

if ($Action -eq "ci" -and (Get-HostArch) -ne "amd64") {
    throw "windows:ci is an x64-host contract. On ARM64, run windows:check:arm64, windows:build:arm64, windows:test:arm64, windows:test:unsupported:arm64, and windows:artifacts explicitly."
}

$targets = Get-SelectedTargets $Target
if ($Action -in @("test", "test-precommit", "test-unsupported", "test-mxc-real")) {
    foreach ($rustTarget in $targets) {
        Assert-NativeTestTarget $rustTarget
    }
}

if ($Action -in @("check", "lint", "build", "build-mxc-fixtures", "test", "test-precommit", "test-unsupported", "test-mxc-real", "test-mxc-boundary", "test-mxc-loopback", "test-mxc-network", "test-mxc-audit", "ci")) {
    $env:LIBCLANG_PATH = Resolve-LibclangPath
    Add-PathEntry $env:LIBCLANG_PATH
    Write-Host "==> LIBCLANG_PATH=$env:LIBCLANG_PATH"
    Configure-Arm64CrossBuild $targets
}

switch ($Action) {
    "package-z3" {
        foreach ($rustTarget in $targets) { Invoke-Z3Package $rustTarget }
    }
    "check" {
        foreach ($rustTarget in $targets) {
            Invoke-Check $rustTarget
        }
    }
    "lint" {
        foreach ($rustTarget in $targets) {
            Invoke-Lint $rustTarget
        }
    }
    "build" {
        foreach ($rustTarget in $targets) {
            Invoke-Build $rustTarget
        }
        Show-Artifacts $targets
    }
    "build-mxc-fixtures" {
        foreach ($rustTarget in $targets) {
            Invoke-VsCargo -RustTarget $rustTarget `
                -Z3Scope None -CargoArgs "cargo build --release -p openshell-driver-mxc --example mxc-forwarding-agent --target $rustTarget" `
                -LogName "build-$rustTarget-mxc-fixtures.log"
        }
    }
    "test" {
        foreach ($rustTarget in $targets) {
            Invoke-Test $rustTarget
        }
    }
    "test-precommit" {
        foreach ($rustTarget in $targets) {
            Invoke-PreCommitTest $rustTarget
        }
    }
    "test-unsupported" {
        foreach ($rustTarget in $targets) {
            Invoke-UnsupportedContractTests $rustTarget
        }
    }
    "test-mxc-boundary" {
        foreach ($rustTarget in $targets) {
            Assert-NativeTestTarget $rustTarget
            Invoke-VsCargo -RustTarget $rustTarget `
                -Z3Scope None -CargoArgs "cargo test --release -p openshell-mxc-boundary --lib --target $rustTarget -- --test-threads=1" `
                -LogName "test-$rustTarget-mxc-boundary.log"
        }
    }
    "test-mxc-loopback" {
        foreach ($rustTarget in $targets) {
            Assert-NativeTestTarget $rustTarget
            Invoke-VsCargo -RustTarget $rustTarget `
                -Z3Scope None -CargoArgs "cargo test --release -p openshell-mxc-boundary --lib --target $rustTarget native_same_container_loopback -- --ignored --nocapture --test-threads=1" `
                -LogName "test-$rustTarget-mxc-loopback.log"
        }
    }
    "test-mxc-network" {
        foreach ($rustTarget in $targets) {
            Assert-NativeTestTarget $rustTarget
            foreach ($testName in @('pc_https_egress_reads_injected_ca_bundle', 'pc_proxy_scopes_network_policy_to_socket_owner')) {
                Invoke-VsCargo -RustTarget $rustTarget `
                    -Z3Scope None -CargoArgs "cargo test --release -p openshell-driver-mxc --test wxc_exec_real --target $rustTarget $testName -- --ignored --exact --test-threads=1 --nocapture" `
                    -LogName "test-$rustTarget-$testName.log"
            }
        }
    }
    "test-mxc-audit" {
        foreach ($rustTarget in $targets) {
            Assert-NativeTestTarget $rustTarget
            Invoke-VsCargo -RustTarget $rustTarget `
                -Z3Scope None -CargoArgs "cargo test --release -p openshell-driver-mxc --lib --target $rustTarget etw_consumer::tests -- --test-threads=1 --nocapture" `
                -LogName "test-$rustTarget-mxc-audit-attribution.log"
            Invoke-VsCargo -RustTarget $rustTarget `
                -Z3Scope Server -CargoArgs "cargo test --release -p openshell-server --lib --target $rustTarget mxc_audit_example -- --nocapture" `
                -LogName "test-$rustTarget-mxc-audit-config.log"
            Invoke-VsCargo -RustTarget $rustTarget `
                -Z3Scope None -CargoArgs "cargo test --release -p openshell-driver-mxc --test windows_demo_examples --target $rustTarget -- --test-threads=1 --nocapture" `
                -LogName "test-$rustTarget-mxc-audit-examples.log"
            $package = Join-Path $TargetDir "mxc-ocsf-qualification-$rustTarget"
            New-Item -ItemType Directory -Force $package | Out-Null
            foreach ($binary in @('openshell-gateway.exe', 'openshell.exe', 'openshell-supervisor.exe', 'openshell-windows-sandbox.exe')) {
                Copy-Item -LiteralPath (Join-Path $TargetDir "$rustTarget/release/$binary") -Destination $package -Force
            }
            if (Test-SharedWindowsZ3 (Join-Path $package 'openshell-gateway.exe')) {
                Copy-Item -LiteralPath (Join-Path $TargetDir "$rustTarget/release/libz3.dll") -Destination $package -Force
            } elseif (Test-Path -LiteralPath (Join-Path $package 'libz3.dll')) {
                Remove-Item -LiteralPath (Join-Path $package 'libz3.dll')
            }
            foreach ($artifact in @('run-ocsf-audit.ps1', 'mxc-ocsf-audit.toml', 'ocsf-audit.yaml')) {
                Copy-Item -LiteralPath (Join-Path $RepoRoot "crates/openshell-driver-mxc/examples/$artifact") -Destination $package -Force
            }
            $wxc = $env:OPENSHELL_WXC_EXEC_PATH
            if (-not $wxc) { throw 'Set OPENSHELL_WXC_EXEC_PATH to the real MXC executor.' }
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $package 'run-ocsf-audit.ps1') `
                -WxcExecPath $wxc -ShareDir (Join-Path $package 'work')
            if ($LASTEXITCODE -ne 0) { throw "Live MXC audit qualification failed; results are in $package" }
        }
    }
    "test-mxc-real" {
        foreach ($rustTarget in $targets) {
            Invoke-MxcRealTests $rustTarget
        }
    }
    "artifacts" {
        Show-Artifacts $targets
    }
    "ci" {
        foreach ($rustTarget in $targets) {
            Invoke-Check $rustTarget
        }
        foreach ($rustTarget in $targets) {
            Invoke-Build $rustTarget
        }
        Invoke-PreCommitTest "x86_64-pc-windows-msvc"
        Invoke-UnsupportedContractTests "x86_64-pc-windows-msvc"
        Show-Artifacts $targets
    }
}
