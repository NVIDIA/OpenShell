# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Windows MSVC build wrapper used by the `windows:*` mise tasks.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("check", "build", "test", "test-unsupported", "artifacts", "ci")]
    [string] $Action,

    [Parameter(Position = 1)]
    [ValidateSet("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc", "all")]
    [string] $Target = "all",

    [string] $LogDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw "windows-msvc.ps1 requires a Windows MSVC host."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
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

$UnsupportedDriverPackageExcludes = "--exclude openshell-driver-docker --exclude openshell-driver-kubernetes --exclude openshell-driver-podman --exclude openshell-driver-vm"
$BundledZ3WorkspaceFeatures = "--features openshell-cli/bundled-z3,openshell-prover/bundled-z3"
$BundledZ3ServerFeatures = "--features openshell-server/bundled-z3,openshell-prover/bundled-z3"
$Z3WorkspaceFeatures = $BundledZ3WorkspaceFeatures
$Z3ServerFeatures = $BundledZ3ServerFeatures

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
    [Environment]::SetEnvironmentVariable("CMAKE_GENERATOR_aarch64_pc_windows_msvc", "Ninja", "Process")

    Write-Host "==> ARM64 cross-build toolchain"
    Write-Host "    clang-cl: $clangCl"
    Write-Host "    ninja:    $ninja"
    Write-Host "    Z3:       MSVC cl.exe with Ninja"
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

function Assert-NativeTestTarget([string] $RustTarget) {
    $targetArch = Get-VsTargetArch $RustTarget
    $hostArch = Get-HostArch
    if ($targetArch -ne $hostArch) {
        throw "Windows tests require a native runner. Target $RustTarget maps to $targetArch, but the host is $hostArch."
    }
}

function Get-SelectedTargets([string] $RequestedTarget) {
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

function Configure-Z3 {
    if ([string]::IsNullOrWhiteSpace($env:Z3_LIBRARY_PATH_OVERRIDE)) {
        Write-Host "==> Z3: bundled"
        return [pscustomobject]@{
            WorkspaceFeatures = $BundledZ3WorkspaceFeatures
            ServerFeatures = $BundledZ3ServerFeatures
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

    if (($env:PATH -split ";") -notcontains $libDir) {
        $env:PATH = "$libDir;$env:PATH"
    }

    Write-Host "==> Z3: system"
    Write-Host "    Z3_LIBRARY_PATH_OVERRIDE=$env:Z3_LIBRARY_PATH_OVERRIDE"
    Write-Host "    Z3_SYS_Z3_HEADER=$env:Z3_SYS_Z3_HEADER"

    return [pscustomobject]@{
        WorkspaceFeatures = ""
        ServerFeatures = ""
    }
}

function Invoke-VsCargo {
    param(
        [Parameter(Mandatory = $true)] [string] $RustTarget,
        [Parameter(Mandatory = $true)] [string] $CargoArgs,
        [Parameter(Mandatory = $true)] [string] $LogName
    )

    & rustup target add $RustTarget
    if ($LASTEXITCODE -ne 0) {
        throw "rustup target add $RustTarget failed"
    }

    $vsDevCmd = Resolve-VsDevCmd $RustTarget
    $targetArch = Get-VsTargetArch $RustTarget
    $hostArch = Get-HostArch
    $logPath = Join-Path $LogDir $LogName
    $environmentSetup = @(
        "set `"CARGO_TARGET_DIR=$TargetDir`"",
        "set `"CARGO_INCREMENTAL=0`"",
        "set `"RUSTC_WRAPPER=`""
    )
    if ($hostArch -eq "amd64" -and $RustTarget -eq "aarch64-pc-windows-msvc") {
        # Let cmake-rs select MSVC cl.exe for bundled Z3. AWS-LC selects
        # clang-cl inside its own ARM64 build script.
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

    $cmdWithLog = "$cmd > `"$logPath`" 2>&1"
    & cmd /v:on /d /c $cmdWithLog
    $exitCode = $LASTEXITCODE
    if (Test-Path $logPath) {
        Get-Content $logPath
    }
    if ($exitCode -ne 0) {
        throw "Command failed with exit code $exitCode. See $logPath"
    }
}

function Invoke-Check([string] $RustTarget) {
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -CargoArgs "cargo check --workspace $UnsupportedDriverPackageExcludes --target $RustTarget $Z3WorkspaceFeatures" `
        -LogName "build-$RustTarget-check.log"
}

function Invoke-Build([string] $RustTarget) {
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -CargoArgs "cargo build --release --target $RustTarget --bin openshell-gateway --bin openshell $Z3WorkspaceFeatures" `
        -LogName "build-$RustTarget-release.log"
}

function Invoke-Test([string] $RustTarget) {
    Assert-NativeTestTarget $RustTarget
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -CargoArgs "cargo test --workspace $UnsupportedDriverPackageExcludes --target $RustTarget --no-fail-fast $Z3WorkspaceFeatures" `
        -LogName "test-$RustTarget.log"
}

function Invoke-UnsupportedContractTests([string] $RustTarget) {
    Assert-NativeTestTarget $RustTarget

    $tests = @(
        "windows_compute_driver_stubs_report_unsupported",
        "windows_spawn_reports_unsupported"
    )
    foreach ($test in $tests) {
        Invoke-VsCargo `
            -RustTarget $RustTarget `
            -CargoArgs "cargo test -p openshell-server --target $RustTarget $test $Z3ServerFeatures" `
            -LogName "test-$RustTarget-unsupported-$test.log"
    }
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
        foreach ($binary in @("openshell-gateway.exe", "openshell.exe")) {
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
if ($Action -in @("test", "test-unsupported")) {
    foreach ($rustTarget in $targets) {
        Assert-NativeTestTarget $rustTarget
    }
}

if ($Action -in @("check", "build", "test", "test-unsupported", "ci")) {
    $z3Features = Configure-Z3
    $Z3WorkspaceFeatures = $z3Features.WorkspaceFeatures
    $Z3ServerFeatures = $z3Features.ServerFeatures
    $env:LIBCLANG_PATH = Resolve-LibclangPath
    Add-PathEntry $env:LIBCLANG_PATH
    Write-Host "==> LIBCLANG_PATH=$env:LIBCLANG_PATH"
    Configure-Arm64CrossBuild $targets
}

switch ($Action) {
    "check" {
        foreach ($rustTarget in $targets) {
            Invoke-Check $rustTarget
        }
    }
    "build" {
        foreach ($rustTarget in $targets) {
            Invoke-Build $rustTarget
        }
        Show-Artifacts $targets
    }
    "test" {
        foreach ($rustTarget in $targets) {
            Invoke-Test $rustTarget
        }
    }
    "test-unsupported" {
        foreach ($rustTarget in $targets) {
            Invoke-UnsupportedContractTests $rustTarget
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
        Invoke-Test "x86_64-pc-windows-msvc"
        Invoke-UnsupportedContractTests "x86_64-pc-windows-msvc"
        Show-Artifacts $targets
    }
}
