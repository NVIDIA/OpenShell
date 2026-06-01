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

function Resolve-VsDevCmd {
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
        $found = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find "Common7\Tools\VsDevCmd.bat" | Select-Object -First 1
        if ($found -and (Test-Path $found)) {
            return (Resolve-Path $found).Path
        }
    }

    $programFiles = @(
        [Environment]::GetEnvironmentVariable("ProgramFiles"),
        [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    ) | Where-Object { $_ }
    $versions = @("18", "17")
    $editions = @("Enterprise", "Professional", "Community", "BuildTools")
    foreach ($root in $programFiles) {
        foreach ($version in $versions) {
            foreach ($edition in $editions) {
                $candidate = Join-Path $root "Microsoft Visual Studio\$version\$edition\Common7\Tools\VsDevCmd.bat"
                if (Test-Path $candidate) {
                    return (Resolve-Path $candidate).Path
                }
            }
        }
    }

    throw "Could not find VsDevCmd.bat. Install Visual Studio Build Tools, or set OPENSHELL_VSDEVCMD."
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

    $vsDevCmd = Resolve-VsDevCmd
    $targetArch = Get-VsTargetArch $RustTarget
    $hostArch = Get-HostArch
    $logPath = Join-Path $LogDir $LogName
    $cmd = "call `"$vsDevCmd`" -arch=$targetArch -host_arch=$hostArch && set `"CARGO_TARGET_DIR=$TargetDir`" && set `"CARGO_INCREMENTAL=0`" && set `"RUSTC_WRAPPER=`" && $CargoArgs"

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
        -CargoArgs "cargo check --workspace $UnsupportedDriverPackageExcludes --target $RustTarget" `
        -LogName "build-$RustTarget-check.log"
}

function Invoke-Build([string] $RustTarget) {
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -CargoArgs "cargo build --release --target $RustTarget --bin openshell-gateway --bin openshell" `
        -LogName "build-$RustTarget-release.log"
}

function Invoke-Test([string] $RustTarget) {
    if ($RustTarget -ne "x86_64-pc-windows-msvc") {
        throw "Windows ARM64 tests require a native ARM64 runner and are not part of this build-only lane."
    }
    Invoke-VsCargo `
        -RustTarget $RustTarget `
        -CargoArgs "cargo test --workspace $UnsupportedDriverPackageExcludes --target $RustTarget --no-fail-fast" `
        -LogName "test-$RustTarget.log"
}

function Invoke-UnsupportedContractTests([string] $RustTarget) {
    if ($RustTarget -ne "x86_64-pc-windows-msvc") {
        throw "Unsupported-driver contract tests run only on the native x64 Windows lane."
    }

    $tests = @(
        "windows_compute_driver_stubs_report_unsupported",
        "windows_spawn_reports_unsupported"
    )
    foreach ($test in $tests) {
        Invoke-VsCargo `
            -RustTarget $RustTarget `
            -CargoArgs "cargo test -p openshell-server --target $RustTarget $test" `
            -LogName "test-$RustTarget-unsupported-$test.log"
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
            $hash = Get-FileHash $path -Algorithm SHA256
            $rows += [pscustomobject]@{
                Target = $rustTarget
                Binary = $binary
                Size = $item.Length
                SHA256 = $hash.Hash
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

$targets = Get-SelectedTargets $Target

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
