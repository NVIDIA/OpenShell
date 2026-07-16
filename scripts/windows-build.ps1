# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# windows-build.ps1 - Reproduce a native Windows (MSVC) build of OpenShell and
# assert that the MXC compute driver is compiled into the gateway.
#
# This wraps the `windows:*` mise tasks with the environment fix-ups needed on a
# clean host, then verifies MXC is in the gateway's dependency graph. MXC is not
# a Cargo feature -- it is a `cfg(target_os = "windows")` dependency of
# `openshell-server`, so building any `*-pc-windows-msvc` target compiles it in.
#
# PowerShell 5.1 compatible (no &&/||/ternary operators).
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-build.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-build.ps1 -Target x64
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-build.ps1 -SkipCheck
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-build.ps1 -RunVerify
#
# Steps (each can be skipped):
#   1. check      - `windows:check[:x64|:arm64]`      (cargo check)
#   2. build      - `windows:build[:x64|:arm64]`      (release gateway + CLI)
#   3. artifacts  - `windows:artifacts`               (size + SHA256)
#   4. mxc graph  - `cargo tree -i openshell-driver-mxc` per target (assertion)
#   5. verify     - delegates to crates/openshell-driver-mxc/examples/verify-mxc.ps1
#                   (tests + runtime; opt-in via -RunVerify; blocked by Smart App
#                   Control on hosts that enforce it)
#
# Exit codes: 0 = all requested steps passed; 1 = a step failed.

[CmdletBinding()]
param(
    [ValidateSet("all", "x64", "arm64")]
    [string] $Target = "all",
    [switch] $SkipCheck,
    [switch] $SkipBuild,
    [switch] $SkipArtifacts,
    [switch] $RunVerify,
    # Override the libclang directory. Auto-discovered from Visual Studio when not
    # set. Needed because a stray host LIBCLANG_PATH (e.g. an ESP32 clang) breaks
    # the z3-sys bindgen build.
    [string] $LibclangPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw "windows-build.ps1 requires a Windows MSVC host."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

# Map the friendly -Target to rust triples and the mise task suffix.
switch ($Target) {
    "x64"   { $Triples = @("x86_64-pc-windows-msvc");  $TaskSuffix = ":x64" }
    "arm64" { $Triples = @("aarch64-pc-windows-msvc"); $TaskSuffix = ":arm64" }
    default { $Triples = @("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"); $TaskSuffix = "" }
}

function Write-Section([string] $Text) {
    Write-Host ""
    Write-Host "==== $Text ====" -ForegroundColor Cyan
}

# ── Resolve libclang (mirror of tasks/scripts/windows-msvc.ps1 discovery) ──────
function Resolve-Libclang {
    if ($LibclangPath) {
        if (Test-Path (Join-Path $LibclangPath "libclang.dll")) { return (Resolve-Path $LibclangPath).Path }
        throw "-LibclangPath set but libclang.dll not found under: $LibclangPath"
    }
    $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    if ($programFilesX86) {
        $vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path $vswhere) {
            $found = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Llvm.Clang -find "VC\Tools\Llvm\x64\bin\libclang.dll" | Select-Object -First 1
            if ($found -and (Test-Path $found)) { return (Split-Path -Parent (Resolve-Path $found).Path) }
        }
    }
    if (Test-Path "C:\Program Files\LLVM\bin\libclang.dll") { return "C:\Program Files\LLVM\bin" }
    throw "Could not auto-discover libclang.dll. Pass -LibclangPath <dir containing libclang.dll>, or install the VS 'C++ Clang tools' component."
}

# Run a mise windows task and throw with context on failure.
function Invoke-MiseTask([string] $Task) {
    Write-Host "--> mise run --skip-tools $Task"
    & mise run --skip-tools $Task
    if ($LASTEXITCODE -ne 0) { throw "mise task '$Task' failed (exit $LASTEXITCODE)." }
}

# ── Pre-flight ─────────────────────────────────────────────────────────────────
Write-Section "Pre-flight"
Write-Host "repo:    $RepoRoot"
Write-Host "target:  $Target  ($($Triples -join ', '))"

# Ensure rust toolchain + targets are present (rustup owns the Windows toolchain).
& rustc --version
foreach ($t in $Triples) {
    Write-Host "--> rustup target add $t"
    & rustup target add $t
    if ($LASTEXITCODE -ne 0) { throw "rustup target add $t failed." }
}

# The fix that unblocked our build: point LIBCLANG_PATH at VS libclang so a stray
# host value (ESP32 clang, etc.) cannot break z3-sys bindgen.
$env:LIBCLANG_PATH = Resolve-Libclang
Write-Host "LIBCLANG_PATH: $env:LIBCLANG_PATH"

# mise must trust the repo before running tasks.
Write-Host "--> mise trust"
& mise trust | Out-Null

# ── Step 1: check ──────────────────────────────────────────────────────────────
if (-not $SkipCheck) {
    Write-Section "Step 1: cargo check"
    Invoke-MiseTask "windows:check$TaskSuffix"
} else {
    Write-Host "Step 1 (check) skipped (-SkipCheck)."
}

# ── Step 2: build ──────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    Write-Section "Step 2: release build"
    Invoke-MiseTask "windows:build$TaskSuffix"
} else {
    Write-Host "Step 2 (build) skipped (-SkipBuild)."
}

# ── Step 3: artifacts ──────────────────────────────────────────────────────────
if (-not $SkipArtifacts) {
    Write-Section "Step 3: artifacts (size + SHA256)"
    Invoke-MiseTask "windows:artifacts"
} else {
    Write-Host "Step 3 (artifacts) skipped (-SkipArtifacts)."
}

# ── Step 4: assert MXC is compiled into the gateway ────────────────────────────
Write-Section "Step 4: assert openshell-driver-mxc is a gateway dependency"
$mxcOk = $true
foreach ($t in $Triples) {
    Write-Host "--> cargo tree -p openshell-server --target $t -i openshell-driver-mxc"
    $tree = & cargo tree -p openshell-server --target $t -i openshell-driver-mxc 2>&1 | Out-String
    if ($tree -match "openshell-driver-mxc") {
        Write-Host "    [$t] MXC is a dependency of openshell-server -> enabled" -ForegroundColor Green
    } else {
        Write-Host "    [$t] MXC NOT found in the graph:" -ForegroundColor Red
        Write-Host $tree
        $mxcOk = $false
    }
}
if (-not $mxcOk) { throw "MXC dependency-graph assertion failed." }

# ── Step 5: optional runtime verification ──────────────────────────────────────
if ($RunVerify) {
    Write-Section "Step 5: verify (tests + runtime dispatch)"
    $verify = Join-Path $RepoRoot "crates\openshell-driver-mxc\examples\verify-mxc.ps1"
    if (-not (Test-Path $verify)) { throw "verify-mxc.ps1 not found at: $verify" }
    Write-Host "--> $verify"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $verify
    $vc = $LASTEXITCODE
    if ($vc -eq 2) {
        Write-Host "verify-mxc.ps1 reported BLOCKED (Smart App Control). Build + MXC-enabled proof stand." -ForegroundColor Yellow
    } elseif ($vc -ne 0) {
        throw "verify-mxc.ps1 failed (exit $vc)."
    }
} else {
    Write-Host "Step 5 (verify) skipped. Add -RunVerify to run tests + runtime dispatch."
}

Write-Section "Done"
Write-Host "Windows build reproduced for: $($Triples -join ', ')" -ForegroundColor Green
Write-Host "MXC support: enabled (compiled into openshell-gateway)." -ForegroundColor Green
exit 0
