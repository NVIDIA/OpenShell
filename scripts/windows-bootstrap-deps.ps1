# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Idempotent bootstrap for OpenShell's build-only Windows MSVC lane.
#
# Installs the toolchain required by `mise run --skip-tools windows:*`:
#   - Visual Studio 2022 (Build Tools workload) with VC x64 + ARM64 tools,
#     a Windows 11 SDK, the C++ Clang toolset (libclang.dll), and CMake.
#   - rustup + Rust 1.95.0 MSVC toolchain, x64 + ARM64 targets, rustfmt + clippy.
#   - mise, protoc, and a PATH-discoverable cmake.
#   - A real Python 3 interpreter: the bundled-z3 build runs Z3's CMake, which
#     does find_package(Python3) for build-time codegen. The Windows Store
#     "python" alias stub does not satisfy this.
#
# Safe to run twice: every dependency is detect-then-install. This script is the
# reproduction artifact for provisioning the host; it is intentionally not
# committed to the repository.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile = Join-Path $ScriptDir "windows-bootstrap-deps.log"
$WorkDir = Join-Path $env:TEMP "openshell-bootstrap"
if (-not (Test-Path $WorkDir)) {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
}

# ---------------------------------------------------------------------------
# Pinned versions (kept in sync with mise.toml where relevant).
# ---------------------------------------------------------------------------
$RustVersion = "1.95.0"
$RustToolchain = "$RustVersion-x86_64-pc-windows-msvc"
$RustTargets = @("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")
$ProtocVersion = "29.6"  # matches mise.toml [tools] protoc
# System Python 3 for Z3's CMake codegen. Any modern 3.x satisfies bundled-z3;
# this need not match mise.toml's managed-venv pin (3.14.5).
$PythonWingetId = "Python.Python.3.13"

# Visual Studio components the Windows MSVC lane relies on. Checked individually
# via vswhere so a partially-provisioned install only pulls the missing pieces.
$VsComponents = @(
    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
    "Microsoft.VisualStudio.Component.VC.Tools.ARM64",
    "Microsoft.VisualStudio.Component.Windows11SDK.26100",
    "Microsoft.VisualStudio.Component.VC.Llvm.Clang",
    "Microsoft.VisualStudio.Component.VC.Llvm.ClangToolset",
    "Microsoft.VisualStudio.Component.VC.CMake.Project",
    # Spectre-mitigated MSVC static libs, required by msvc_spectre_libs
    # (pulled in transitively by the bundled-z3 -> z3-sys build). Without these
    # `cargo check` fails: "No spectre-mitigated libs were found."
    # NOTE: these IDs are version-pinned to the MSVC toolset 14.44 / VS 17.14.
    # If the installed toolset moves, update the "14.44.17.14" segment to match
    # (format: VC.<toolsetMajor>.<toolsetMinor>.<vsMajor>.<vsMinor>.<arch>.Spectre).
    "Microsoft.VisualStudio.Component.VC.14.44.17.14.x86.x64.Spectre",
    "Microsoft.VisualStudio.Component.VC.14.44.17.14.ARM64.Spectre"
)

# ---------------------------------------------------------------------------
# Logging + PATH helpers.
# ---------------------------------------------------------------------------
try {
    Start-Transcript -Path $LogFile -Append | Out-Null
} catch {
    Write-Warning "Could not start transcript: $_"
}

function Write-Step([string] $Message) {
    Write-Host "==> $Message"
}

function Refresh-Path {
    # Re-read machine + user PATH so tools installed earlier in this run are
    # resolvable by Get-Command / native invocation without a new shell.
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"
    # rustup/cargo land here before the machine PATH catches up.
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if ((Test-Path $cargoBin) -and (($env:Path -split ";") -notcontains $cargoBin)) {
        $env:Path = "$cargoBin;$env:Path"
    }
}

function Add-MachinePath([string] $Dir) {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $entries = $machine -split ";" | Where-Object { $_ }
    if ($entries -notcontains $Dir) {
        Write-Step "Adding to machine PATH: $Dir"
        [Environment]::SetEnvironmentVariable("Path", ($machine.TrimEnd(";") + ";" + $Dir), "Machine")
    }
    Refresh-Path
}

function Test-Tool([string] $Name) {
    Refresh-Path
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-Vswhere {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) { return $vswhere }
    return $null
}

# ---------------------------------------------------------------------------
# 1. Visual Studio Build Tools (VC x64/ARM64, SDK, Clang toolset, CMake).
# ---------------------------------------------------------------------------
function Install-VisualStudio {
    Write-Step "Checking Visual Studio build components"
    $vswhere = Get-Vswhere
    $installPath = $null
    if ($vswhere) {
        $installPath = & $vswhere -latest -products * -property installationPath 2>$null | Select-Object -First 1
    }

    $missing = @()
    foreach ($comp in $VsComponents) {
        $present = $false
        if ($vswhere) {
            $hit = & $vswhere -latest -products * -requires $comp -property installationPath 2>$null | Select-Object -First 1
            if ($hit) { $present = $true }
        }
        if ($present) {
            Write-Host "    present: $comp"
        } else {
            Write-Host "    MISSING: $comp"
            $missing += $comp
        }
    }

    if ($missing.Count -eq 0 -and $installPath) {
        Write-Step "Visual Studio components already satisfied at $installPath"
        return
    }

    $setup = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\setup.exe"

    if ($installPath -and (Test-Path $setup)) {
        # Modify the existing install: add only the missing components. The
        # install path contains spaces, so quote it in the command line —
        # Start-Process -ArgumentList (array) does not quote elements itself.
        # NOTE: the installed VS Installer setup.exe does not accept --wait
        # (that flag is only valid on the vs_BuildTools bootstrapper below).
        # Start-Process -Wait blocks on the quiet modify until it completes.
        $addArgs = ($missing | ForEach-Object { "--add $_" }) -join " "
        $argLine = "modify --installPath `"$installPath`" --quiet --norestart --nocache $addArgs"
        Write-Step "Modifying Visual Studio at $installPath (adding $($missing.Count) component(s))"
        Write-Host "    setup.exe $argLine"
        $proc = Start-Process -FilePath $setup -ArgumentList $argLine -Wait -PassThru
    } else {
        # No existing install: bootstrap VS Build Tools from scratch.
        $bootstrapper = Join-Path $WorkDir "vs_BuildTools.exe"
        Write-Step "Downloading VS Build Tools bootstrapper"
        Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_BuildTools.exe" -OutFile $bootstrapper -UseBasicParsing
        $addArgs = ($VsComponents | ForEach-Object { "--add $_" }) -join " "
        $argLine = "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended $addArgs"
        Write-Step "Installing VS Build Tools with required components"
        Write-Host "    vs_BuildTools.exe $argLine"
        $proc = Start-Process -FilePath $bootstrapper -ArgumentList $argLine -Wait -PassThru
    }

    $code = $proc.ExitCode
    # 0 = success, 3010 = success but reboot required, 1641 = success reboot initiated.
    if ($code -eq 0 -or $code -eq 3010 -or $code -eq 1641) {
        Write-Step "Visual Studio installer returned exit $code; waiting for servicing to settle"
    } else {
        throw "Visual Studio installer failed with exit code $code. See VS install logs under %TEMP%."
    }

    # The VS Installer can detach into a background servicing process that keeps
    # applying payloads after setup.exe returns. Block until those processes exit
    # so downstream verification sees a fully-provisioned install.
    $deadline = (Get-Date).AddMinutes(45)
    while (Get-Process -Name setup, vs_installer, vs_installerservice -ErrorAction SilentlyContinue) {
        if ((Get-Date) -gt $deadline) {
            throw "Timed out waiting for Visual Studio servicing processes to exit."
        }
        Start-Sleep -Seconds 10
    }

    # Confirm the components actually landed before proceeding.
    $vswhere2 = Get-Vswhere
    foreach ($comp in $VsComponents) {
        $hit = & $vswhere2 -latest -products * -requires $comp -property installationPath 2>$null | Select-Object -First 1
        if (-not $hit) {
            throw "VS component still missing after install: $comp"
        }
    }
    Write-Step "Visual Studio components verified"
}

# ---------------------------------------------------------------------------
# 2. rustup + Rust 1.95.0 MSVC toolchain, both targets, rustfmt + clippy.
# ---------------------------------------------------------------------------
function Install-Rust {
    Write-Step "Checking rustup"
    if (-not (Test-Tool "rustup")) {
        $rustupInit = Join-Path $WorkDir "rustup-init.exe"
        Write-Step "Downloading rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit -UseBasicParsing
        Write-Step "Installing rustup with default toolchain $RustToolchain"
        & $rustupInit -y --default-toolchain $RustToolchain --profile default
        if ($LASTEXITCODE -ne 0) { throw "rustup-init failed with exit code $LASTEXITCODE" }
        Refresh-Path
    } else {
        Write-Host "    present: rustup"
    }

    # Ensure cargo's bin dir is on the persistent machine PATH so tools spawned
    # in fresh shells (e.g. mise running the windows:* wrapper) can find rustup.
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if (Test-Path $cargoBin) { Add-MachinePath $cargoBin }

    # NOTE: `--component` takes one value per flag; `--component rustfmt clippy`
    # would parse `clippy` as a second toolchain name.
    Write-Step "Ensuring toolchain $RustToolchain with rustfmt + clippy"
    & rustup toolchain install $RustToolchain --component rustfmt --component clippy
    if ($LASTEXITCODE -ne 0) { throw "rustup toolchain install failed with exit code $LASTEXITCODE" }

    & rustup default $RustToolchain
    if ($LASTEXITCODE -ne 0) { throw "rustup default failed with exit code $LASTEXITCODE" }

    & rustup component add rustfmt clippy --toolchain $RustToolchain
    if ($LASTEXITCODE -ne 0) { throw "rustup component add failed with exit code $LASTEXITCODE" }

    foreach ($target in $RustTargets) {
        Write-Step "Adding target $target"
        & rustup target add $target --toolchain $RustToolchain
        if ($LASTEXITCODE -ne 0) { throw "rustup target add $target failed with exit code $LASTEXITCODE" }
    }
}

# ---------------------------------------------------------------------------
# 3. mise (task runner) via winget.
# ---------------------------------------------------------------------------
function Install-Mise {
    Write-Step "Checking mise"
    if (Test-Tool "mise") {
        Write-Host "    present: mise"
        return
    }
    if (-not (Test-Tool "winget")) {
        throw "winget is required to install mise but was not found."
    }
    Write-Step "Installing mise via winget (jdx.mise)"
    # Pin --source winget: the msstore source can fail cert validation and make
    # the package ambiguous.
    winget install --id jdx.mise --exact --source winget --silent --accept-package-agreements --accept-source-agreements
    Refresh-Path
    if (-not (Test-Tool "mise")) {
        throw "mise not found on PATH after winget install."
    }
}

# Trust the repo's mise config. A fresh mise refuses to run repo tasks until the
# config is trusted ("Config files ... are not trusted. Trust them with `mise
# trust`."). Idempotent: re-trusting an already-trusted config is a no-op.
function Trust-MiseConfig {
    $repoRoot = Split-Path -Parent $ScriptDir
    $config = Join-Path $repoRoot "mise.toml"
    if (-not (Test-Path $config)) {
        Write-Warning "mise.toml not found at $config; skipping mise trust"
        return
    }
    Write-Step "Trusting mise config: $config"
    & mise trust $config
    if ($LASTEXITCODE -ne 0) { throw "mise trust failed with exit code $LASTEXITCODE" }
}

# ---------------------------------------------------------------------------
# 4. protoc (pinned to mise's version) via direct GitHub release download.
# ---------------------------------------------------------------------------
function Install-Protoc {
    Write-Step "Checking protoc"
    if (Test-Tool "protoc") {
        Write-Host "    present: protoc ($((& protoc --version) 2>$null))"
        return
    }
    $installDir = "C:\tools\protoc"
    $binDir = Join-Path $installDir "bin"
    $zip = Join-Path $WorkDir "protoc-$ProtocVersion-win64.zip"
    $url = "https://github.com/protocolbuffers/protobuf/releases/download/v$ProtocVersion/protoc-$ProtocVersion-win64.zip"
    Write-Step "Downloading protoc $ProtocVersion"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    if (Test-Path $installDir) { Remove-Item -Recurse -Force $installDir }
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Write-Step "Extracting protoc to $installDir"
    Expand-Archive -Path $zip -DestinationPath $installDir -Force
    Add-MachinePath $binDir
    if (-not (Test-Tool "protoc")) {
        throw "protoc not found on PATH after install (expected in $binDir)."
    }
}

# ---------------------------------------------------------------------------
# 5. cmake on PATH (z3-sys bundled-z3 build uses the cmake crate).
# ---------------------------------------------------------------------------
function Install-Cmake {
    Write-Step "Checking cmake"
    if (Test-Tool "cmake") {
        Write-Host "    present: cmake ($((& cmake --version | Select-Object -First 1) 2>$null))"
        return
    }
    if (-not (Test-Tool "winget")) {
        throw "winget is required to install cmake but was not found."
    }
    Write-Step "Installing cmake via winget (Kitware.CMake)"
    winget install --id Kitware.CMake --exact --source winget --silent --accept-package-agreements --accept-source-agreements
    Refresh-Path
    if (-not (Test-Tool "cmake")) {
        # winget may add CMake to PATH only after a fresh shell; add its default bin.
        $cmakeBin = "C:\Program Files\CMake\bin"
        if (Test-Path (Join-Path $cmakeBin "cmake.exe")) {
            Add-MachinePath $cmakeBin
        }
    }
    if (-not (Test-Tool "cmake")) {
        throw "cmake not found on PATH after winget install."
    }
}

# ---------------------------------------------------------------------------
# 6. A real Python 3 interpreter (z3-sys bundled-z3 -> Z3 CMake find_package).
# ---------------------------------------------------------------------------
# NOTE: mise.toml pins python 3.14.5, but that provisions mise's managed venv;
# the windows:* lane runs with --skip-tools, so it needs a system Python 3 that
# CMake's FindPython3 can locate (PATH + HKLM\SOFTWARE\Python\PythonCore). A
# machine-scoped install lands ahead of the non-functional Windows Store alias.
function Test-RealPython {
    # The Windows Store "python" is an execution-alias stub that is not a usable
    # interpreter for CMake. Treat only a real interpreter (resolvable
    # sys.executable outside WindowsApps) as present.
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $cmd) { return $false }
    if ($cmd.Source -like "*\WindowsApps\*") { return $false }
    try {
        $exe = & python -c "import sys; print(sys.executable)" 2>$null
        return ($LASTEXITCODE -eq 0 -and $exe -and $exe -notlike "*\WindowsApps\*")
    } catch {
        return $false
    }
}

function Install-Python {
    Write-Step "Checking Python 3"
    if (Test-RealPython) {
        Write-Host "    present: python ($((& python --version) 2>$null))"
        return
    }
    if (-not (Test-Tool "winget")) {
        throw "winget is required to install Python 3 but was not found."
    }
    Write-Step "Installing Python 3 via winget ($PythonWingetId, machine scope)"
    winget install --id $PythonWingetId --exact --source winget --scope machine `
        --silent --accept-package-agreements --accept-source-agreements
    Refresh-Path
    if (-not (Test-RealPython)) {
        throw "A real Python 3 interpreter was not found on PATH after install."
    }
}

# ---------------------------------------------------------------------------
# Verification summary.
# ---------------------------------------------------------------------------
function Show-Verification {
    Write-Host ""
    Write-Step "Verification"
    Refresh-Path

    function Report([string] $Label, [scriptblock] $Action) {
        # Discard stderr: rustup ("info: syncing channel updates ...") and mise
        # ("[WARN] migrate: ...") write progress/warnings there and would
        # otherwise be misreported as failures. Judge success by exit code.
        # Let the command run to completion, then take the first non-empty line
        # for display. Piping into `Select-Object -First 1` *inside* the block
        # would truncate the pipe and terminate the exe early (nonzero exit).
        $global:LASTEXITCODE = 0
        try {
            $lines = @((& $Action 2>$null | Out-String) -split "`r?`n" | Where-Object { $_.Trim() })
            $first = if ($lines.Count -gt 0) { $lines[0].Trim() } else { "" }
            if ($LASTEXITCODE -eq 0 -and $first) {
                Write-Host ("  [OK]   {0}: {1}" -f $Label, $first)
            } else {
                Write-Host ("  [FAIL] {0}: exit=$LASTEXITCODE output='{1}'" -f $Label, $first)
            }
        } catch {
            Write-Host ("  [FAIL] {0}: {1}" -f $Label, $_.Exception.Message)
        }
    }

    Report "rustc"   { rustc --version }
    Report "cargo"   { cargo --version }
    Report "targets" { (rustup target list --installed) -join ", " }
    Report "mise"    { mise --version }
    Report "protoc"  { protoc --version }
    Report "cmake"   { cmake --version }
    Report "python"  { python --version }

    $vswhere = Get-Vswhere
    if ($vswhere) {
        $ip = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null | Select-Object -First 1
        if ($ip) {
            $vsdev = Join-Path $ip "Common7\Tools\VsDevCmd.bat"
            Write-Host ("  [{0}] VsDevCmd.bat: {1}" -f $(if (Test-Path $vsdev) { "OK" } else { "FAIL" }), $vsdev)
            $allCl = Get-ChildItem (Join-Path $ip "VC\Tools\MSVC") -Recurse -Filter cl.exe -ErrorAction SilentlyContinue
            $cl = @($allCl | Where-Object { $_.FullName -match "Hostx64\\x64\\" }) | Select-Object -First 1
            if (-not $cl) { $cl = $allCl | Select-Object -First 1 }
            Write-Host ("  [{0}] cl.exe: {1}" -f $(if ($cl) { "OK" } else { "FAIL" }), $(if ($cl) { $cl.FullName } else { "not found" }))
            # Prefer the x64 toolset's libclang.dll — this is the one the
            # windows-msvc.ps1 wrapper's Resolve-LibclangPath resolves on an x64 host.
            $allLibclang = Get-ChildItem (Join-Path $ip "VC\Tools\Llvm") -Recurse -Filter libclang.dll -ErrorAction SilentlyContinue
            $libclang = @($allLibclang | Where-Object { $_.FullName -match "\\Llvm\\x64\\bin\\" }) | Select-Object -First 1
            if (-not $libclang) { $libclang = $allLibclang | Select-Object -First 1 }
            Write-Host ("  [{0}] libclang.dll: {1}" -f $(if ($libclang) { "OK" } else { "FAIL" }), $(if ($libclang) { $libclang.FullName } else { "not found" }))
        } else {
            Write-Host "  [FAIL] VS install path with VC.Tools.x86.x64 not found"
        }
    } else {
        Write-Host "  [FAIL] vswhere.exe not found"
    }
}

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
try {
    Write-Step "OpenShell Windows build-deps bootstrap starting ($(Get-Date -Format o))"
    Write-Step "Log: $LogFile"

    Install-VisualStudio
    Install-Rust
    Install-Mise
    Trust-MiseConfig
    Install-Protoc
    Install-Cmake
    Install-Python
    Show-Verification

    Write-Step "Bootstrap complete."
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
