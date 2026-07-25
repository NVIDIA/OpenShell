---
name: build-openshell-mxc-windows
description: Auto-executable build skill that forks OpenShell into a sibling directory and produces Windows-native x64 (x86_64-pc-windows-msvc) and ARM64 (aarch64-pc-windows-msvc) binaries on a Windows 11 26100+ host. Scope is build-only — cross-compilation, minimal Windows compatibility shims, and ARM64 CI scaffolding. Does not implement an MXC compute driver, policy translation, an MSI installer, or a supervisor port. Trigger keywords - build openshell mxc windows, openshell windows build, x64 build, arm64 build, windows msvc, openshell-mxc fork, native windows openshell, MXC build.
---

# Build OpenShell-MXC for Windows (x64 + ARM64)

Auto-executable skill. Forks the OpenShell repository into a sibling directory, applies the minimum Windows compatibility shims required to compile, and produces native binaries for `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`.

This skill covers only the build slice. It does **not** implement the MXC compute driver, policy translation, AppContainer wiring, supervisor port, MSI installer, or Windows Service registration. Those are handled by sibling skills (to be created).

## Scope

In scope:

- `x86_64-pc-windows-msvc` compilation
- `aarch64-pc-windows-msvc` compilation
- Audit and cfg-gate Unix-only dependencies in `openshell-server` and shared crates so the workspace compiles to Windows MSVC
- Keep Docker, Kubernetes, Podman, and VM compute crates in the Windows build graph as stubs that return "unsupported" at runtime
- Add a Windows-specific mise task lane (`windows:*`) that wraps MSVC builds without changing the Linux `mise run ci` path
- `cargo test` compiles and passes on a native x64 or ARM64 Windows host for non-Linux-gated tests
- Scaffold an ARM64 CI workflow (job definition only; runner provisioning is operator work)

Out of scope (defer to follow-on skills):

- New MXC compute driver crate
- OpenShell → MXC policy translation
- Windows network and credential integration
- Sandbox supervisor Windows port
- Docker, Kubernetes, Podman, or VM runtime support on Windows
- MSI installer, Windows Service registration, WinGet manifest

The Linux build must remain green at every commit. All Windows-specific code must be behind `#[cfg(target_os = "windows")]` and Linux-only code behind `#[cfg(target_os = "linux")]` or `#[cfg(unix)]`.

## Prerequisites

The skill targets a **Windows 11 host with CurrentBuild ≥ 26100**. Because the scope is compilation only, the skill warns rather than aborts when any of the items below is missing — a `cargo check` attempt can still surface useful information on a less-than-ideal host. Recommended:

| Requirement | Check | Install hint |
|---|---|---|
| Windows 11 build ≥ 26100 | `[System.Environment]::OSVersion.Version` | OS update |
| Visual Studio 2022 or newer with **MSVC v143** + **Windows 11 SDK** | `where.exe cl.exe` from a VS Developer PowerShell | Include the x64/x86 and ARM64 C++ tools. The wrapper discovers installed release directories such as `18` and `2022`. |
| Visual C++ ARM64 Spectre-mitigated libraries | `vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Runtimes.ARM64.Spectre -property installationPath` | Required by ARM64 dependencies that select the Spectre runtime. |
| Visual C++ Clang and CMake tools | `where.exe clang-cl.exe`; `where.exe cmake.exe` | `bindgen` needs host-native `libclang.dll`; ARM64 crypto crates use `clang-cl`; bundled Z3 uses CMake's Visual Studio generator with native MSVC for x64-to-ARM64 builds. |
| Rust ≥ 1.88 via rustup with MSVC targets | `rustc --version` | `winget install Rustlang.Rustup` |
| mise CLI for task orchestration only | `mise --version` | https://mise.jdx.dev/installing-mise.html |
| Git ≥ 2.40 | `git --version` | `winget install Git.Git` |
| Windows PowerShell 5.1+ or PowerShell 7+ | `$PSVersionTable.PSVersion` | Built into Windows; PowerShell 7 optional |

The Windows mise lane shells into Visual Studio's developer environment before invoking Cargo, so commands can run from an ordinary PowerShell session if Visual Studio Build Tools are discoverable. Use rustup for the Rust toolchain and MSVC targets; mise is only the task runner for the Windows lane. In CI, prefer `mise run --skip-tools windows:*` so Linux tool installation remains untouched.

## Inputs

The skill reads these environment variables (PowerShell syntax):

| Variable | Default | Purpose |
|---|---|---|
| `$env:OPENSHELL_UPSTREAM` | `https://github.com/NVIDIA/OpenShell.git` | Upstream Git remote to fork from. Override to use a local path or GitLab mirror. |
| `$env:OPENSHELL_MXC_FORK_DIR` | `C:\Users\$env:USERNAME\openshell-mxc` | Sibling directory for the fork. Must not exist. |
| `$env:OPENSHELL_WXC_EXEC_PATH` | unset | Optional path to `wxc-exec.exe`. Validated for existence and architecture match only. Not used in this build-only skill. |
| `$env:OPENSHELL_MXC_SKIP_ARM64` | `0` | Set to `1` to skip aarch64 build (e.g., for fast x64-only iterations). |
| `$env:OPENSHELL_MXC_FORK_BRANCH` | `windows-mxc-build` | Branch name created in the fork. |
| `$env:Z3_SYS_BUNDLED_DIR_OVERRIDE` | pinned source cached under `CARGO_TARGET_DIR` when explicit, otherwise `%LOCALAPPDATA%\OpenShell\cache\z3` | Reuse an existing Z3 source tree containing `src/api/z3.h`; otherwise the wrapper fetches and caches the pinned revision automatically. |

## Workflow

The skill runs the following checklist top-to-bottom. Each step is idempotent; re-running the skill is safe once the fork exists.

```
[ ] Step 1: Verify host preconditions
[ ] Step 2: Install Windows MSVC Rust targets
[ ] Step 3: Fork OpenShell into the sibling directory
[ ] Step 4: Apply minimum Windows compatibility shims (cfg gating)
[ ] Step 5: Add Windows mise task lane
[ ] Step 6: mise check on x86_64-pc-windows-msvc
[ ] Step 7: mise check on aarch64-pc-windows-msvc
[ ] Step 8: mise build --release (both targets)
[ ] Step 9: mise test on the host's native MSVC target
[ ] Step 10: Validate $env:OPENSHELL_WXC_EXEC_PATH (informational)
[ ] Step 11: Scaffold ARM64 CI workflow
[ ] Step 12: Commit and report artifacts
```

### Step 1: Verify host preconditions

This step is **advisory**. It records what is and isn't available on the host, but the skill continues regardless — compilation may still succeed (or produce useful errors) on a less-than-ideal host.

```powershell
$warnings = @()

$os = [System.Environment]::OSVersion.Version
if ($os.Build -lt 26100) {
    $warnings += "Windows build $($os.Build) < 26100 (recommended for MXC runtime; not required for compilation)."
}

# MSVC toolchain (must be a VS 2022 Developer PowerShell to be on PATH)
foreach ($tool in 'cl.exe', 'link.exe') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        $warnings += "$tool not found on PATH — open a VS 2022 Developer PowerShell, or expect link failures in Step 5+."
    }
}

# Rust + git
foreach ($tool in 'rustup', 'cargo', 'rustc', 'git') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        $warnings += "$tool not found on PATH — Step $(if ($tool -eq 'git') { '3' } else { '2+' }) will fail."
    }
}

if (Get-Command rustc -ErrorAction SilentlyContinue) { rustc --version }

if ($warnings.Count -gt 0) {
    Write-Warning "Host preconditions not fully met:"
    $warnings | ForEach-Object { Write-Warning "  - $_" }
    Write-Warning "Continuing anyway — re-evaluate after the next failing step."
} else {
    Write-Host "Host preconditions OK."
}
```

Record the warning list so it can be included in the final report (Step 12). Do not attempt to install Visual Studio Build Tools or rustup automatically.

### Step 2: Install Windows MSVC Rust targets

```powershell
rustup target add x86_64-pc-windows-msvc
if ($env:OPENSHELL_MXC_SKIP_ARM64 -ne "1") {
    rustup target add aarch64-pc-windows-msvc
}
```

### Step 3: Fork OpenShell into the sibling directory

This is the only step that creates a new on-disk repo. Confirm `$env:OPENSHELL_MXC_FORK_DIR` does not exist before cloning.

```powershell
$fork = if ($env:OPENSHELL_MXC_FORK_DIR) { $env:OPENSHELL_MXC_FORK_DIR } else { "C:\Users\$env:USERNAME\openshell-mxc" }
$upstream = if ($env:OPENSHELL_UPSTREAM) { $env:OPENSHELL_UPSTREAM } else { "https://github.com/NVIDIA/OpenShell.git" }
$branch = if ($env:OPENSHELL_MXC_FORK_BRANCH) { $env:OPENSHELL_MXC_FORK_BRANCH } else { "windows-mxc-build" }

if (Test-Path $fork) { throw "Fork dir already exists: $fork. Remove or set OPENSHELL_MXC_FORK_DIR." }

git clone $upstream $fork
Set-Location $fork
git checkout -b $branch

# Copy this skill into the fork so it can self-iterate.
New-Item -ItemType Directory -Force -Path "$fork\.claude\skills\build-openshell-mxc-windows" | Out-Null
New-Item -ItemType Directory -Force -Path "$fork\.agents\skills\build-openshell-mxc-windows" | Out-Null
Copy-Item "$PSScriptRoot\*" "$fork\.claude\skills\build-openshell-mxc-windows\" -Recurse -Force
Copy-Item "$PSScriptRoot\*" "$fork\.agents\skills\build-openshell-mxc-windows\" -Recurse -Force
```

From this point forward, `Set-Location $fork`. All edits land in the fork, not in the source OpenShell repo.

### Step 4: Apply minimum Windows compatibility shims

The goal is **the smallest patchset that makes `cargo check --target x86_64-pc-windows-msvc` succeed**, not a full Windows port. Strategy:

1. **Cfg-gate Linux-only crates and modules.** Any module that imports `nix`, `landlock`, `libseccomp`, `caps`, or constructs Unix-domain sockets without conditional compilation must be wrapped in `#[cfg(target_os = "linux")]` or `#[cfg(unix)]`.
2. **Stub Windows-side gateway entry points.** Where Linux uses Unix domain sockets for driver IPC (gateway ↔ compute driver), provide a `#[cfg(target_os = "windows")]` stub that returns `Err(unimplemented!("Windows named-pipe transport — follow-on skill"))`. The build must compile; runtime behavior is not in scope.
3. **Disable Linux-only crates from the Windows build graph.** In each crate's `Cargo.toml`, gate platform-specific dependencies with `[target.'cfg(target_os = "linux")'.dependencies]`. Common offenders: `nix`, `landlock`, `libseccomp`, `caps`, `procfs`.
4. **Default storage paths.** Where Linux code uses `~/.local/share/openshell` or `/var/lib/openshell`, add a `#[cfg(target_os = "windows")]` branch returning `%APPDATA%\OpenShell`.

See [reference.md](reference.md) for the concrete dependency audit (which crates and modules need gating, and the exact patterns to apply).

Driver crates that are not supported on Windows (`openshell-driver-docker`, `openshell-driver-podman`, `openshell-driver-vm`, `openshell-driver-kubernetes`) must compile as minimal Windows library stubs. Preserve their configuration structs so existing config parsing keeps working, and make every Windows runtime entry point or constructor return an "unsupported on Windows" error. Do not build, package, ship, or smoke-test standalone driver binaries as Windows deliverables. Do not enable Docker, Kubernetes, Podman, VM, Docker Desktop, WSL, Hyper-V, Podman machine, Podman Desktop, or any VM-backed runtime in this build-only skill.

### Step 5: Add Windows mise task lane

Create a Windows-only task file at `tasks/windows.toml` and a PowerShell wrapper at `tasks/scripts/windows-msvc.ps1`. This lane is additive: do not change the existing Linux `build`, `test`, or `ci` tasks. The Linux build procedure remains the repo's default mise/Cargo path.

The task file must expose these commands:

| Task | Purpose |
|---|---|
| `windows:check:x64` | `cargo check --workspace --target x86_64-pc-windows-msvc` |
| `windows:check:arm64` | `cargo check --workspace --target aarch64-pc-windows-msvc` |
| `windows:build:x64` | Release-build `openshell-gateway` and `openshell` for x64 |
| `windows:build:arm64` | Release-build `openshell-gateway` and `openshell` for ARM64 |
| `windows:test:x64` | Native x64 `cargo test --workspace --no-fail-fast`, excluding unsupported driver packages as top-level workspace targets |
| `windows:test:arm64` | Native ARM64 `cargo test --workspace --no-fail-fast` with the same exclusions |
| `windows:test:unsupported:x64` | Focused server/runtime tests that assert unsupported Windows driver contracts without building standalone driver binaries |
| `windows:test:unsupported:arm64` | The same focused contracts on a native ARM64 host |
| `windows:ci` | Ordered Windows check/build/test/unsupported-contract/artifact lane |

The PowerShell wrapper must:

1. Discover `VsDevCmd.bat` through `$env:OPENSHELL_VSDEVCMD`, `vswhere`, or standard Visual Studio install paths.
2. Add the requested rustup target before invoking Cargo.
3. Set `CARGO_INCREMENTAL=0` and keep `CARGO_TARGET_DIR` inside the fork unless the caller overrides it.
4. Clear inherited `RUSTC_WRAPPER` for this lane, because `mise run --skip-tools` intentionally does not provision `sccache`.
5. Exclude Docker, Kubernetes, Podman, and VM driver packages as top-level Windows workspace targets for check/test while still allowing their library stubs to compile as dependencies.
6. Emit logs for x64/ARM64 checks, builds, tests, and unsupported-contract tests.
7. Fail fast if a Windows-only task is invoked on a non-Windows host.

Use `mise run --skip-tools windows:*` in GitHub Actions and local Windows automation. `--skip-tools` is intentional: this repo should not ask mise to install Rust on Windows because the MSVC flow relies on rustup plus Visual Studio Build Tools.

For bundled Z3, the wrapper fetches the revision pinned by `z3-sys` through
Git and sets `Z3_SYS_BUNDLED_DIR_OVERRIDE`. It caches under an explicitly
configured `CARGO_TARGET_DIR`, or under the current user's local application
data directory when Cargo uses its default target tree. Concurrent commands
publish the validated source through an atomic directory rename so x64 and
ARM64 validation can share the cache safely. This bypasses the unauthenticated
GitHub Contents API lookup that can fail with HTTP 403 on shared networks.

The repository-wide `mise run pre-commit` task is supported on Windows.
`tasks/rust.toml` and `tasks/test.toml` route compiler-bearing checks through
the wrapper for the native host target, while `tasks/markdown.toml` provides a
Windows-safe dependency setup command. Keep existing Unix `run` bodies
unchanged when adding `run_windows` behavior. Linux installer,
build-environment shell-helper, and packaging asset tests skip explicitly;
cross-platform checks continue to run. The wrapper serializes its Cargo
commands and limits Cargo compilation to four jobs by default so
concurrent pre-commit tasks do not exhaust Windows process resources. Set
`OPENSHELL_WINDOWS_BUILD_JOBS` to a positive integer to override the limit.
It deliberately leaves `CL` and `_CL_` unset because `clang-cl` consumes those
variables too. Injecting MSVC-only options such as `/MP` can make ARM64 crypto
dependency builds treat the option as an input file.

### Step 6: mise check on x86_64-pc-windows-msvc

```powershell
$env:CARGO_TARGET_DIR = "$fork\target"
mise run --skip-tools windows:check:x64
```

This wraps `cargo check --workspace --target x86_64-pc-windows-msvc`. If it fails, the error log is the audit list. Iterate Step 4 through Step 6 until x64 succeeds. Common error patterns and their fixes are in [reference.md](reference.md#common-errors).

### Step 7: mise check on aarch64-pc-windows-msvc

```powershell
if ($env:OPENSHELL_MXC_SKIP_ARM64 -ne "1") {
    mise run --skip-tools windows:check:arm64
}
```

ARM64 typically surfaces the same dependency issues as x64. If x64 passes but ARM64 fails, the fault is almost always a native dependency (a `*-sys` crate without ARM64 prebuilds) or an inline-asm block lacking aarch64 paths. Either find a pure-Rust replacement or add ARM64 to the existing cfg gate.

On an x64 host this is a cross-build. The wrapper validates the ARM64 compiler
and Spectre libraries, adds host-native LLVM to `PATH`, lets ARM64 crypto crates
select `clang-cl`, and keeps bundled Z3 on native MSVC `cl.exe` through the
Visual Studio generator.
Use a short absolute `CARGO_TARGET_DIR` if Windows path-length limits are hit.

### Step 8: mise build --release (both targets)

```powershell
mise run --skip-tools windows:build:x64
if ($env:OPENSHELL_MXC_SKIP_ARM64 -ne "1") {
    mise run --skip-tools windows:build:arm64
}
```

Build only the binaries needed for build validation: `openshell-gateway` and `openshell` CLI. Skip `openshell-sandbox` — the supervisor Windows port is a follow-on skill.

Verify the binaries exist and report their architecture:

```powershell
Get-Item "$fork\target\x86_64-pc-windows-msvc\release\openshell-gateway.exe"
Get-Item "$fork\target\aarch64-pc-windows-msvc\release\openshell-gateway.exe" -ErrorAction SilentlyContinue
dumpbin /HEADERS "$fork\target\x86_64-pc-windows-msvc\release\openshell-gateway.exe" | Select-String "machine"
```

Expected machine values: `x64` for `x86_64-pc-windows-msvc`, `ARM64` for `aarch64-pc-windows-msvc`.

### Step 9: mise test on the native Windows architecture

```powershell
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($arch -eq [System.Runtime.InteropServices.Architecture]::Arm64) {
    mise run --skip-tools windows:test:arm64
    mise run --skip-tools windows:test:unsupported:arm64
} else {
    mise run --skip-tools windows:test:x64
    mise run --skip-tools windows:test:unsupported:x64
}
```

The wrapper rejects test targets that do not match the host architecture. This
keeps ARM64 results native and avoids reporting x64 emulation as ARM64 coverage.

Failures fall into three buckets:

1. **Linux-only test** — gate with `#[cfg(not(target_os = "windows"))]` and add a short comment describing the Windows-equivalent test that will eventually replace it.
2. **Path or environment assumption** — fix with conditional `%APPDATA%` paths.
3. **Genuine bug** — fix or open a follow-on issue and gate.

ARM64 tests are not run locally — they require a native ARM64 runner and are scaffolded in Step 11.

### Step 10: Validate `$env:OPENSHELL_WXC_EXEC_PATH` (informational)

This skill does **not** invoke `wxc-exec.exe`. The validation here is a forward-compatibility check so the follow-on MXC driver skill can rely on a known-good path.

```powershell
if ($env:OPENSHELL_WXC_EXEC_PATH) {
    if (-not (Test-Path $env:OPENSHELL_WXC_EXEC_PATH)) {
        Write-Warning "OPENSHELL_WXC_EXEC_PATH set but file missing: $env:OPENSHELL_WXC_EXEC_PATH"
    } else {
        $arch = (dumpbin /HEADERS $env:OPENSHELL_WXC_EXEC_PATH | Select-String "machine").Line
        Write-Host "wxc-exec.exe found: $env:OPENSHELL_WXC_EXEC_PATH ($arch)"
    }
} else {
    Write-Host "OPENSHELL_WXC_EXEC_PATH unset — MXC driver wiring is out of scope for this skill."
}
```

### Step 11: Scaffold ARM64 CI workflow

Add `.github/workflows/windows-msvc.yml` (or its GitLab equivalent for the fork) with two jobs: `x64` and `arm64`. The x64 job runs on `windows-2025`; the arm64 job runs on a self-hosted runner labelled `windows-arm64`. Do not provision the runner from the skill — emit a TODO comment in the workflow file noting that runner setup is operator work.

Template (skill writes this verbatim to `.github/workflows/windows-msvc.yml` in the fork):

```yaml
name: Windows MSVC (build-only)
on:
  push:
    branches: [windows-mxc-build]
  pull_request:
jobs:
  x64:
    runs-on: windows-2025
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v3
        with:
          install: false
          experimental: true
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-pc-windows-msvc
      - run: mise run --skip-tools windows:check:x64
      - run: mise run --skip-tools windows:build:x64
      - run: mise run --skip-tools windows:test:x64
      - run: mise run --skip-tools windows:test:unsupported:x64
  arm64:
    # TODO: provision a windows-arm64 self-hosted runner
    runs-on: [self-hosted, windows-arm64]
    if: false  # flip to true once the runner is online
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v3
        with:
          install: false
          experimental: true
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: aarch64-pc-windows-msvc
      - run: mise run --skip-tools windows:check:arm64
      - run: mise run --skip-tools windows:build:arm64
```

### Step 12: Commit and report

Commit each logical change as a Conventional Commit (per AGENTS.md). Suggested commit sequence:

```powershell
git add Cargo.toml Cargo.lock
git commit -m "chore(windows): platform-gate Linux-only dependencies"

git add crates/
git commit -m "feat(windows): cfg-gate Linux-only modules for MSVC target"

git add .github/workflows/windows-msvc.yml
git commit -m "ci(windows): scaffold x64 + arm64 MSVC workflow"

git add tasks/windows.toml tasks/scripts/windows-msvc.ps1
git commit -m "chore(windows): add mise MSVC task lane"
```

Final report should include:

| Item | Value |
|---|---|
| Host preconditions | "OK" or the warning list captured in Step 1 |
| Fork directory | `$env:OPENSHELL_MXC_FORK_DIR` |
| Branch | `$env:OPENSHELL_MXC_FORK_BRANCH` |
| x64 binary | `target\x86_64-pc-windows-msvc\release\openshell-gateway.exe` (size, sha256) |
| ARM64 binary | `target\aarch64-pc-windows-msvc\release\openshell-gateway.exe` (size, sha256) or "skipped" |
| Test summary | passed / failed / gated-out from `test-x64.log` |
| Windows mise lane | status of `windows:check:*`, `windows:build:*`, `windows:test:x64`, and `windows:test:unsupported:x64` |
| Gated modules | list of crates and modules with new `#[cfg(...)]` guards |
| `wxc-exec.exe` | path and architecture, or "unset" |
| Next skills to run | follow-on driver and policy-translation skills |

## Additional resources

- [reference.md](reference.md) — Unix dependency audit, common cargo errors and fixes, cfg gating patterns
