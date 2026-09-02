---
name: build-openshell-mxc-windows
description: Maintain and validate OpenShell's build-only Windows MSVC lane for x64 and ARM64. Use when working on Windows compilation, `windows:*` mise tasks, unsupported Windows compute-driver contracts, or Windows build reports. This skill does not implement Docker, Kubernetes, Podman, VM, MXC driver, policy translation, MSI, service, or supervisor runtime support on Windows.
metadata:
  internal: true
---

# Build OpenShell-MXC for Windows

This skill maintains the existing native Windows MSVC build lane in the
OpenShell repository. The Windows lane is already present in `main`; do not
treat this skill as a first-time porting recipe unless the user explicitly asks
for a new fork or a from-scratch bring-up.

The lane is build-only. It validates that OpenShell can compile and test on
Windows MSVC for the supported deliverables:

- `openshell-gateway.exe`
- `openshell.exe`

It intentionally does not make Windows a Docker, Kubernetes, Podman, or VM
runtime host.

## Current Repository Shape

The Windows build lane is implemented by these tracked files:

| Path | Purpose |
|---|---|
| `tasks/windows.toml` | Mise task entry points for `windows:*` commands. |
| `tasks/rust.toml`, `tasks/test.toml`, and `tasks/markdown.toml` | Windows routing for compiler-bearing checks, explicit Unix-only test skips, and Markdown dependency setup. |
| `tasks/scripts/windows-msvc.ps1` | PowerShell wrapper that enters the Visual Studio developer environment and invokes Cargo. |
| `.github/workflows/windows-msvc.yml` | Manually dispatched GitHub Actions jobs with architecture-specific Rust caches for x64 and future ARM64 Windows validation. |
| `architecture/windows-msvc-build.md` | Design notes and validation contract. |
| `.agents/skills/build-openshell-mxc-windows/` | This skill and companion reference material. |

Use the code that is already in the repo. Do not generate a parallel Windows
build system, duplicate the wrapper, or add repository automation that the user
did not request.

## Scope

In scope:

- Refreshing a local checkout to the latest upstream GitHub `main`.
- Maintaining `tasks/windows.toml` and `tasks/scripts/windows-msvc.ps1`.
- Running x64 and ARM64 MSVC checks.
- Building x64 and ARM64 release binaries for `openshell-gateway` and
  `openshell`.
- Running workspace tests on a native x64 or ARM64 host.
- Running focused unsupported-driver contract tests.
- Reporting test counts, skipped/gated areas, warnings, artifacts, and logs.
- Keeping Linux and macOS build paths unchanged.
- Keeping unsupported Windows compute drivers explicit and testable.

Out of scope:

- Docker Desktop support on Windows.
- Kubernetes support on Windows.
- Podman, Podman machine, or Podman Desktop support on Windows.
- VM, Hyper-V, WSL, libkrun, or VM-backed sandbox execution on Windows.
- New MXC compute driver crate.
- OpenShell to MXC policy translation.
- Windows named-pipe driver IPC.
- Windows Credential Manager or DPAPI integration.
- MSI, WinGet, Windows service registration, or installer work.
- Windows supervisor runtime port.

## Hard Rules

- Do not enable Docker, Kubernetes, Podman, or VM runtimes on Windows.
- Do not build, package, ship, or smoke-test standalone Windows binaries for
  unsupported compute drivers.
- Exclude unsupported Windows runtime crates from the Windows gateway dependency graph.
- Unsupported Windows runtime entry points must return a clear unsupported
  error.
- Keep Windows-specific code behind `#[cfg(target_os = "windows")]`.
- Keep Unix/Linux-only code behind `#[cfg(unix)]` or
  `#[cfg(target_os = "linux")]`.
- Do not modify the default Linux `mise run ci` path unless the user explicitly
  asks for it.
- Use `mise run --skip-tools windows:*` for Windows validation. The Windows
  toolchain is rustup plus Visual Studio Build Tools, not mise-provisioned Rust.
- Prefer one cross-platform `run` command when the underlying tool supports it
  (for example, `npm --prefix`). Add `run_windows` only when the Windows shell
  or validation contract genuinely differs.

## Recommended Checkout Flow

From a fork checkout where `upstream` points to the official
`NVIDIA/OpenShell` GitHub repository, use:

```powershell
git fetch upstream main
git switch main
git merge --ff-only upstream/main
git branch --set-upstream-to=upstream/main main
git status --short --branch
```

For a direct checkout of the official repository, use `origin` instead of
`upstream`. Confirm the remote URLs with `git remote -v` before refreshing.

If there are local changes, preserve or resolve them before refreshing. Do not
discard user work unless the user explicitly asks to clean the checkout.

## Prerequisites

The lane targets a Windows host with Visual Studio Build Tools and rustup.

| Requirement | Check | Notes |
|---|---|---|
| Windows 11 | `[System.Environment]::OSVersion.Version` | Build 26100+ is recommended for MXC-adjacent validation, but compilation can still surface useful errors on older hosts. |
| Visual Studio 2022 or newer | `where.exe cl.exe` from a Developer PowerShell | Build Tools, Community, Professional, and Enterprise editions work when the target C++ components are installed. The wrapper discovers `VsDevCmd.bat` through `OPENSHELL_VSDEVCMD`, `vswhere`, or installed release directories such as `18` and `2022`. |
| Visual C++ ARM64 tools | `vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.ARM64 -property installationPath` | Required for native ARM64 check, build, and tests and for x64-to-ARM64 check/build. Tests always require a native runner. |
| Visual C++ ARM64 Spectre-mitigated libraries | `vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Runtimes.ARM64.Spectre -property installationPath` | Required by `regorus` through `msvc_spectre_libs`; the build fails when the selected MSVC toolset lacks `lib\spectre\arm64`. |
| Visual C++ Clang tools | `vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Llvm.Clang -property installationPath` | Provides host-native `libclang.dll` for `bindgen` and `clang-cl.exe` for ARM64 crypto dependencies such as `ring` and `aws-lc-sys`. On ARM64, the wrapper uses `VC\Tools\Llvm\Arm64\bin`. |
| Visual C++ CMake tools | `vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.CMake.Project -property installationPath` | Provides CMake and Ninja. The x64-to-ARM64 path adds Ninja to `PATH` for native dependencies but keeps bundled Z3 on CMake's Visual Studio ARM64 generator with native MSVC `cl.exe`. |
| Windows SDK | `where.exe rc.exe` from a Developer PowerShell | Install an SDK containing target libraries and ARM64 tools. |
| Rust via rustup | `rustc --version` | Add each target being validated: `x86_64-pc-windows-msvc` and/or `aarch64-pc-windows-msvc`. The wrapper also adds the selected target. |
| mise | `mise --version` | Used as a task runner only. |
| Git | `git --version` | Needed for checkout and sync work. |
| PowerShell | `$PSVersionTable.PSVersion` | Windows PowerShell 5.1 works; PowerShell 7 is quieter with mise shell hooks. |

Do not install Visual Studio, Rust, Docker, Kubernetes, Podman, WSL, or Hyper-V
from this skill.

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `OPENSHELL_VSDEVCMD` | unset | Optional explicit path to `VsDevCmd.bat`. |
| `OPENSHELL_MXC_SKIP_ARM64` | `0` | Set to `1` to skip ARM64 when using `all` tasks. |
| `OPENSHELL_WINDOWS_BUILD_JOBS` | `CARGO_BUILD_JOBS`, then `4` | Positive Cargo job limit used by the wrapper. |
| `CARGO_TARGET_DIR` | `target` under repo root | Override Cargo output location. Use a short absolute path when x64-to-ARM64 builds approach Windows path-length limits. |
| `Z3_LIBRARY_PATH_OVERRIDE` | unset | Directory containing an x64 system `libz3.lib`; not valid for ARM64. |
| `Z3_SYS_Z3_HEADER` | unset | Full `z3.h` path required with a system Z3 library. |
| `Z3_SYS_BUNDLED_DIR_OVERRIDE` | pinned source cached under `CARGO_TARGET_DIR` when explicit, otherwise `%LOCALAPPDATA%\OpenShell\cache\z3` | Use an existing Z3 source tree containing `src/api/z3.h`; otherwise the wrapper fetches the pinned revision through Git and sets this automatically. |
| `RUSTC_WRAPPER` | cleared by wrapper | The wrapper clears inherited values because `--skip-tools` does not provision `sccache`. |

Legacy fork variables such as `OPENSHELL_UPSTREAM`,
`OPENSHELL_MXC_FORK_DIR`, and `OPENSHELL_MXC_FORK_BRANCH` are no longer part
of the normal maintenance workflow. Use them only if the user explicitly asks
for a new disposable fork.

## Validation Workflow

Run the smallest useful slice first, then broaden:

```powershell
mise run --skip-tools windows:check:x64
mise run --skip-tools windows:check:arm64
mise run --skip-tools windows:build:x64
mise run --skip-tools windows:build:arm64
mise run --skip-tools windows:test:x64
mise run --skip-tools windows:test:unsupported:x64
```

For full validation, detect the Windows host architecture first and choose the
native lane dynamically:

```powershell
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
switch ($arch.ToString()) {
    "X64" {
        mise run --skip-tools windows:ci
    }
    "Arm64" {
        mise run --skip-tools windows:check:arm64
        mise run --skip-tools windows:build:arm64
        mise run --skip-tools windows:test:arm64
        mise run --skip-tools windows:test:unsupported:arm64
        mise run --skip-tools windows:artifacts
    }
    default {
        throw "Unsupported Windows host architecture for OpenShell MSVC validation: $arch"
    }
}
```

On x64 hosts, `windows:ci` is the full current CI contract and runs in this
order:

1. x64 check.
2. ARM64 check, unless `OPENSHELL_MXC_SKIP_ARM64=1`.
3. x64 release build.
4. ARM64 release build, unless skipped.
5. Native x64 workspace tests.
6. Focused unsupported-driver contract tests.
7. Artifact reporting.

The GitHub Actions jobs use architecture-specific `Swatinem/rust-cache`
entries for the Cargo registry and dependency target artifacts. Failed runs
also save their usable dependency artifacts. The workflow remains manually
dispatched until cache-hit runtimes justify restoring automatic triggers.

The ARM64 check/build steps in this x64-host contract are cross-builds. The
wrapper discovers and adds host-native LLVM and Ninja to `PATH`, requires the
ARM64 compiler and Spectre-mitigated libraries, lets ARM64 crypto crates select
`clang-cl`, and keeps bundled Z3 on native MSVC `cl.exe` with CMake's Visual
Studio ARM64 generator. Z3 does not use Ninja because `z3-sys 0.10.9` passes
the MSBuild-only `-m` argument.

On ARM64 hosts, validate the native ARM64 check, build, and test path. The
wrapper rejects test targets that do not match the host architecture, so x64
compatibility under emulation is not part of these tasks. The aggregate
`windows:ci` task remains the x64-host CI contract; run the explicit ARM64
commands above on an ARM64 host.

The repository-wide `mise run pre-commit` task is also supported on Windows.
Its Rust check, Clippy, and test dependencies enter the same MSVC environment
for the native host target and clear inherited `RUSTC_WRAPPER`. Linux glibc
installer tests and Linux service/RPM packaging-asset tests skip explicitly;
the Linux build-environment shell-helper test also skips; cross-platform checks
continue to run. The blocking Windows Clippy pass excludes unsupported
Windows runtime packages as top-level targets. It allows only unused imports,
dead code, and unused async functions that result from cfg-gated Windows stubs;
other warnings remain errors.

The wrapper limits Cargo to four jobs by default and serializes wrapper-owned
Cargo commands with a host-local mutex. It deliberately does not set `CL` or
`_CL_`: those variables are also consumed by `clang-cl`, where a global MSVC
option such as `/MP4` can be interpreted as an input file and break ARM64
crypto dependency builds.

## Expected Task Behavior

| Task | Expected behavior |
|---|---|
| `windows:check:x64` | `cargo check --workspace` for `x86_64-pc-windows-msvc`, excluding unsupported Windows packages as top-level workspace targets. |
| `windows:check:arm64` | `cargo check --workspace` for `aarch64-pc-windows-msvc`, with the same top-level exclusions. |
| `windows:build:x64` | Release-builds `openshell-gateway.exe` and `openshell.exe` for x64. |
| `windows:build:arm64` | Release-builds `openshell-gateway.exe` and `openshell.exe` for ARM64. |
| `windows:test:x64` | Runs native x64 workspace tests with `--no-fail-fast`, excluding unsupported Windows packages as top-level workspace targets. |
| `windows:test:arm64` | Runs native ARM64 workspace tests with `--no-fail-fast` and the same package exclusions. Rejects non-ARM64 hosts. |
| `windows:test:unsupported:x64` | Re-runs focused `openshell-gateway` tests for unsupported Windows driver behavior. |
| `windows:test:unsupported:arm64` | Re-runs the same focused contracts natively on ARM64. Rejects non-ARM64 hosts. |
| `windows:artifacts` | Reports size and SHA256 for release artifacts that exist. |
| `windows:ci` | Runs the full ordered x64-host Windows CI lane, plus ARM64 check/build when not skipped. |

The unsupported driver package excludes are intentional. They prevent standalone
driver crates from being top-level Windows check/test targets while allowing
required libraries and Windows contracts to compile through gateway dependencies.
This includes the Kubernetes Secrets and Vault packages: their libraries remain
in the gateway build graph, but their Unix-socket standalone binaries do not.

## Unsupported Driver Contract

Windows must continue to reject unsupported compute drivers clearly.

| Driver | Windows build behavior | Runtime behavior |
|---|---|---|
| Docker | Driver crate excluded; gateway registration stub retained. | Gateway construction returns unsupported. |
| Kubernetes | Driver crate excluded; gateway registration stub retained. | Gateway construction returns unsupported. |
| Podman | Driver crate excluded; gateway registration stub retained. | Gateway construction returns unsupported. |
| VM | Driver crate excluded; gateway registration stub retained. | Gateway construction returns unsupported. |

The focused contract tasks for either native architecture run:

```text
windows_builtin_compute_drivers_report_unsupported
```

These tests are also included in the full x64 workspace test run; the focused
task intentionally re-runs them so unsupported Windows behavior is visible in
the CI report.

## Test Accounting Guidance

When reporting `windows:ci`, distinguish these categories:

- Passed tests from the full x64 workspace test log.
- Passed tests from the full ARM64 workspace test log when run on a native
  ARM64 host.
- The focused unsupported-contract re-run.
- Explicit Cargo ignored tests, usually ignored doc examples.
- Tests hidden by `#[cfg(not(target_os = "windows"))]`; these often appear as
  `running 0 tests`, not as ignored tests.
- Test-name `filtered out` counts from focused `cargo test` invocations.
- Package-level exclusions for unsupported Windows crates; Cargo does not report
  those as ignored tests.

Useful log files:

| Log | Meaning |
|---|---|
| `build-x86_64-pc-windows-msvc-check.log` | x64 check output. |
| `build-aarch64-pc-windows-msvc-check.log` | ARM64 check output. |
| `build-x86_64-pc-windows-msvc-release.log` | x64 release build output. |
| `build-aarch64-pc-windows-msvc-release.log` | ARM64 release build output. |
| `test-x86_64-pc-windows-msvc.log` | Full native x64 workspace test output. |
| `test-aarch64-pc-windows-msvc.log` | Full native ARM64 workspace test output. |
| `test-x86_64-pc-windows-msvc-unsupported-*.log` | Focused unsupported-driver contract output. |
| `test-aarch64-pc-windows-msvc-unsupported-*.log` | Focused native ARM64 contract output. |

The first bundled-Z3 check or test can spend several minutes in CMake/MSBuild
without much console output because Cargo output is redirected to the log. Look
for native `MSBuild.exe` workers before treating the process as stalled. The
wrapper fetches the pinned Z3 source through Git before Cargo starts. It caches
under an explicitly configured `CARGO_TARGET_DIR`, or under the current user's
local application data directory when Cargo uses its default target tree.
Concurrent commands publish the validated source through an atomic directory
rename, so x64 and ARM64 validation can share the cache safely. The wrapper does
not rely on the rate-limited GitHub Contents API used by `z3-sys`. A failed
fetch reports the partial checkout path for diagnosis. The artifact report
computes SHA256 through .NET directly and does not rely on the
`Get-FileHash` module being available inside the mise-launched Windows
PowerShell process.

## Common Fix Patterns

When Windows validation fails:

1. Identify whether the error is from a top-level Windows deliverable, a
   gateway dependency stub, or a Unix-only module leaking into the Windows build.
2. Prefer existing local patterns in the same crate.
3. Gate Unix imports and modules with `#[cfg(unix)]` or
   `#[cfg(target_os = "linux")]`.
4. Add or preserve Windows stubs that return unsupported errors.
5. Keep Linux behavior unchanged.
6. Run `cargo fmt --all`, `git diff --check`, and the relevant `windows:*`
   tasks after changes.

Do not add broad abstractions or new Windows runtime support to satisfy a build
error. If a missing runtime feature is required, stop and propose a follow-on
skill or design doc.

## Final Report Checklist

Every substantial Windows build run should report:

| Item | Required detail |
|---|---|
| Git state | Branch, upstream GitHub base commit, and whether local changes existed. |
| Host preconditions | OS, Rust, MSVC discovery, and notable warnings. |
| Commands run | Exact `mise run --skip-tools windows:*` commands. |
| x64 check/build | Pass/fail and log path. |
| ARM64 check/build | Pass/fail/skipped and log path. |
| Native tests | Passed/failed/ignored/filtered counts and log path for the host architecture. |
| Unsupported contracts | Which focused tests ran and their result. |
| Artifacts | Binary paths, size, and SHA256 when available. |
| Skips | Explicitly explain tests not run for a non-native architecture, unsupported driver package exclusions, and Windows cfg-gated tests. |
| Follow-ups | Only concrete follow-ups tied to failures or requested scope. |
