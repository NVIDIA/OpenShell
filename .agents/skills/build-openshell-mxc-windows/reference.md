# Reference: Windows MSVC maintenance lane

Companion to [SKILL.md](SKILL.md). Use this file for quick lookup while
maintaining the existing build-only Windows MSVC lane.

## Lane Files

| File | Purpose |
|---|---|
| `tasks/windows.toml` | Mise task definitions for `windows:*`. |
| `tasks/scripts/windows-msvc.ps1` | Visual Studio environment discovery, rustup target setup, Cargo invocation, logs, artifact report. |
| `.github/workflows/windows-msvc.yml` | Manual GitHub Actions x64 job and disabled ARM64 scaffold, each with an architecture-specific Rust dependency cache. |
| `architecture/windows-msvc-build.md` | Human-readable design contract. |

## Commands

Use `--skip-tools` for all Windows mise tasks:

```powershell
mise run --skip-tools windows:check:x64
mise run --skip-tools windows:check:arm64
mise run --skip-tools windows:build:x64
mise run --skip-tools windows:build:arm64
mise run --skip-tools windows:test:x64
mise run --skip-tools windows:test:arm64
mise run --skip-tools windows:test:unsupported:x64
mise run --skip-tools windows:test:unsupported:arm64
mise run --skip-tools windows:ci
```

For host-native full validation, detect architecture first:

```powershell
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($arch -eq [System.Runtime.InteropServices.Architecture]::Arm64) {
    mise run --skip-tools windows:check:arm64
    mise run --skip-tools windows:build:arm64
    mise run --skip-tools windows:test:arm64
    mise run --skip-tools windows:test:unsupported:arm64
    mise run --skip-tools windows:artifacts
} else {
    mise run --skip-tools windows:ci
}
```

The native test tasks reject a target that does not match the host architecture.
Do not report x64 compatibility-under-emulation coverage from an ARM64 run.

The wrapper adds missing rustup targets and clears inherited
`RUSTC_WRAPPER`. It does not install Visual Studio, Rust, Docker, Kubernetes,
Podman, WSL, Hyper-V, or VM tooling.

On Windows, `mise run pre-commit` routes `rust:check`, `rust:lint`, and
`test:rust` through this wrapper for the host-native target. The shared task
definitions retain their existing Unix commands. Only tests for Linux glibc
installer behavior, Linux build-environment shell helpers, and Linux
service/RPM packaging assets skip on Windows. The Windows Clippy command
excludes unsupported runtime packages as top-level targets and allows only
unused imports, dead code, and unused async functions caused by cfg-gated
Windows stubs; other warnings remain errors.

The wrapper limits Cargo to four jobs by default and serializes wrapper-owned
Cargo commands with a host-local mutex. It does not set `CL` or `_CL_` because
`clang-cl` also consumes them and can parse a global `/MP4` option as an input
file.

For ARM64, verify the Visual Studio instance contains the ARM64 MSVC tools,
ARM64 Spectre-mitigated libraries, Clang tools, CMake tools, and a Windows SDK.
Clang supplies host-native `libclang.dll` for `bindgen` and `clang-cl.exe` for
ARM64 crypto dependencies such as `ring` and `aws-lc-sys`. Native ARM64 uses
the normal bundled-Z3 CMake path. An x64-to-ARM64 check/build discovers and
adds host-native Ninja to `PATH`, while the crypto crates select `clang-cl`.
Bundled Z3 uses CMake's Visual Studio ARM64 generator with native MSVC `cl.exe`
because `z3-sys 0.10.9` passes the MSBuild-only `-m` argument. Use a short
`CARGO_TARGET_DIR` if Windows path-length limits are reached.

## Unsupported Driver Rules

Windows is a build target only. These runtimes remain unsupported:

- Docker
- Kubernetes
- Podman
- VM

Rules:

- Keep registration stubs in the gateway composition crate where the gateway needs them.
- Return clear unsupported errors at runtime.
- Do not build standalone Windows driver binaries.
- Do not add Docker Desktop, WSL, Hyper-V, Podman machine, Podman Desktop, or
  VM-backed execution as part of this skill.

Current focused unsupported-contract tests:

```text
windows_builtin_compute_drivers_report_unsupported
```

Run them with the architecture-specific focused task on the native host.

## Cargo Excludes

The Windows wrapper intentionally excludes unsupported runtime packages as
top-level workspace targets for check/test:

```text
--exclude openshell-driver-docker
--exclude openshell-driver-kubernetes
--exclude openshell-driver-kubernetes-secrets
--exclude openshell-driver-podman
--exclude openshell-driver-vault
--exclude openshell-driver-vm
--exclude openshell-sandbox
--exclude openshell-supervisor-network
--exclude openshell-supervisor-process
--exclude openshell-vfio
```

The gateway keeps platform configuration and unsupported-operation contracts
without depending on the Docker, Kubernetes, Podman, sandbox supervisor,
process supervisor, VM, or VFIO runtime crates. The Kubernetes Secrets and
Vault libraries still compile as gateway dependencies; only their standalone
Unix-socket binaries and package-level tests are excluded as top-level targets.

## Common Errors

### Unix imports leak into Windows builds

Symptoms:

```text
unresolved import std::os::unix
unresolved import tokio::net::UnixListener
unresolved import nix::...
```

Fix pattern:

```rust
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
```

Move Unix-only functions into Unix-only modules, or add a Windows stub that
returns an unsupported error.

### Linux-only dependency reaches Windows

Symptoms:

```text
failed to run custom build command for libseccomp-sys
pkg-config could not find libsecret
```

Fix pattern:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
libseccomp = "..."
```

Only gate the dependency if no Windows path should use it.

### ARM64 check fails but x64 passes

Likely causes:

- Native dependency does not support `aarch64-pc-windows-msvc`.
- ARM64 MSVC or Spectre-mitigated libraries are missing.
- Host-native `clang-cl`, Ninja, or CMake is missing during an x64-to-ARM64 build.
- `CL` or `_CL_` injects a global MSVC option such as `/MP4` into `clang-cl`.
- Build script assumes x64 tools.
- Inline assembly or prebuilt artifact lacks ARM64 handling.

Do not skip ARM64 silently. Either fix the target handling or report the exact
blocked dependency.

### Focused tests report many filtered-out tests

This is expected for `windows:test:unsupported:x64`. Cargo runs one named test
and filters the other `openshell-gateway` tests. Report these as filtered, not
ignored.

## Reporting Counts

Use the log summaries from:

| Log | Count source |
|---|---|
| `test-x86_64-pc-windows-msvc.log` | Full x64 workspace test pass. |
| `test-aarch64-pc-windows-msvc.log` | Full native ARM64 workspace test pass. |
| `test-x86_64-pc-windows-msvc-unsupported-*.log` | Focused unsupported-contract re-runs and filtered counts. |
| `test-aarch64-pc-windows-msvc-unsupported-*.log` | Focused native ARM64 re-runs and filtered counts. |

Separate:

- passed
- failed
- ignored
- filtered out
- cfg-gated zero-test targets
- package-level excludes

Package-level excludes are not printed as ignored tests by Cargo.

## Final Sanity Checks

Before committing Windows-lane changes, choose checks based on the host
architecture:

```powershell
cargo fmt --all
git diff --check
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($arch -eq [System.Runtime.InteropServices.Architecture]::Arm64) {
    mise run --skip-tools windows:check:arm64
    mise run --skip-tools windows:build:arm64
    mise run --skip-tools windows:test:arm64
    mise run --skip-tools windows:test:unsupported:arm64
} else {
    mise run --skip-tools windows:check:x64
    mise run --skip-tools windows:check:arm64
    mise run --skip-tools windows:test:unsupported:x64
}
```

Run the full x64-host `windows:ci` lane when build or test behavior changed and
the host can run that lane natively.
