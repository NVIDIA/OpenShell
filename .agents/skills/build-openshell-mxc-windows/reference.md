# Reference: Unix dependency audit and cfg gating patterns

Companion to [SKILL.md](SKILL.md). Use these tables and patterns when Step 4 (apply minimum Windows compatibility shims) hits a specific error during `cargo check --target x86_64-pc-windows-msvc`.

## Linux-only workspace dependencies

These crates from the OpenShell workspace `Cargo.toml` do not build on `x86_64-pc-windows-msvc`. Gate them out of the Windows build graph in each consuming crate's `Cargo.toml`.

| Crate | Used by | Windows fix |
|---|---|---|
| `nix` (features: signal, process, user, fs, term) | `openshell-sandbox`, `openshell-driver-vm`, `openshell-cli` | Move to `[target.'cfg(unix)'.dependencies]` in each consumer |
| `rustix` (features: process) | `openshell-server`, `openshell-sandbox` | Has Windows support — usually compiles; only gate the call sites that use Unix-only functions |
| `landlock` (if present in any crate) | `openshell-sandbox` | `[target.'cfg(target_os = "linux")'.dependencies]` |
| `libseccomp` / `seccompiler` | `openshell-sandbox` | `[target.'cfg(target_os = "linux")'.dependencies]` |
| `caps` | `openshell-sandbox` | `[target.'cfg(unix)'.dependencies]` |
| `procfs` | `openshell-sandbox`, `openshell-driver-vm` | `[target.'cfg(target_os = "linux")'.dependencies]` |
| `libkrun-sys` (transitive via VM driver) | `openshell-driver-vm` | Move Linux implementation behind non-Windows cfg and expose a Windows stub that returns unsupported |

Compute drivers that must remain unsupported on Windows:

- `openshell-driver-docker` - preserve config parsing, but Windows runtime construction returns unsupported
- `openshell-driver-podman` - preserve config parsing, but Windows runtime construction returns unsupported
- `openshell-driver-vm` - preserve config parsing, but Windows VM spawn returns unsupported
- `openshell-driver-kubernetes` - preserve config parsing, but Windows runtime construction returns unsupported

The build-only slice does not need Docker, Kubernetes, Podman, or VM runtime support. Keep these crates in the Windows build graph as library stubs so config files still deserialize and the gateway can return clear unsupported errors. Do not build, package, ship, or smoke-test standalone driver binaries as Windows deliverables, and do not enable Docker Desktop, WSL, Hyper-V, Kubernetes, Podman machine, Podman Desktop, or any VM-backed runtime.

## Common errors and fixes

### `error[E0432]: unresolved import 'tokio::net::UnixListener'`

Wrap the import and all use sites:

```rust
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
```

For the Windows side, leave a compile-time stub:

```rust
#[cfg(target_os = "windows")]
pub fn bind_driver_socket(_path: &str) -> anyhow::Result<()> {
    anyhow::bail!("named-pipe driver IPC not implemented");
}
```

### `error: failed to run custom build command for 'libseccomp-sys'`

The crate has no Windows backend. Gate it out:

```toml
# in crates/openshell-sandbox/Cargo.toml
[target.'cfg(target_os = "linux")'.dependencies]
libseccomp = "..."
```

Then in `src/lib.rs`:

```rust
#[cfg(target_os = "linux")]
mod seccomp;
```

### `error: linking with 'link.exe' failed: exit code: 1120` referencing `nix_*` symbols

A `use nix::...` is reachable from the Windows build path. Either gate the `use` with `#[cfg(unix)]` or move the function into a Unix-only module.

### `error: the trait bound 'PathBuf: From<&str>' is not satisfied` on Windows-only paths

Usually caused by hardcoded forward-slash paths. Replace with `PathBuf::from()` and rely on `std::path::MAIN_SEPARATOR` or use `dirs::data_local_dir()` for `%APPDATA%`.

### `error[E0599]: no method 'set_nonblocking' found` on `std::os::unix::net::UnixStream`

Same pattern — gate with `#[cfg(unix)]`.

### `cargo:warning=libsecret-sys ... not found`

`libsecret` only works on Linux. If `openshell-providers` pulls it in, gate it. The build-only skill does not need credential storage on Windows; that is a follow-on skill.

### Bundled Z3 fails with HTTP 403

The wrapper should fetch the pinned Z3 revision through Git before Cargo starts.
If that prefetch fails, inspect the reported partial checkout and verify that
Git can reach `https://github.com/Z3Prover/z3.git`.

## Cfg gating patterns

### Module-level

```rust
// crates/openshell-sandbox/src/sandbox/mod.rs
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
pub use windows::*;
```

### Cargo dependency-level

```toml
[target.'cfg(target_os = "linux")'.dependencies]
landlock = "0.4"
libseccomp = "0.3"

[target.'cfg(target_os = "windows")'.dependencies]
windows-sys = { version = "0.59", features = ["Win32_Storage_FileSystem", "Win32_System_Pipes"] }
```

Do **not** add the `windows-sys` dependency in this build-only skill unless a specific compile error demands it. The follow-on MXC driver skill will introduce the Windows API surface.

### Path defaults

```rust
pub fn default_state_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("/var/lib"))
            .join("openshell")
    }
    #[cfg(target_os = "windows")]
    {
        // %APPDATA%\OpenShell
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("OpenShell")
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from(".openshell")
    }
}
```

### Test gating

```rust
#[cfg(not(target_os = "windows"))]
#[test]
fn linux_landlock_smoke() {
    // ...
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "supervisor Windows port is a follow-on skill"]
fn windows_supervisor_smoke() {
    unimplemented!()
}
```

## Linux build must stay green

After every cfg gate change, run `cargo check --workspace` on the Linux baseline before committing. The skill's commits must not regress Linux. Use a separate clone or WSL session if running on a Windows-only host, or rely on the existing Linux CI to fail the PR.

## Windows mise lane expectations

The Windows build path is additive. Keep the repository's Linux `mise run ci`, default Cargo tasks, and Linux documentation unchanged. Windows automation lives in `tasks/windows.toml` and delegates to `tasks/scripts/windows-msvc.ps1`.

On Windows, `mise run pre-commit` routes `rust:check`, `rust:lint`, and
`test:rust` through the same wrapper for the host-native target. Shared task
definitions retain their Unix commands. Only Linux installer and
service/RPM-packaging tests skip. The Windows Clippy command allows unused
imports, dead code, and unused async functions caused by cfg-gated stubs; other
warnings remain errors.

| Task | Expected behavior |
|---|---|
| `mise run --skip-tools windows:check:x64` | Runs x64 MSVC `cargo check --workspace` |
| `mise run --skip-tools windows:check:arm64` | Runs ARM64 MSVC `cargo check --workspace` |
| `mise run --skip-tools windows:build:x64` | Builds release `openshell-gateway.exe` and `openshell.exe` for x64 |
| `mise run --skip-tools windows:build:arm64` | Builds release `openshell-gateway.exe` and `openshell.exe` for ARM64 |
| `mise run --skip-tools windows:test:x64` | Runs native x64 workspace tests |
| `mise run --skip-tools windows:test:arm64` | Runs workspace tests on a native ARM64 Windows host |
| `mise run --skip-tools windows:test:unsupported:x64` | Verifies unsupported driver contracts through server/runtime tests without building standalone driver binaries |
| `mise run --skip-tools windows:test:unsupported:arm64` | Verifies the same contracts on a native ARM64 Windows host |
| `mise run --skip-tools windows:ci` | Runs the full Windows lane in order |

Use `--skip-tools` for Windows CI and automation. Rust must come from rustup with MSVC targets, and Visual Studio Build Tools must provide the linker and SDK. Because `--skip-tools` does not provision mise-managed tools, the Windows wrapper clears inherited `RUSTC_WRAPPER=sccache` before invoking Cargo. The wrapper excludes unsupported driver packages as top-level workspace targets for Windows check/test, but those library stubs still compile when the gateway depends on them. The wrapper may discover `VsDevCmd.bat`, but it must not install Visual Studio, Rust, Docker, Kubernetes, Podman, VM tooling, WSL, or Hyper-V.

ARM64 validation requires the Visual Studio ARM64 C++ tools, ARM64
Spectre-mitigated libraries, host-native `libclang.dll` and `clang-cl.exe`,
CMake tools, Ninja, and an ARM64-capable Windows SDK. During x64-to-ARM64
check/build, ARM64 crypto crates use `clang-cl` while bundled Z3 stays on
native MSVC `cl.exe` with Ninja. Use a short `CARGO_TARGET_DIR` if Windows
path-length limits are reached. Test tasks reject a target that does not match
the Windows host architecture.

Bundled Z3 source is pinned by revision, fetched through Git, and cached under
`CARGO_TARGET_DIR`. The wrapper sets `Z3_SYS_BUNDLED_DIR_OVERRIDE` so `z3-sys`
does not make an unauthenticated GitHub Contents API call. An explicit override
must point to a source tree containing `src/api/z3.h`.

## What NOT to do in this skill

- Do not implement named-pipe IPC. Stubs only. (Belongs to the follow-on MXC driver skill.)
- Do not add Windows Credential Manager integration. (Follow-on skill.)
- Do not implement DPAPI encryption. (Follow-on skill.)
- Do not create a new MXC driver crate. (Separate skill.)
- Do not write OpenShell → MXC JSON translation. (Separate skill.)
- Do not build MSI installers. (Follow-on skill.)
- Do not modify the `openshell-sandbox` supervisor for Windows beyond cfg-gating to compile. The full port is a follow-on skill.

The success criterion is **the workspace compiles and basic tests pass on Windows MSVC for both architectures, with the Linux build unchanged**. Nothing more.
