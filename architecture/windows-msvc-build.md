# Windows MSVC Build Design

This page records the design decisions for the native Windows MSVC build lane.
It is intentionally build-only. It does not make Windows a Docker, Kubernetes,
Podman, or VM runtime host.

## Goals

- Compile the OpenShell gateway and CLI for `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`.
- Keep the Linux and macOS build paths unchanged.
- Preserve gateway configuration parsing for all existing compute driver names.
- Return clear unsupported errors when a Windows gateway is configured to use Docker, Kubernetes, Podman, or VM.
- Keep dedicated `windows:*` validation tasks while allowing the repository-wide
  `pre-commit` task to delegate compiler-bearing Rust checks to the native
  Windows MSVC environment.

## Non-Goals

- Do not support Docker Desktop, WSL, Hyper-V, Podman machine, Podman Desktop, Kubernetes, or VM-backed sandbox execution on Windows.
- Do not ship Windows standalone binaries for Docker, Kubernetes, Podman, or VM drivers.
- Do not implement named-pipe driver IPC, Windows services, MSI packaging, Credential Manager integration, DPAPI integration, or MXC policy translation in this build lane.

## Unsupported Driver Strategy

The gateway uses platform-specific configuration contracts on Windows. These
contracts preserve config-file parsing and reject unsupported driver selection
with a clear error without depending on the runtime driver crates.

The Windows lane does not build, release, package, or smoke-test standalone
driver binaries for Docker, Kubernetes, Podman, or VM. Those binaries are Linux
or macOS deliverables only.

The Kubernetes Secrets and Vault packages are also excluded as top-level
Windows workspace targets because their standalone driver binaries use Unix
domain sockets. Their libraries remain in the gateway dependency graph, so the
gateway's credential-driver configuration and in-process behavior still compile
on Windows.

| Driver | Windows build behavior | Runtime behavior |
|---|---|---|
| Docker | Driver crate excluded; server config contract retained. | Gateway construction returns unsupported. |
| Kubernetes | Driver crate excluded; server config contract retained. | Gateway construction returns unsupported. |
| Podman | Driver crate excluded; server config contract retained. | Gateway construction returns unsupported. |
| VM | Driver crate excluded from workspace validation. | Gateway construction returns unsupported. |

This keeps Windows behavior explicit without carrying runtime dependencies or
creating misleading Windows driver artifacts.

## Mise Lane

The GitHub Actions workflow is manually dispatched. Each architecture restores
and saves a dedicated Rust cache containing the Cargo registry and dependency
build artifacts, including artifacts from failed runs. Keep the workflow manual
until cache-hit runtimes demonstrate that it is suitable for pull requests and
merges to `main`.

Windows validation is exposed through `tasks/windows.toml`:

| Task | Purpose |
|---|---|
| `windows:check:x64` | Check the x64 MSVC gateway/CLI build graph. |
| `windows:check:arm64` | Check the ARM64 MSVC gateway/CLI build graph. |
| `windows:build:x64` | Build release x64 `openshell-gateway.exe` and `openshell.exe`. |
| `windows:build:arm64` | Build release ARM64 `openshell-gateway.exe` and `openshell.exe`. |
| `windows:test:x64` | Run native x64 workspace tests, excluding unsupported Windows packages as top-level test targets. |
| `windows:test:arm64` | Run native ARM64 workspace tests with the same package exclusions. |
| `windows:test:unsupported:x64` | Run focused server/runtime tests for unsupported driver contracts. |
| `windows:test:unsupported:arm64` | Run the same focused contracts natively on ARM64. |
| `windows:ci` | Run check, build, test, unsupported-contract tests, and artifact reporting. |

The Windows tasks call `tasks/scripts/windows-msvc.ps1`. The wrapper discovers
Visual Studio's `VsDevCmd.bat` with `vswhere` or by enumerating installed
release directories, validates the requested compiler and ARM64 Spectre
libraries, adds rustup MSVC targets, clears inherited `RUSTC_WRAPPER`, and
keeps build artifacts under the normal Cargo target tree.
On Windows, the generic `rust:check`, `rust:lint`, and `test:rust` tasks call
the same wrapper with the host-native MSVC target. The wrapper preserves the
Unix Cargo commands on Linux and macOS, excludes unsupported Windows runtime
packages, and runs the server test-support suite separately. Windows Clippy
continues to deny all warnings except unused imports, dead code, and unused
async functions caused by cfg-gated Windows stubs. Repository-wide pre-commit
skips only Linux-specific installer, build-environment shell-helper, and
packaging-asset tests; its
cross-platform Python, Markdown, license, and documentation checks still run.
Test tasks require the Rust target architecture to match the Windows host, so
an ARM64 test result is native coverage rather than x64 emulation coverage.
By default it enables bundled Z3 for reproducible Windows builds. When
`Z3_LIBRARY_PATH_OVERRIDE` points at a directory containing `libz3.lib`, the
wrapper uses that system Z3 instead and requires `Z3_SYS_Z3_HEADER` to point at
the full path to `z3.h`. For bundled builds, the wrapper fetches the Z3 source
revision pinned by `z3-sys` through Git and sets
`Z3_SYS_BUNDLED_DIR_OVERRIDE`. When `CARGO_TARGET_DIR` is explicit, the wrapper
uses it for the source cache. Otherwise, it caches under the current user's
local application data directory, outside the checkout. Publishing uses an
atomic directory rename so concurrent x64 and ARM64 commands can share the
cache safely. This keeps downloaded sources outside the checkout by default and
avoids the unauthenticated GitHub API lookup in the `z3-sys` build script, which
can fail with HTTP 403 when a shared runner or developer network exhausts its
API rate limit. An explicitly set `Z3_SYS_BUNDLED_DIR_OVERRIDE` remains
supported and must contain `src/api/z3.h`.

The lane uses `mise run --skip-tools windows:*` because Windows Rust comes from
rustup and linking comes from Visual Studio Build Tools. Mise orchestrates the
tasks; it does not own the Windows toolchain.

ARM64 validation requires the Visual Studio ARM64 MSVC tools, ARM64
Spectre-mitigated libraries, host-native Clang tools, CMake tools, and an
ARM64-capable Windows SDK. Clang provides `libclang.dll` for `bindgen` and
`clang-cl.exe` for ARM64 crypto dependencies. During x64-to-ARM64 check/build,
the wrapper discovers and adds the Visual Studio-bundled Ninja to `PATH` for
native dependencies. It lets `cmake-rs` select the Visual Studio ARM64
generator with native MSVC `cl.exe` for bundled Z3 so the Z3 build does not
inherit the crypto crates' compiler requirement. Z3 stays on the Visual Studio
generator because `z3-sys` emits an MSBuild-only `-m` argument that Ninja
rejects. Artifact hashing uses .NET SHA256 directly because module autoloading
in the mise-launched Windows PowerShell process is not guaranteed.

The wrapper defaults Cargo compilation to four jobs. Set
`OPENSHELL_WINDOWS_BUILD_JOBS` to a positive integer to override that limit.
A host-local mutex serializes wrapper-owned Cargo commands so concurrent
pre-commit tasks do not multiply the process count while bundled Z3 compiles.
The wrapper does not set `CL` or `_CL_`: those variables are also consumed by
`clang-cl`, where MSVC's `/MP` option can be interpreted as an input file and
break ARM64 crypto dependency builds.

## CI Shape

The x64 GitHub Actions job runs on `windows-2025` and executes:

```powershell
mise run --skip-tools windows:check:x64
mise run --skip-tools windows:build:x64
mise run --skip-tools windows:test:x64
mise run --skip-tools windows:test:unsupported:x64
```

The cache is partitioned by architecture so incompatible x64 and ARM64 target
artifacts cannot collide. It does not cache Cargo-installed binaries, which
also keeps the disabled self-hosted ARM64 scaffold from modifying persistent
runner tooling.

The local aggregate `windows:ci` task cross-builds ARM64 on an x64 host. The
GitHub x64 job currently runs only the x64 tasks, and native ARM64 tests remain
exclusive to an ARM64 runner.

The ARM64 job is scaffolded but disabled until a Windows ARM64 runner is
available. Once enabled, it should run check, release build, native workspace
tests, and the focused unsupported-driver contracts for
`aarch64-pc-windows-msvc`.

## Validation Contract

A successful Windows build report should include:

- x64 and ARM64 `cargo check` status.
- x64 and ARM64 release build status for `openshell-gateway.exe` and `openshell.exe`.
- x64 test summary.
- Native ARM64 test summary when validation runs on an ARM64 host.
- Focused unsupported-driver contract test status.
- Artifact size and SHA256 for each Windows binary.

Warnings from Linux-only dead code are acceptable in this build-only phase when
they come from code paths intentionally disabled on Windows.
