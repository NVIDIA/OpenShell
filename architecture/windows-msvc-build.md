# Windows MSVC Build Design

This page records the design decisions for the native Windows MSVC build lane.
It provides the native build lane and validates the in-process MXC compute
driver. It does not make Windows a Docker, Kubernetes, Podman, or VM runtime host.

## Goals

- Compile the OpenShell gateway and CLI for `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`.
- Keep the Linux and macOS build paths unchanged.
- Preserve gateway configuration parsing for all existing compute driver names.
- Build and test the in-process MXC driver on supported Windows hosts.
- Use the ordinary in-process compute-driver composition path; MXC receives the
  canonical sandbox policy through `DriverSandboxSpec` and advertises that it
  reports runtime readiness.
- Return clear unsupported errors when a Windows gateway is configured to use Docker, Kubernetes, Podman, or VM.
- Keep dedicated `windows:*` validation tasks while allowing the repository-wide
  `pre-commit` task to delegate compiler-bearing Rust checks to the native
  Windows MSVC environment.

## Non-Goals

- Do not support Docker Desktop, WSL, Hyper-V, Podman machine, Podman Desktop, Kubernetes, or VM-backed sandbox execution on Windows.
- Do not ship Windows standalone binaries for Docker, Kubernetes, Podman, or VM drivers.
- Do not implement named-pipe driver IPC, Windows services, MSI packaging, Credential Manager integration, or DPAPI integration in this lane.

## Unsupported Driver Strategy

The gateway composition crate installs platform-specific registration stubs on
Windows. These registrations preserve config-file selection and reject
unsupported drivers with a clear error without depending on their runtime
crates.

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
| Docker | Driver crate excluded; gateway registration stub retained. | Gateway construction returns unsupported. |
| Kubernetes | Driver crate excluded; gateway registration stub retained. | Gateway construction returns unsupported. |
| Podman | Driver crate excluded; gateway registration stub retained. | Gateway construction returns unsupported. |
| VM | Driver crate excluded; gateway registration stub retained. | Gateway construction returns unsupported. |
| MXC | Driver links into the native gateway and runs in Windows validation. | `process_container` is default-deny; grant-only `isolation_session` requires explicit configuration. |

This keeps Windows behavior explicit without carrying runtime dependencies or
creating misleading Windows driver artifacts.

## Mise Lane

The GitHub Actions workflow runs x64 Windows Clippy and Rust tests for
pull-request mirror branches and merge queues. On pushes to `main`, a cache-seed
job runs the same lint and test commands before a dependent job builds the
release binaries. Manual dispatches exercise the same seed-then-build path.
The binaries remain CI validation artifacts and are not uploaded or published.

Each job restores and saves a dedicated Rust cache containing the Cargo
registry and dependency build artifacts, including artifacts from failed runs.
The seed job and pull-request job use the same Cargo target and sccache
namespaces. The release build waits for the seed job, then restores its newly
warmed cache rather than compiling concurrently from a cold cache.

Windows validation is exposed through `tasks/windows.toml`:

| Task | Purpose |
|---|---|
| `windows:check:x64` | Check the x64 MSVC gateway/CLI build graph. |
| `windows:check:arm64` | Check the ARM64 MSVC gateway/CLI build graph. |
| `windows:build:x64` | Build release x64 `openshell-gateway.exe` and `openshell.exe`. |
| `windows:build:arm64` | Build release ARM64 `openshell-gateway.exe` and `openshell.exe`. |
| `windows:test:x64` | Run native x64 workspace tests, including MXC mapper and lifecycle tests, while excluding unsupported Windows packages as top-level test targets. |
| `windows:test:arm64` | Run native ARM64 workspace tests with the same package exclusions. |
| `windows:test:unsupported:x64` | Run focused gateway-composition tests for unsupported driver contracts. |
| `windows:test:unsupported:arm64` | Run the same focused contracts natively on ARM64. |
| `windows:ci` | Run check, build, test, unsupported-contract tests, and artifact reporting. |

The Windows tasks call `tasks/scripts/windows-msvc.ps1`. The wrapper discovers
Visual Studio's `VsDevCmd.bat` with `vswhere` or by enumerating installed
release directories, validates the requested compiler and ARM64 Spectre
libraries, adds rustup MSVC targets, preserves an inherited `RUSTC_WRAPPER`
when the command is available, and keeps build artifacts under the normal
Cargo target tree. If the wrapper command is unavailable, it warns and clears
the setting so local builds continue without compiler caching.
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
By default it enables the `z3-sys` prebuilt-release feature and pins Z3 4.16.0.
On a clean target directory, `z3-sys` downloads the official static library for
the selected Windows architecture instead of compiling Z3 through
CMake/MSBuild. GitHub Actions supplies its read-only workflow token for the
release lookup, and the Cargo target cache preserves the extracted library for
subsequent runs. When
`Z3_LIBRARY_PATH_OVERRIDE` points at a directory containing `libz3.lib`, the
wrapper uses that system Z3 instead and requires `Z3_SYS_Z3_HEADER` to point at
the full path to `z3.h`. Local clean builds use the unauthenticated GitHub API
unless `READ_ONLY_GITHUB_TOKEN` is set.

GitHub Actions layers the Cargo target cache with sccache's GitHub Actions
backend. The target cache lets Cargo skip intact dependency builds; sccache
recovers cacheable Rust compiler outputs when source changes invalidate part of
that target tree. CI enables client-side mode and normalizes the checkout root
for stable compiler cache keys. The target-cache action runs its metadata step
with `RUSTC_WRAPPER` cleared so cache maintenance does not depend on sccache.

The lane uses `mise run --skip-tools windows:*` because Windows Rust comes from
rustup and linking comes from Visual Studio Build Tools. Mise orchestrates the
tasks; it does not own the Windows toolchain.

ARM64 validation requires the Visual Studio ARM64 MSVC tools, ARM64
Spectre-mitigated libraries, host-native Clang tools, CMake tools, and an
ARM64-capable Windows SDK. Clang provides `libclang.dll` for `bindgen` and
`clang-cl.exe` for ARM64 crypto dependencies. During x64-to-ARM64 check/build,
the wrapper discovers and adds the Visual Studio-bundled Ninja to `PATH` for
native dependencies. Z3 uses the official prebuilt ARM64 static library, so it
does not inherit compiler settings from those native dependencies. Artifact
hashing uses .NET SHA256 directly because module autoloading in the
mise-launched Windows PowerShell process is not guaranteed.

The wrapper defaults Cargo compilation to four jobs. Set
`OPENSHELL_WINDOWS_BUILD_JOBS` to a positive integer to override that limit.
A host-local mutex serializes wrapper-owned Cargo commands so concurrent
pre-commit tasks do not multiply the compiler process count.
The wrapper does not set `CL` or `_CL_`: those variables are also consumed by
`clang-cl`, where MSVC's `/MP` option can be interpreted as an input file and
break ARM64 crypto dependency builds.

## CI Shape

The x64 GitHub Actions jobs run on `windows-2025`. Pull-request mirrors and
merge queues execute:

```powershell
mise run --skip-tools rust:lint
mise run --skip-tools test:rust
```

Pushes to `main` and manual dispatches first seed the shared caches with those
same lint and test commands. After the seed succeeds, a separate job executes:

```powershell
mise run --skip-tools windows:build:x64
```

The server test-support suite includes the unsupported-driver contract test, so
CI does not run the focused test task a second time. The focused task remains
available for local diagnosis.

The cache is partitioned by architecture so incompatible x64 and ARM64 target
artifacts cannot collide. It does not cache Cargo-installed binaries, which
also keeps the disabled self-hosted ARM64 scaffold from modifying persistent
runner tooling.

The local aggregate `windows:ci` task cross-builds ARM64 on an x64 host. The
GitHub x64 job runs only the x64 tasks, and native ARM64 tests remain exclusive
to an ARM64 runner.

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

Warnings from Linux-only dead code are acceptable in the native Windows lane when
they come from code paths intentionally disabled on Windows.
