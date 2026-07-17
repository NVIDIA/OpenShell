# Windows MSVC Build Design

This page records the design decisions for the native Windows MSVC build lane.
It is intentionally build-only. It does not make Windows a Docker, Kubernetes,
Podman, or VM runtime host.

## Goals

- Compile the OpenShell gateway and CLI for `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`.
- Keep the Linux and macOS build paths unchanged.
- Preserve gateway configuration parsing for all existing compute driver names.
- Return clear unsupported errors when a Windows gateway is configured to use Docker, Kubernetes, Podman, or VM.
- Validate the Windows lane through mise tasks that are separate from the default Linux `ci` task.

## Non-Goals

- Do not support Docker Desktop, WSL, Hyper-V, Podman machine, Podman Desktop, Kubernetes, or VM-backed sandbox execution on Windows.
- Do not ship Windows standalone binaries for Docker, Kubernetes, Podman, or VM drivers.
- Do not implement named-pipe driver IPC, Windows services, MSI packaging, Credential Manager integration, DPAPI integration, or MXC policy translation in this build lane.

## Unsupported Driver Strategy

Unsupported compute drivers use contract stubs on Windows. The stubs preserve
configuration structs and public library entry points so the gateway can parse
existing config files and reject unsupported driver selection with a clear error.

The Windows lane does not build, release, package, or smoke-test standalone
driver binaries for Docker, Kubernetes, Podman, or VM. Those binaries are Linux
or macOS deliverables only.

| Driver | Windows build behavior | Runtime behavior |
|---|---|---|
| Docker | Library config stub compiles as a gateway dependency. | Gateway construction returns unsupported. |
| Kubernetes | Library config stub compiles as a gateway dependency. | Gateway construction returns unsupported. |
| Podman | Library config stub compiles as a gateway dependency. | Gateway construction returns unsupported. |
| VM | Library config stub compiles as a gateway dependency. | VM spawn returns unsupported. |

This keeps Windows behavior explicit without carrying runtime dependencies or
creating misleading Windows driver artifacts.

## Mise Lane

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
Visual Studio's `VsDevCmd.bat`, adds rustup MSVC targets, clears inherited
`RUSTC_WRAPPER`, and keeps build artifacts under the normal Cargo target tree.
Test tasks require the Rust target architecture to match the Windows host, so
an ARM64 test result is native coverage rather than x64 emulation coverage.
By default it enables bundled Z3 for reproducible Windows builds. When
`Z3_LIBRARY_PATH_OVERRIDE` points at a directory containing `libz3.lib`, the
wrapper uses that system Z3 instead and requires `Z3_SYS_Z3_HEADER` to point at
the full path to `z3.h`.

The lane uses `mise run --skip-tools windows:*` because Windows Rust comes from
rustup and linking comes from Visual Studio Build Tools. Mise orchestrates the
tasks; it does not own the Windows toolchain.

ARM64 validation requires the Visual Studio ARM64 MSVC tools, host-native Clang
tools for `libclang.dll`, CMake tools for bundled Z3, and an ARM64-capable
Windows SDK. Artifact hashing uses .NET SHA256 directly because module
autoloading in the mise-launched Windows PowerShell process is not guaranteed.

## CI Shape

The x64 GitHub Actions job runs on `windows-2025` and executes:

```powershell
mise run --skip-tools windows:check:x64
mise run --skip-tools windows:build:x64
mise run --skip-tools windows:test:x64
mise run --skip-tools windows:test:unsupported:x64
```

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
