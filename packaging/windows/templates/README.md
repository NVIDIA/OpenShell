# OpenShell Windows 0.1.8 (arm64)

**Unsigned candidate, not ready for release.** See VALIDATION.md for passed checks and remaining limitations.

This portable kit is built from [NVIDIA/OpenShell's windows branch](https://github.com/NVIDIA/OpenShell/tree/@SOURCE_SHA@), commit `@SOURCE_SHA@`. The Rust binaries and SDKs are versioned `0.1.8`. These Windows sources differ from the main-branch `v0.1.8` tag.

Read KNOWN-LIMITATIONS.md before running workloads. The Windows runtime is under development and is not a production-qualified isolation boundary. Consult release-manifest.json and VALIDATION.md for this kit's actual signing and validation status.

## Prerequisites

- Windows matching this kit's architecture and the matching Microsoft Visual C++ runtime. x64 means 64-bit Intel/AMD; there is no 32-bit x86 kit.
- MXC 1.0.0 installed separately outside WindowsApps/MSIX, on a host that passes the native ProcessContainer capability probe.
- OpenSSL on PATH for installation-specific Ed25519 key generation.
- PowerShell 7.3 or newer for the PowerShell harness example.
- Node >=20.3 for the TypeScript example, or Python >=3.11 with a compatible grpcio wheel and uv for the Python health example.

MXC, the Visual C++ runtime, Node, Python, and OpenSSL are not redistributed here. Rust and Visual Studio are unnecessary to run the kit.

## Verify and start

Verify the downloaded ZIP using its GitHub attestation and checksum as described in SIGNING.md. Extract the entire archive and keep all four executables and libz3.dll together. From the extracted directory:

```powershell
.\scripts\Test-OpenShellPackage.ps1
.\scripts\Test-OpenShellHost.ps1 -WxcExecPath <absolute-path-to-wxc-exec.exe>
.\scripts\Initialize-OpenShell.ps1 -WxcExecPath <absolute-path-to-wxc-exec.exe>
.\scripts\Start-OpenShell.ps1
```

Initialization creates private per-installation keys and state under `%LOCALAPPDATA%\OpenShell\Windows-0.1.8`. Existing initialization is not overwritten. Use `-StateDirectory` consistently for another installation, and `-Port` during initialization if 17670 is occupied.

The foreground gateway listens on `http://127.0.0.1:17670` without user authentication. Any local process can call it. Use only on a trusted development host and do not expose it on a network. Internal supervisor authentication uses the generated keys. The gateway database is in memory; delete sandboxes before stopping the gateway and recreate them after restart.

## Harness examples

In a second PowerShell 7.3+ terminal:

```powershell
.\examples\powershell\harness.ps1
```

For TypeScript:

```powershell
Push-Location .\examples\typescript
npm install ..\..\sdk\nvidia-openshell-sdk-0.1.8.tgz
node .\harness.mjs
Pop-Location
```

The command examples create a cmd.exe workload, check its workspace output, and request deletion. The TypeScript example also checks completion and waits for asynchronous cleanup. Dependencies download from npm; the local SDK tarball requires no GitHub Packages credentials.

For the Python health check, select an interpreter supported by grpcio:

```powershell
uv venv .venv
uv pip install --python .venv\Scripts\python.exe .\sdk\openshell-0.1.8-py3-none-any.whl
uv run --no-project --python .venv\Scripts\python.exe .\examples\python\health.py
```

The Python wheel is pure Python; that does not establish native ARM64 compatibility of its dependencies. Examples are not substitutes for the validation report.

The `-AllowUnsigned` switch exists solely for deliberate candidate testing. A package requiring it is not release-ready.
