# Native Windows support

The [`windows` branch](https://github.com/NVIDIA/OpenShell/tree/windows) is the
development and release branch for native Windows OpenShell. The Windows
implementation stays on that branch. This guide and other shared documentation
can also appear on `main`; their presence there does not move the Windows
implementation or release source to `main`.

Native Windows uses Microsoft MXC ProcessContainer isolation on x64 and ARM64.
It is separate from running Linux OpenShell inside WSL 2. Docker, Podman,
Kubernetes, and MicroVM are not native Windows compute backends.

## Runtime and current limits

The gateway links the MXC compute driver. It starts a trusted
`openshell-supervisor.exe` on the host and an
`openshell-windows-sandbox.exe` boundary inside each ProcessContainer. The pair
uses the authenticated Sandbox Protocol for process operations and forwarding.
The host supervisor applies network policy and endpoint-bound provider credentials
through an authenticated explicit proxy. Workloads must support that proxy.

MXC maps filesystem and UI policy to native controls. This implementation is
under development and is not a production-qualified security boundary:

- Outer-fence guarantees are temporarily asserted for compatibility testing.
  Exclusive supervisor-mediated egress and live access revocation are unverified.
- The loopback exception can expose unrelated host-local services to workloads.
  Treat the gateway host as trusted.
- Foreground main-process attachment and ConPTY resize are unavailable. Create
  command workloads with `--detach`.
- Gateway restart recovery for live MXC generations is not supported.

See the Windows branch's [MXC driver documentation](https://github.com/NVIDIA/OpenShell/blob/windows/crates/openshell-driver-mxc/README.md)
for the current capabilities and enforcement limits, and its
[boundary library documentation](https://github.com/NVIDIA/OpenShell/blob/windows/crates/openshell-mxc-boundary/README.md)
for the runtime architecture. Passing build or E2E checks does not establish
the missing security guarantees.

## Get the Windows source

Use a separate checkout so an existing `main` checkout can remain in place:

```powershell
git clone --branch windows https://github.com/NVIDIA/OpenShell.git OpenShell-windows
Set-Location OpenShell-windows
mise trust
```

Base native Windows implementation changes on `windows` and target that branch
for review. Documentation-only changes can also merge into `main`, while
retaining explicit `windows` branch links for Windows code, tasks, and runtime
instructions. The `main` installer and its dev, prerelease, and stable artifacts
are not the native Windows distribution path.

## Build

Use Windows with rustup, mise, Visual Studio C++ Build Tools, a Windows SDK,
and host-compatible LLVM/libclang. Install the MSVC components for each target
you build, including ARM64 tools and Spectre-mitigated libraries for ARM64.
The [Windows build skill](https://github.com/NVIDIA/OpenShell/blob/windows/.agents/skills/build-openshell-mxc-windows/SKILL.md)
lists the full prerequisites and environment overrides.

Run the build matching your target:

```powershell
# x64
mise run --skip-tools windows:build:x64

# ARM64
mise run --skip-tools windows:build:arm64
```

The tasks produce `openshell.exe`, `openshell-gateway.exe`,
`openshell-supervisor.exe`, and `openshell-windows-sandbox.exe` under
`target/<target-triple>/release/`. Keep these binaries from the same build
together with the matching `libz3.dll` staged by the build task. The target
triples are `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`.
`CARGO_TARGET_DIR` can override the output root.

The build uses pinned prebuilt Z3 by default. Compile and test hosts do not
need a working MXC runtime; running native sandboxes does. These tasks do not
install an MSI, register a Windows service, or publish a release.

## Prepare and run MXC

Use MXC 1.0.0 and a host that passes the native ProcessContainer capability
probe. Place `wxc-exec.exe` outside `WindowsApps` or an MSIX package directory
and configure its absolute path.

```powershell
& "C:\mxc\wxc-exec.exe" --probe
```

`probes.baseContainerSupportsIngressHostLoopbackAllow` must be `true`.
A Windows version number alone does not establish runtime compatibility.
Configure `compute_driver = "mxc"` and use the matching
[Windows gateway configuration](https://github.com/NVIDIA/OpenShell/blob/windows/docs/how-it-works/gateways/configuration.mdx#configure-mxc)
and [example gateway TOML](https://github.com/NVIDIA/OpenShell/blob/windows/crates/openshell-driver-mxc/examples/mxc-gateway.toml).
Command-based sandbox creation requires administrator opt-in with
`allow_driver_config = true`, a workload command and working directory, and
`--detach`. Use a sandbox policy to grant the required filesystem and network
access.

## Validate

Follow [native Windows validation](https://github.com/NVIDIA/OpenShell/blob/windows/TESTING.md#native-windows-validation)
for native x64 or ARM64 lint, build, unit tests, and real MXC tests. Cross-building
ARM64 on x64 does not run native ARM64 tests. Real MXC tests and E2E require a
capable host; record probe-gated skips separately from passes.

The [Windows CI guidance](https://github.com/NVIDIA/OpenShell/blob/windows/CI.md#windows-validation)
describes opt-in PR checks and branch builds. A successful compilation or an
advisory CI run is not a Windows release qualification result.
