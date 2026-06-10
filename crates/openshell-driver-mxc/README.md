# openshell-driver-mxc

OpenShell compute driver backed by **Microsoft MXC** (`wxc-exec`) on Windows.

## Design

This driver implements the gateway's `ComputeDriver` gRPC contract as an
**in-process library** linked into `openshell-gateway`. It drives MXC through
the state-aware lifecycle (`provision` → `start` → `exec` → `stop` →
`deprovision`), runs the agent **inside the driver** (exec-in-driver), and
**self-reports readiness** — there is no in-sandbox supervisor, no host-side
surrogate, and no `ConnectSupervisor` relay. See
`docs/reference/mxc-compute-driver-design.mdx` for Shailendra's full
architectural rationale (decisions D1–D4).

## Capability Matrix (June 15 demo slice)

| Capability | MXC driver | Closing it requires |
|---|---|---|
| Filesystem policy (read-write / read-only grants) | ✅ provision-time AppContainer shares | — |
| Governed egress (CONNECT proxy + OPA + L7) | ❌ | `implement-openshell-mxc-egress-proxy` |
| Network policy | ❌ `isolation_session` rejects network config | MXC feedback item M1 + egress skill |
| Process policy (seccomp, uid/gid) | ❌ host-side governance design; OS isolation only | not pursued |
| Interactive exec/connect/forward | ❌ exec runs in-driver, no client attach | `adapt-openshell-gateway-windows` |
| Bundled agent image | ❌ no OCI image; relies on Windows host install | — |
| Restart durability | ❌ in-memory registry; restart orphans live sessions | follow-on |
| Concurrent sandboxes | ⚠️ isolation_session v1 is single-session | MXC backend feature |

The June 15 demo proof point is **filesystem policy enforcement**:
- **Positive**: write to the in-policy `share_dir` succeeds; `hello.txt` appears on the host.
- **Negative**: write outside the policy fails with Windows access-denied; driver emits a
  `DriverPlatformEvent` denial and the exec exits non-zero.

## Configuration (`[openshell.drivers.mxc]`)

```toml
[openshell.drivers.mxc]
# Path to wxc-exec.exe (required for live runs)
wxc_exec_path = "C:\\path\\to\\wxc-exec.exe"
# MXC configurationId — never use "small" (known OS bug)
default_configuration_id = "composable"
# Agent command executed inside the sandbox
agent_command = ["cmd", "/c", "echo hello > C:\\work\\demo\\hello.txt"]
# Working directory for the agent (defaults to share_dir)
agent_cwd = "C:\\work\\demo"
# Host directory mapped read-write into the sandbox
share_dir = "C:\\work\\demo"
# Enable --debug on wxc-exec invocations
debug = false
```

Or via environment / CLI:
```
OPENSHELL_DRIVERS=mxc openshell-gateway ...
openshell-gateway --drivers mxc ...
```

## Prerequisites (live runs)

- Windows 11 Insider build ≥ 26300.8553
- `IsoSessionApp.dll` present and registered
- `wxc-exec.exe` built with `--features isolation_session`

For off-box smoke tests against the in-process mock shim (no `wxc-exec`,
no isolation session needed), set `OPENSHELL_MXC_MOCK_WXC=1`.

## PolicyMapper seam

Policy translation (`SandboxPolicy` → MXC `ContainerConfig`) is delegated to
a `policy::PolicyMapper` trait. The primary implementation,
`EmbeddedPolicyMapper`, calls the embedded [`policy_map`](src/policy_map/)
module's `map_to_mxc` directly on the typed proto (no YAML bridge), then
normalizes the resulting filesystem paths to Windows form. `policy_map/` is
the **source of truth** for the OpenShell→MXC mapping — it was the standalone
`openshell-policy-mapper` crate, now embedded as a module here. The original
`StubPolicyMapper` is retained as a documented, compile-only fallback that only
maps `share_dir`.

Everything in this crate — including the mapper, the
[`policy-to-mxc`](examples/policy-to-mxc.rs) example, and the parity tests in
[`tests/policy_mapper_examples.rs`](tests/policy_mapper_examples.rs) — is
Windows-only (`#[cfg(target_os = "windows")]`); the crate is an empty stub on
other platforms. The mapper's parity tests therefore run on the Windows MSVC
test lane (`mise run windows:test:x64`), not the Linux lane.

## Packaging the demo for the demo box

Use [`examples/package-demo.ps1`](examples/package-demo.ps1) to assemble
the gateway EXE, CLI EXE, runtime DLLs (`libz3.dll`), `demo.yaml`, the
gateway config, and the runbook into one folder, then copy that folder to
the demo Windows host and follow `mxc-demo-runbook.md` inside it. The
script prints a SHA256 manifest so the operator can sanity-check what
landed before moving it.

## Deferred work

- **Interactive exec/connect/forward** → `adapt-openshell-gateway-windows`
- **Governed egress / network policy** → `implement-openshell-mxc-egress-proxy`
- **Restart durability** (deprovision orphaned sessions on startup) → follow-on
- **GPU passthrough** → not pursued in host-side-governance design
