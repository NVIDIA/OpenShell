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
- Giedrius's policy mapper crate wired as the primary `PolicyMapper` binding
  (until then the `StubPolicyMapper` grants only `share_dir` as read-write)

## PolicyMapper seam

Policy translation (`SandboxPolicy` → MXC `ContainerConfig`) is delegated to
Giedrius's Rust mapper crate via the `policy::PolicyMapper` trait. Until that
crate lands, `StubPolicyMapper` applies only the `share_dir` grant and rejects
everything else. **No live agent runs** until the real mapper is wired.

## Deferred work

- **Interactive exec/connect/forward** → `adapt-openshell-gateway-windows`
- **Governed egress / network policy** → `implement-openshell-mxc-egress-proxy`
- **Restart durability** (deprovision orphaned sessions on startup) → follow-on
- **GPU passthrough** → not pursued in host-side-governance design
