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
| Governed egress (CONNECT proxy + OPA + L7) | Available behind `egress_proxy` on `process_container`; host proxy integration is the next consumer | `implement-openshell-mxc-egress-proxy` |
| Network policy | Split into MXC `network.proxy` + trimmed OpenShell policy on `process_container`; `isolation_session` still rejects network config | MXC feedback item M1 for persistent sessions |
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
# MXC backend: "isolation_session" (default) or "process_container"
backend = "process_container"
# MXC configurationId — never use "small" (known OS bug)
default_configuration_id = "composable"
# process_container-only options
pc_least_privilege = false
pc_capabilities = []
# Agent command executed inside the sandbox
agent_command = ["cmd", "/c", "echo hello > C:\\work\\demo\\hello.txt"]
# Working directory for the agent (defaults to share_dir)
agent_cwd = "C:\\work\\demo"
# Host directory mapped read-write into the sandbox
share_dir = "C:\\work\\demo"
# Pattern C governed egress. Requires backend = "process_container" until
# MXC M1 adds network.proxy support for isolation_session.
egress_proxy = false
egress_proxy_addr = ""
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

When `egress_proxy` is enabled, `EmbeddedPolicyMapper` uses `split_policy`
instead: MXC receives filesystem grants plus a loopback `network.proxy`
redirect, and the driver stores the trimmed network-only `SandboxPolicy` for
the host CONNECT proxy. The development export surface remains the
[`policy-to-mxc`](examples/policy-to-mxc.rs) example; there is no production
`openshell policy export-mxc` subcommand yet.

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

## Real-MXC test lane

Three tasks drive real `wxc-exec.exe` hardware; all are **skip-safe** — any test
or scenario that requires an absent binary or backend prints a SKIP reason and
exits 0 rather than failing.

| Task | What it runs | When to use |
|---|---|---|
| `windows:test:mxc-real:x64` | `tests/wxc_exec_real.rs` — Tier-2 invoker tests with `--ignored --test-threads=1` | Pre-merge on any Windows host that has `wxc-exec`; dry-run tests always pass; enforcement tests probe-gate themselves |
| `windows:e2e:mxc` | `examples/run-mxc-e2e.ps1` — Tier-3 scenario runner, real binary, probe-gated | Demo box / nightly; needs the gateway + CLI binaries in the script directory |
| `windows:e2e:mxc:mock` | Same runner with `-Mock` — wiring-only, no real `wxc-exec` needed | Any Windows host (CI, dev machine); validates wiring and the network-reject scenario |

**Probe script:** `examples/probe-mxc-host.ps1` emits a JSON capability report
(OS build, wxc-exec path/version, dry-run exit code, per-backend trial result,
and a `verdicts` object). Run it before the real-MXC lane to understand what
will PASS vs SKIP on a given host:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File crates/openshell-driver-mxc/examples/probe-mxc-host.ps1
```

**Skip semantics:** tests in `wxc_exec_real.rs` are marked
`#[ignore = "requires real wxc-exec"]` — the standard `windows:test:x64` suite
never runs them. `OPENSHELL_WXC_EXEC_PATH` overrides the default
`C:\mxc\wxc-exec.exe` lookup. See `docs4gtb/mxc-box-capabilities.md` for the
empirical capability snapshot of the development box (build 26200, processcontainer
velocity keys not enabled, isolation_session absent).

## Deferred work

- **Interactive exec/connect/forward** → `adapt-openshell-gateway-windows`
- **Governed egress proxy implementation** → `implement-openshell-mxc-egress-proxy`
- **Restart durability** (deprovision orphaned sessions on startup) → follow-on
- **GPU passthrough** → not pursued in host-side-governance design
