# openshell-driver-mxc

OpenShell compute driver backed by **Microsoft MXC** (`wxc-exec`) on Windows.

## Design

This driver implements the gateway's `ComputeDriver` contract as an in-process
library linked into `openshell-gateway`. `process_container` launches a one-shot
AppContainer and is the default. The opt-in `isolation_session` backend uses the
state-aware `provision` → `start` → `exec` → `stop` → `deprovision` lifecycle.
The driver launches and monitors the configured workload itself and self-reports
readiness; there is no in-sandbox supervisor or `ConnectSupervisor` relay.

## Capability Matrix

| Capability | MXC driver | Closing it requires |
|---|---|---|
| Filesystem policy (read-write / read-only grants) | ✅ provision-time AppContainer shares | — |
| Governed egress (CONNECT proxy + OPA + L7) | Available behind `egress_proxy` on `process_container`; the driver starts a per-sandbox host CONNECT proxy, generates HTTPS MITM trust material, and injects the CA bundle into the sandbox process env | Gateway event-bus wiring follow-on |
| Network policy | Split into MXC `network.proxy` + trimmed OpenShell policy on `process_container`; `isolation_session` still rejects network config | MXC feedback item M1 for persistent sessions |
| Process policy (seccomp, uid/gid) | ❌ host-side governance design; OS isolation only | not pursued |
| Interactive exec/connect/forward | ❌ exec runs in-driver, no client attach | gateway interactive-exec surgery (follow-on) |
| Bundled agent image | ❌ no OCI image; relies on Windows host install | — |
| Restart durability | ❌ in-memory registry; restart orphans live sessions | follow-on |
| Concurrent sandboxes | ⚠️ isolation_session v1 is single-session | MXC backend feature |

The filesystem enforcement proof has two paths:

- A write to a path granted by the sandbox policy succeeds.
- A `process_container` write outside the sandbox policy fails with Windows access denied, and the driver reports the failed workload.

## Configuration (`[openshell.drivers.mxc]`)

Gateway configuration contains only host runtime settings:

```toml
[openshell.drivers.mxc]
wxc_exec_path = "C:\\path\\to\\wxc-exec.exe"
# Default: process_container. isolation_session is grant-only and opt-in.
backend = "process_container"
default_configuration_id = "composable"
pc_least_privilege = false
pc_capabilities = []
# Pattern-C governed egress. The address is a loopback seed; each sandbox
# receives a unique ephemeral proxy port.
egress_proxy = false
egress_proxy_addr = ""
debug = false
```

When `egress_proxy` is enabled, `egress_proxy_addr` must be a loopback
`IP:PORT` seed. The driver preserves the configured IP and allocates a unique
ephemeral port for each sandbox's `network.proxy` redirect.

Supply workload settings for each sandbox. The public config is keyed by driver name; the gateway forwards only the inner `mxc` object to the driver:

```powershell
$config = '{"mxc":{"command":["cmd","/c","echo hello > C:\\\\work\\\\demo\\\\hello.txt"],"cwd":"C:\\\\work\\\\demo"}}'
openshell sandbox create --name mxc-demo --policy demo.yaml `
  --driver-config-json $config --env MODE=demo --no-tty
```

The `command` array is required and preserves Windows argument boundaries. `cwd` is optional. Environment variables come from the standard sandbox and template environment maps; the driver never copies values from the gateway host environment.

The host CONNECT proxy enforces network policy when governed egress is enabled. Live policy replacement or merge updates remain unsupported; delete and recreate the sandbox to apply a different policy.

## Prerequisites (live runs)

- Windows 11 Insider build ≥ 26300.8553
- `IsoSessionApp.dll` present and registered
- `wxc-exec.exe` built with `--features isolation_session`

For off-box smoke tests against the in-process mock shim (no `wxc-exec`,
no isolation session needed), set `OPENSHELL_MXC_MOCK_WXC=1`.

## Policy mapping

The production driver maps the typed `SandboxPolicy` to MXC configuration before it inserts a registry entry or invokes `wxc-exec`. Mapping failure therefore returns from `CreateSandbox` without leaving a partial sandbox.

When `egress_proxy` is enabled, `EmbeddedPolicyMapper` uses `split_policy`
instead: MXC receives filesystem grants plus a loopback `network.proxy`
redirect, and the driver starts a host CONNECT proxy from the trimmed
network-only `SandboxPolicy`. The proxy uses the configured agent command as
the static sandbox process identity because MXC does not expose Linux-style
procfs socket ownership. For HTTPS L7 inspection, the host proxy generates a
per-sandbox CA, grants the CA directory read-only in MXC, and injects
`NODE_EXTRA_CA_CERTS`, `DENO_CERT`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO` into the agent process env. The
development export surface remains the
[`policy-to-mxc`](examples/policy-to-mxc.rs) example; there is no production
`openshell policy export-mxc` subcommand yet.

If governed egress is disabled, any network rule fails closed rather than launching without an enforcement path.

Parity and matrix tests under [`tests/`](tests/) cover the mapper on the Windows MSVC lane. The driver performs this mapping automatically; there is no separate policy-export command or example.

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

**Probe script:** `examples/probe-mxc-host.ps1` is an operator/CI preflight that emits a JSON capability report
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

- **Interactive exec/connect/forward** — gateway interactive-exec surgery (follow-on)
- **Governed egress polish** — gateway denial/activity bus wiring,  broader real-MXC HTTPS L7 scenario coverage, and per-sandbox port allocation
- **Restart durability** (deprovision orphaned sessions on startup) → follow-on
- **GPU passthrough** → not pursued in host-side-governance design
