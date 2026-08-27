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

| Capability | MXC driver |
|---|---|
| Filesystem policy | Read-only/read-write grants come only from `SandboxPolicy`. `process_container` enforces default-deny; `isolation_session` is an explicit grant-only compatibility mode. |
| Network policy | Rejected synchronously during sandbox creation until an enforcing egress path is bound. |
| Process policy | Unsupported; MXC supplies OS isolation only. |
| Interactive exec/connect/forward | Unsupported; the configured workload runs in-driver. |
| Restart durability | Unsupported; the in-memory registry cannot recover live sessions. |

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
debug = false
```

Supply workload settings for each sandbox. The public config is keyed by driver name; the gateway forwards only the inner `mxc` object to the driver:

```powershell
$config = '{"mxc":{"command":["cmd","/c","echo hello > C:\\\\work\\\\demo\\\\hello.txt"],"cwd":"C:\\\\work\\\\demo"}}'
openshell sandbox create --name mxc-demo --policy demo.yaml `
  --driver-config-json $config --env MODE=demo --no-tty
```

The `command` array is required and preserves Windows argument boundaries. `cwd` is optional. Environment variables come from the standard sandbox and template environment maps; the driver never copies values from the gateway host environment.

Network policy and live policy replacement or merge updates are rejected while the gateway uses MXC. Delete and recreate the sandbox to apply a different filesystem policy.

## Prerequisites (live runs)

- Windows 11 Insider build ≥ 26300.8553
- `IsoSessionApp.dll` present and registered
- `wxc-exec.exe` built with `--features isolation_session`

For off-box smoke tests against the in-process mock shim (no `wxc-exec`,
no isolation session needed), set `OPENSHELL_MXC_MOCK_WXC=1`.

## Policy mapping

The production driver maps the typed `SandboxPolicy` to MXC configuration before it inserts a registry entry or invokes `wxc-exec`. Mapping failure therefore returns from `CreateSandbox` without leaving a partial sandbox.

`EmbeddedPolicyMapper` calls the embedded [`policy_map`](src/policy_map/) module directly and normalizes filesystem paths to Windows form. It does not add gateway-configured host paths. The policy supplied for the sandbox is the only source of filesystem grants.

The mapper retains an internal policy-splitting seam for future development, but the runtime exposes no governed-egress switch. Any network rule fails closed until an enforcing proxy is implemented and bound to the sandbox lifecycle.

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

- **Interactive exec/connect/forward** → `adapt-openshell-gateway-windows`
- **Governed egress** remains fail-closed until an enforcing proxy is implemented and bound to sandbox lifecycle.
- **Restart durability** (deprovision orphaned sessions on startup) → follow-on
- **GPU passthrough** → not pursued in host-side-governance design
