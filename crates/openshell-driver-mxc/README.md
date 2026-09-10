# openshell-driver-mxc

OpenShell compute driver backed by **Microsoft MXC** (`wxc-exec`) on Windows.

## Design

This driver implements the gateway's ordinary in-process `ComputeDriver`
contract and is linked into `openshell-gateway`. It sets
`driver_reports_runtime_readiness`, so the gateway accepts driver-reported
readiness without a supervisor session. The gateway composes the create-time
effective `SandboxPolicy` and carries it on the driver-only copy of
`DriverSandboxSpec.policy`. `process_container` launches a one-shot AppContainer
and is the default. The opt-in `isolation_session` backend uses the
state-aware `provision` → `start` → `exec` → `stop` → `deprovision` lifecycle.
The driver launches and monitors the configured workload itself and self-reports
readiness; there is no in-sandbox supervisor or `ConnectSupervisor` relay.

## Capability Matrix

| Capability | MXC driver | Closing it requires |
|---|---|---|
| Filesystem policy (read-write / read-only grants) | ✅ provision-time AppContainer shares | — |
| UI policy | `process_container` advertises complete support and maps portable graphical UI, clipboard-direction, and input-injection controls to MXC; omitted fields inside an explicit section deny. `isolation_session` advertises no support, so the gateway rejects any explicit section before provisioning. | MXC support for persistent sessions |
| Governed egress (CONNECT proxy + OPA + L7) | Available behind `egress_proxy` on `process_container`; the driver starts a per-sandbox host CONNECT proxy, generates HTTPS MITM trust material, and injects the CA bundle into the sandbox process env | Gateway event-bus wiring follow-on |
| Network policy | Split into MXC `network.proxy` + trimmed OpenShell policy on `process_container`; `isolation_session` still rejects network config | MXC feedback item M1 for persistent sessions |
| Provider credentials | The child receives revision-scoped placeholders and non-secret provider environment only. The per-sandbox host proxy retains the resolver and substitutes credentials only for their bound endpoints. | — |
| Network middleware | ❌ rejected before launch because the MXC host proxy does not receive the gateway middleware registry | Gateway middleware-registry injection |
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
etw_audit = false
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

The `command` array is required and preserves Windows argument boundaries. `cwd`
is optional. Environment variables come from the standard sandbox and template
environment maps; the driver never copies values from the gateway host
environment. Provider-owned keys override matching entries case-insensitively.
MXC receives revision-scoped placeholders and explicitly classified non-secret
provider configuration, while credential values remain in the host proxy. When
governed egress is enabled, the driver replaces common TLS trust environment
variables with paths to the proxy-generated CA material and grants that
sandbox-unique CA directory read-write so the AppContainer can read it.

The host CONNECT proxy enforces network policy when governed egress is enabled.
Live policy replacement or merge updates remain unsupported; delete and recreate
the sandbox to apply a different policy.

When `etw_audit` is enabled, each gateway process owns a distinct real-time ETW
session named from the stable `OpenShell-MXC-ETW` prefix, its process ID, and a
per-start discriminator. Starting another gateway never stops an existing
gateway's capture. Graceful shutdown stops the session by its owned handle. A
force-killed gateway can leave a stale session; the audit example removes only
matching sessions whose encoded owner process is no longer running.

The gateway-local OCSF JSONL sink is available only for the Windows/MXC path
and is opt-in. Set `OPENSHELL_OCSF_JSON=1` to enable it and optionally set
`OPENSHELL_OCSF_LOG_DIR` to override its `%PROGRAMDATA%\OpenShell\logs` default.
Other gateway deployments do not initialize this local file sink.

The ETW callback uses a non-blocking queue capped at 4,096 records and 16 MiB
of copied event data. Records that exceed either limit are dropped instead of
blocking the ETW pump or growing gateway memory. The gateway emits an immediate
warning identifying the audit coverage gap and rate-limits follow-up warnings
to once every 30 seconds while overload continues.

Audit attribution bootstraps only when the driver-owned `wxc-exec` PID and its
kernel process start key both match the values attached to the ETW record;
command text is never an ownership key. This generation key prevents a recycled
PID from inheriting the previous process's attribution regardless of delivery
delay. The process monitor retires the live PID at exit. Established identity,
activity, and correlation-vector links remain available for five seconds so
already in-flight ETW records can arrive, but retired PID evidence cannot resolve
them. Records without matching generation evidence remain unattributed.

## Prerequisites (live runs)

- Windows 11 Insider build ≥ 26300.8553
- `IsoSessionApp.dll` present and registered
- `wxc-exec.exe` built with `--features isolation_session`
- Any enforced App Control policy allows both `openshell-gateway.exe` and
  `openshell.exe`. Diagnose executable blocks with event 3077 in the
  `Microsoft-Windows-CodeIntegrity/Operational` log.

For off-box smoke tests against the in-process mock shim (no `wxc-exec`,
no isolation session needed), set `OPENSHELL_MXC_MOCK_WXC=1`.

## Policy mapping

The production driver maps the typed `SandboxPolicy` carried by the standard
driver request to MXC configuration before it inserts a registry entry or
invokes `wxc-exec`. Mapping failure therefore returns from `CreateSandbox`
without leaving a partial sandbox. There is no in-process policy side channel
or MXC-specific gateway composition variant. Provider resolver state uses a
separate, create-scoped in-process handoff because it intentionally cannot be
represented in the public compute-driver protobuf.

When `egress_proxy` is enabled, `EmbeddedPolicyMapper` uses `split_policy`
instead: MXC receives filesystem grants plus a loopback `network.proxy`
redirect, and the driver starts a host CONNECT proxy from the trimmed
network-only `SandboxPolicy`. Policies containing `network_middlewares` are
rejected synchronously until this host-proxy path can receive the gateway's
built-in and remote middleware registry. The proxy uses the configured agent
command as the static sandbox process identity because MXC does not expose
Linux-style procfs socket ownership. For HTTPS L7 inspection, the host proxy generates a
per-sandbox CA and injects `NODE_EXTRA_CA_CERTS`, `DENO_CERT`, `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO` into the agent
process env. It does not add the generated CA directory to MXC read-only grants:
released `wxc-exec` BaseContainer builds require `WRITE_DAC` on every such
grant and reject the user-owned proxy temp directory. Instead, the driver adds
the sandbox-unique directory as an internal read-write share so HTTPS clients
can read the injected paths. The directory contains only public CA certificates;
the ephemeral CA private key remains in the host proxy's memory. The driver
seeds only `SYSTEMROOT`, `WINDIR`, `PATH`, `COMSPEC`, and `LOCALAPPDATA` from the
gateway host before applying sandbox and TLS overrides, so required Windows
bootstrap values remain available without exposing the gateway's full
environment. The development export surface remains the
[`policy-to-mxc`](examples/policy-to-mxc.rs) example; there is no production
`openshell policy export-mxc` subcommand yet.

The mapper normalizes filesystem paths to Windows form and does not add
gateway-configured host paths. The policy supplied for the sandbox is the only
source of filesystem grants. For `process_container`, the driver advertises
`supports_ui_policy = true` and emits the top-level `ui` object shared by MXC's
0.8 stable and 0.9 development schemas, with restrictive defaults or the exact
requested clipboard direction, graphical UI setting, and input-injection
setting. `isolation_session` advertises false, so the gateway rejects explicit
UI policy before the driver RPC; the mapper also rejects it before lifecycle
side effects as defense in depth.

If governed egress is disabled, any network rule fails closed rather than launching without an enforcement path.

Parity and matrix tests under [`tests/`](tests/) cover the mapper on the Windows MSVC lane. The real-MXC lane also dry-runs every clipboard direction against the installed schema. The driver performs this mapping automatically; there is no separate policy-export command or example.

## Provider credential example

[`examples/run-provider-credential-test.ps1`](examples/run-provider-credential-test.ps1)
creates an MXC sandbox with an attached GitHub provider. Its policy explicitly
allows the graphical UI subsystem required by Windows PowerShell while denying
clipboard access and input injection; the existing policy mapper translates
that portable section to MXC's `ui` object. The probe verifies that the sandbox
sees a revision-scoped `GITHUB_TOKEN` placeholder, the host CONNECT proxy
substitutes it for `api.github.com`, and the same placeholder is rejected for a
different allowed endpoint.

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
| `windows:test:mxc-real:x64` | `tests/wxc_exec_real.rs` — Tier-2 invoker tests with `--ignored --test-threads=1`, including an HTTPS request through the host proxy | Pre-merge on any Windows host that has `wxc-exec`; dry-run tests always pass; enforcement tests probe-gate themselves |
| `windows:test:mxc-real:arm64` | Native ARM64 `tests/wxc_exec_real.rs` with the same contract | Pre-merge on an ARM64 Windows host with `wxc-exec` |
| `windows:e2e:mxc` | `examples/run-mxc-e2e.ps1` — Tier-3 scenario runner, real binary, probe-gated | Demo box / nightly; needs the gateway + CLI binaries in the script directory |
| `windows:e2e:mxc:mock` | Same runner with `-Mock` — wiring-only, no real `wxc-exec` needed | Any Windows host (CI, dev machine); validates wiring and the network-reject scenario |

**Probe script:** `examples/probe-mxc-host.ps1` is an operator/CI preflight that emits a JSON capability report
(OS build, wxc-exec path/version, dry-run exit code, per-backend trial result,
and a `verdicts` object). Run it before the real-MXC lane to understand what
will PASS vs SKIP on a given host:

The probe uses a unique, user-owned Windows temp directory for every run.
MXC treats config paths literally (it does not expand `%TEMP%`), and the
per-run directory keeps AppContainer+DACL fallback mutations narrowly scoped.

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
- **Restart durability** (deprovision orphaned sessions on startup) → follow-on
- **GPU passthrough** → not pursued in host-side-governance design
