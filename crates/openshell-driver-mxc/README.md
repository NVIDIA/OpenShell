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
The driver launches and monitors the configured workload and self-reports
readiness. Optional `openshell-supervisor-relay` wrapping provides launch,
shutdown, and dynamic forwarding over an inherited stdin/stdout control channel;
it does not implement the Linux `ConnectSupervisor` protocol.

## Capability Matrix

| Capability | MXC driver |
|---|---|
| Filesystem policy | Read-only/read-write grants come only from `SandboxPolicy`. `process_container` enforces default-deny; `isolation_session` is an explicit grant-only compatibility mode. |
| UI policy | `process_container` advertises complete support and maps portable graphical UI, clipboard-direction, and input-injection controls to MXC; omitted fields inside an explicit section deny. `isolation_session` advertises no support, so the gateway rejects any explicit section before provisioning. |
| Network policy | With `egress_proxy = true` on `process_container`, split into MXC 0.8 loopback-only egress plus the full policy enforced by a per-sandbox OpenShell host CONNECT proxy. The driver injects proxy environment variables for proxy-aware clients; direct Internet access remains denied by MXC. Otherwise rejected synchronously. `isolation_session` remains fail-closed. |
| Provider credentials | The child receives revision-scoped placeholders and non-secret provider environment only. The per-sandbox host proxy retains the resolver and substitutes credentials only for their bound endpoints. |
| Process policy | Unsupported; MXC supplies OS isolation only. |
| Dynamic forwarding | Supported through `openshell-supervisor-relay`; interactive exec/connect remain unsupported. |
| Network middleware | Rejected before launch until the host proxy receives the gateway middleware registry. |
| ETW/OCSF audit | Optional Windows Sandboxing ETW consumer attributes host events to OpenShell sandboxes and emits OCSF records. |
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
# processContainer only: launch openshell-supervisor-relay instead of
# agent_command/legacy command directly, giving the driver a control
# channel into the sandbox (launch handshake, dynamic `openshell forward
# service` bridging). target_port is the launched command's own listening
# port; 0 disables spawner wrapping (default -- the command runs directly).
pc_relay_spawner_path = ""
pc_relay_target_port  = 0
# processContainer only: env-inheritance tier for the launched process
# (safest first): default is a minimal Windows CreateProcessW bootstrap set
# (SYSTEMROOT/WINDIR/PATH/COMSPEC/LOCALAPPDATA) + agent_env; pc_minimal_env
# starts from an EMPTY env (agent_env only) for runtimes that choke on an
# unrecognized host env; pc_inherit_full_env is an explicit unsafe opt-in
# to the gateway host's entire environment (secrets included) + agent_env,
# ignored when pc_minimal_env is also set.
pc_minimal_env = false
pc_inherit_full_env = false
# processContainer only: include "allowLocalNetwork": true in the MXC
# network section. This compatibility setting broadens network access and is
# not required by the BaseContainer qualification profile.
pc_allow_local_network = false
# Legacy workload settings, used only as a fallback when a sandbox's
# CreateSandbox request carries no --driver-config-json (see below) --
# agent_command is required for a sandbox to succeed via this fallback path.
agent_command = ["cmd", "/c", "echo hello > C:\\work\\demo\\hello.txt"]
agent_cwd = "C:\\work\\demo"
# Host directory mapped read-write into the sandbox. NOT an automatic
# filesystem grant on its own -- the sandbox's SandboxPolicy is the only
# source of filesystem grants, so a policy's filesystem_policy.read_write
# must include this path explicitly for the workload to reach it.
share_dir = "C:\\work\\demo"
# Pattern C governed egress. Requires backend = "process_container".
egress_proxy = false
egress_proxy_addr = ""
debug = false
etw_audit = false
```

When `egress_proxy` is enabled, `egress_proxy_addr` must be a loopback
`IP:PORT` seed. The driver preserves the configured IP and allocates a unique
ephemeral port for each sandbox's authenticated host CONNECT proxy.

Supply workload settings for each sandbox. The public config is keyed by driver name; the gateway forwards only the inner `mxc` object to the driver:

```powershell
$config = '{"mxc":{"command":["cmd","/c","echo hello > C:\\\\work\\\\demo\\\\hello.txt"],"cwd":"C:\\\\work\\\\demo"}}'
openshell sandbox create --name mxc-demo --policy demo.yaml `
  --driver-config-json $config --env MODE=demo --no-tty
```

The `command` array is required and preserves Windows argument boundaries. `cwd` is optional. Per-sandbox environment variables come from the standard sandbox and template environment maps only; this path never copies values from the gateway host environment. The legacy `agent_env`/`pc_inherit_full_env` TOML fields above are a separate, gateway-wide mechanism and are the only way the gateway host's own environment reaches a sandbox -- bare `agent_env` keys opt specific host values in. Provider-owned keys override matching entries case-insensitively, but raw static values remain in the host proxy; MXC receives their revision-scoped placeholders. When governed egress is enabled, the driver replaces common TLS trust environment variables with paths to public proxy CA files staged under `share_dir`, and injects `HTTP_PROXY`/`HTTPS_PROXY` while clearing `NO_PROXY` so inherited bypass rules cannot skip policy enforcement.

UI capability (Win32k syscalls, clipboard, input injection) is a `SandboxPolicy` concern, not gateway TOML -- see the Capability Matrix above and `docs/reference/policy-schema.mdx`'s `ui` section. Defaults to disabled (Win32k syscall lockdown) when a policy has no explicit `ui:` section; set `allow_graphical_ui: true` for agents that touch user32/gdi32 at startup even without opening a real window (e.g. Node.js-based targets like OpenClaw's gateway -- see `examples/e2e-policies/openclaw-gateway.yaml`).

`egress_proxy_addr` must be a `127.0.0.1:PORT` address. The port acts only as a configuration seed: the driver reserves a unique ephemeral loopback port for every sandbox. MXC 0.8 denies direct Internet egress and permits `127.0.0.1/32`; the driver points proxy-aware clients at the per-sandbox listener using environment variables. The current policy permits all loopback ports, so sandboxes can also reach unrelated host services bound to loopback. Control-channel forwarding does not require the legacy reverse-WebSocket connections to fresh host ports; restricting the generated policy is separate hardening work. Do not treat this path as loopback-service isolation. Live policy replacement or merge updates remain unsupported; delete and recreate the sandbox to apply a different policy.

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

Each sandbox receives a distinct proxy listener and a random per-sandbox credential through its proxy environment. Missing, incorrect, duplicate, or another sandbox's proxy credentials receive HTTP 407 before policy evaluation or forwarding. This authenticates requests to the OpenShell proxy; it does not restrict access to unrelated host-loopback services or authenticate individual processes inside a sandbox. Proxy credentials and command/environment payloads must not be logged.

The MXC credential handoff is also fixed at sandbox creation. The gateway rejects expiring static provider credentials because the in-process MXC driver has no live credential-refresh channel. Dynamic token grants remain request-time operations in the host proxy. Recreate the sandbox after rotating or revoking a non-expiring static credential.

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
instead: MXC receives filesystem grants plus loopback-only egress,
and the driver starts a host CONNECT proxy from the trimmed
network-only `SandboxPolicy`. Policies containing `network_middlewares` are
rejected synchronously until this host-proxy path can receive the gateway's
built-in and remote middleware registry. The proxy uses the configured agent
command as the static sandbox process identity because MXC does not expose
Linux-style procfs socket ownership. For HTTPS L7 inspection, the host proxy generates a
per-sandbox CA and injects `NODE_EXTRA_CA_CERTS`, `DENO_CERT`, `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO` into the agent
process env. In curated-environment mode, the driver stages the public CA files
under the authorized `share_dir/.openshell-proxy/<sandbox-id>` directory. Other
environment modes grant the sandbox's unique public-CA directory as an internal
read-write share. The directory contains only public CA certificates;
the ephemeral CA private key remains in the host proxy's memory. The driver
seeds only `SYSTEMROOT`, `WINDIR`, `PATH`, `COMSPEC`, and `LOCALAPPDATA` from the
gateway host before applying sandbox and TLS overrides, so required Windows
bootstrap values remain available without exposing the gateway's full
environment unless the gateway explicitly opts into another environment mode.

When governed egress is disabled, any network rule fails closed during sandbox creation.

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

This example uses `process_container`. The `IsoSessionApp.dll` and
`--features isolation_session` prerequisites above apply only to
`isolation_session` runs and are not required for this scenario.

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
`C:\mxc\wxc-exec.exe` lookup. Run the probe on the actual test host; a different
machine's capability report is not evidence that its backend is available here.

## Deferred work

- **Interactive exec/connect** — gateway interactive-exec integration (follow-on); dynamic service forwarding is supported through the relay.
- **Persistent-session governed egress** remains fail-closed until `isolation_session` exposes an enforceable proxy path.
- **Restart durability** (deprovision orphaned sessions on startup) → follow-on
- **GPU passthrough** → not pursued in host-side-governance design
