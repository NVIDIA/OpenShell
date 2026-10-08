# openshell-driver-mxc

The Windows-only MXC compute driver runs each workload in a Microsoft MXC
ProcessContainer while preserving OpenShell's standard RFC 0012 runtime split:

```text
gateway / MXC driver
        |
        | gateway authentication and policy
        v
openshell-supervisor --role=isolation-backend   (host)
        |
        | generation-scoped TLS + sandbox JWT
        v
openshell-windows-sandbox                       (ProcessContainer)
        |
        v
workload
```

Caller driver config is disabled by default, so command-based MXC workflows
need explicit administrator opt-in. Host filesystem grants have no trusted
label resolver and are rejected while resource admission is enabled.
See [resource admission configuration](../../docs/how-it-works/gateways/configuration.mdx#external-resource-admission)
for the independent controls and the security consequences of opting out.

This driver implements the gateway's ordinary in-process `ComputeDriver`
contract and is linked into `openshell-gateway`. Runtime readiness comes from
the authenticated host supervisor session, not a driver-reported condition.
The resolved create-time `SandboxPolicy` is carried by
`DriverSandboxSpec.policy`. The driver provisions a one-shot ProcessContainer,
launches the Windows boundary and separate host supervisor, and monitors both.
The boundary launches the workload only after authenticated confirmation.

The driver resolves its gateway endpoint and TLS server-name defaults from
generic gateway inputs. The host supervisor authenticates its gateway session
and retains main-process attachment independently of the optional Unix SSH
adapter. TCP readiness remains gated by authenticated session acceptance.

Windows boundary execution is implemented by the `openshell-mxc-boundary`
library behind the dedicated `openshell-windows-sandbox.exe`. The compute driver does not
embed the supervisor, and the sandbox does not link the compute driver.
Dynamic forwarding uses the shared protocol stream, not a dedicated relay
executable or a reverse connection to a new gateway listener.

## Enforcement boundaries

The current port is not runtime-qualified against main's outer-fence contract.
Broad host-loopback access does not establish `NoUnmanagedEgressPath`, and
live access revocation has no verified native evidence. The driver therefore
does not publish those guarantees, and main's confirmation gate prevents
workload activation. Configuration intent must not be promoted to enforcement
proof. A qualified PSEC host is necessary but does not by itself close these
implementation gaps.

- MXC supplies the default-deny filesystem fence, AppContainer token, UI
  policy, and loopback-only network fence.
- `openshell-windows-sandbox` consumes its bootstrap files before launching untrusted
  code, authenticates the paired supervisor, and terminates workloads when an
  authenticated supervisor cannot recover within the reconnect deadline.
- The host supervisor owns an authenticated per-generation explicit proxy.
  Missing or cross-sandbox credentials receive HTTP 407 before policy
  evaluation. MXC denies direct Internet egress.
- The current explicit-proxy path attributes traffic to the admitted main
  workload binary. It does not distinguish descendant processes. MXC process
  policy must therefore prevent an untrusted allowed child binary from
  inheriting broader per-binary network rights.
- The loopback fence permits `127.0.0.1/32`; it does not isolate unrelated host
  services bound to that address. Treat the gateway host as trusted.
- Host supervisor tokens and descriptors live beneath an owner-only Windows
  DACL. Boundary bootstrap secrets live in the ProcessContainer staging path
  and are deleted before workload launch.

## Configuration

The packaged `openshell-supervisor.exe` and `openshell-windows-sandbox.exe` default to
siblings of `openshell-gateway.exe`. Override their paths for development
builds.

```toml
[openshell.drivers.mxc]
wxc_exec_path = "C:\\mxc-kit\\bin\\wxc-exec.exe"
supervisor_binary_path = "C:\\OpenShell\\openshell-supervisor.exe"
sandbox_binary_path = "C:\\OpenShell\\openshell-windows-sandbox.exe"
# Defaults to %LOCALAPPDATA%\OpenShell\mxc.
state_dir = "C:\\Users\\operator\\AppData\\Local\\OpenShell\\mxc"
# Empty uses the gateway's loopback listener and TLS mode.
grpc_endpoint = ""
backend = "process_container"
pc_least_privilege = false
pc_capabilities = []
pc_allow_local_network = true
pc_minimal_env = false
debug = false
etw_audit = false
```

Only `process_container` supports this architecture. `isolation_session` is
rejected during sandbox validation.

MXC 1.0.0 is required. Pre-1.0 executors and the retired
`default_configuration_id` setting are not supported; remove that setting
before upgrading. Both live launches and standalone mapper output use the
stable directional `network.egress` / `network.ingress` schema. The standalone
mapper emits numeric CIDRs and TCP ports, and reports DNS and L7 semantics as
mapping losses; the host supervisor continues to enforce the full network policy.

Supply the workload command and working directory per sandbox:

```powershell
$config = '{"mxc":{"command":["C:\\Windows\\System32\\cmd.exe","/d","/c","echo hello"],"cwd":"C:\\work"}}'
openshell sandbox create --name mxc-demo --policy policy.yaml `
  --driver-config-json $config --no-tty
```

The command is required. The working directory is required because it contains
the generation-scoped bootstrap staging directory. Environment belongs in
`--env` or `--env-from`, not gateway configuration.

When gateway TLS is enabled, configure the gateway-owned `guest_tls_ca`.
The host supervisor verifies the gateway certificate with that CA and uses
main's launch authentication bundle. Gateway client certificates and keys are
not required; driver-owned guest TLS fields are rejected.

## Capabilities

| Capability | Status |
|---|---|
| Filesystem and UI policy | Mapped to the MXC ProcessContainer fence |
| Network policy and provider credentials | Standard host supervisor proxy; proxy-aware workloads only |
| Exec, signals, retained output | Authenticated Sandbox Protocol; ConPTY resize is not yet supported |
| Dynamic forwarding | Standard supervisor `ForwardTcp` path through sandbox loopback connect |
| ETW/OCSF audit | Optional Windows Sandboxing ETW consumer |
| Gateway restart recovery | Not yet supported; live MXC generations remain in-memory |

## Validation

Run the Windows build lane on a native Windows MSVC host:

```powershell
mise run --skip-tools windows:check:x64
mise run --skip-tools windows:lint:x64
mise run --skip-tools windows:build:x64
mise run --skip-tools windows:test:mxc-real:x64
mise run --skip-tools windows:e2e:mxc
```

The real-MXC tests are skip-safe when `wxc-exec.exe` or the required host
capabilities are absent. A complete integration run still requires a qualified
Windows MXC host; cross-compilation validates code shape but cannot validate
ProcessContainer networking or DACL behavior.

The real runtime requires native ProcessContainer directional egress and ingress
host-loopback support, reported by `wxc-exec.exe --probe`. AppContainer fallback
cannot supply these guarantees. Count test-internal `SKIP` messages separately
from Cargo's passed count.

The E2E runner uses native release artifacts (override with `-BinaryDir`), OpenSSL
on PATH for disposable Ed25519 keys, and per-run writable fixtures under
`target/windows-e2e-results`. It preserves the tracked gateway TOML and isolates
CLI registration via disposable APPDATA, LOCALAPPDATA, and XDG directories.
Inherited gateway overrides are cleared for the run and restored exactly
(including empty versus absent entries). The caller's gateway aliases are not
modified. Signing keys have an owner-only DACL,
remain outside result bundles, and are removed unless `-KeepRunning` is requested.

E2E runs real MXC only: there is no mock mode, and an inherited
`OPENSHELL_MXC_MOCK_WXC=1` is rejected. Any skipped selected scenario makes the
run incomplete and exits non-zero; a passing exit requires all selected scenarios
to execute successfully. Unit-test mocks are separate from E2E coverage.
`network-policy` checks admission and workload execution, not real network
enforcement. All-skipped real runs report `INCOMPLETE`, not `PASS`.

The `forwarding` scenario starts a TCP listener inside MXC, then verifies two
nonce-bound request/reply exchanges through `openshell forward service`, the
gateway, supervisor, and Windows boundary. Both listener ports are dynamically
assigned. Its native echo agent is a test-only Cargo example, built automatically
by the E2E mise task and remote runner, not a shipped runtime binary. It verifies
managed ingress, not denial of direct host-to-workload connections. Select it with
`-Scenario forwarding` on the local harness or remote runner.

The separate `service-forwarding` scenario runs the same native fixture in HTTP
mode, exposes a named endpoint with `openshell service expose`, and verifies two
unique GET responses through gateway host-based routing. It deletes the endpoint
and requires HTTP 404 afterward. Requests connect only to the gateway with the
exposed URL's Host header, so no wildcard DNS setup is required.

The `ws-agent.yaml` and `openclaw-gateway.yaml` policies preserve the Windows
branch's workload grants. `inference.yaml` is a template: replace its filesystem,
curl executable, inference host, and port placeholders before use. Authorize
curl, which owns the network socket, not its cmd launcher. These policies have
parser/mapper regression coverage; they do not add live WebSocket, OpenClaw,
or provider-backed inference scenarios to the six-scenario E2E runner.

With `-KeepRunning`, the runner restores the caller's environment but retains
the disposable CLI/runtime directory for the live gateway and prints its path.
Remove that directory only after stopping the gateway.
