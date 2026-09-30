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
openshell-sandbox                               (ProcessContainer)
        |
        v
workload
```

The driver provisions and monitors the two runtime processes. It does not own a
second forwarding protocol. Process lifecycle, exec, provider refresh, dynamic
forwarding, retained output, and network policy flow through the ordinary
supervisor session and authenticated Sandbox Protocol.

## Enforcement boundaries

- MXC supplies the default-deny filesystem fence, AppContainer token, UI
  policy, and loopback-only network fence.
- `openshell-sandbox` consumes its bootstrap files before launching untrusted
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

The packaged `openshell-supervisor.exe` and `openshell-sandbox.exe` default to
siblings of `openshell-gateway.exe`. Override their paths for development
builds.

```toml
[openshell.drivers.mxc]
wxc_exec_path = "C:\\mxc-kit\\bin\\wxc-exec.exe"
supervisor_binary_path = "C:\\OpenShell\\openshell-supervisor.exe"
sandbox_binary_path = "C:\\OpenShell\\openshell-sandbox.exe"
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

Legacy configurations may retain `default_configuration_id`; it remains unused
by ProcessContainer and does not enable IsolationSession. New configurations
should omit that field.

Supply the workload command and working directory per sandbox:

```powershell
$config = '{"mxc":{"command":["C:\\Windows\\System32\\cmd.exe","/d","/c","echo hello"],"cwd":"C:\\work"}}'
openshell sandbox create --name mxc-demo --policy policy.yaml `
  --driver-config-json $config --no-tty
```

The command is required. The working directory is required because it contains
the generation-scoped bootstrap staging directory. Environment belongs in
`--env` or `--env-from`, not gateway configuration.

When gateway TLS is enabled, configure the gateway-owned `guest_tls_ca`,
`guest_tls_cert`, and `guest_tls_key` bundle. The gateway injects those paths
into the host supervisor; driver-owned copies of these fields are rejected.

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
mise run --skip-tools windows:e2e:mxc:mock
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
CLI registration via `XDG_CONFIG_HOME`. Signing keys have an owner-only DACL,
remain outside result bundles, and are removed unless `-KeepRunning` is requested.

Mock E2E verifies authenticated rejection of a non-AppContainer boundary before
workload execution. Workload filesystem and network-policy scenarios skip in
mock mode; do not treat the mock as isolation or successful-runtime coverage.
`network-policy` checks admission and workload execution, not real network
enforcement. All-skipped real runs report `SKIP`, not `PASS`.
