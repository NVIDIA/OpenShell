# openshell-driver-mxc

Native Windows implementation and releases stay on the
[`windows` branch](https://github.com/NVIDIA/OpenShell/tree/windows).
Start with the [Windows guide](https://github.com/NVIDIA/OpenShell/blob/windows/WINDOWS.md)
for checkout and build instructions, including when this README is linked
from documentation on `main`.

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
need explicit administrator opt-in with `allow_driver_config = true`.
MXC does not support external-resource label admission. Host filesystem grants
rely on sandbox policy and a trusted gateway operator. See
[resource admission configuration](../../docs/how-it-works/gateways/configuration.mdx#external-resource-admission)
for the independent caller configuration gate and resource admission controls.

This driver implements the gateway's ordinary in-process `ComputeDriver`
contract and is linked into `openshell-gateway`. Runtime readiness comes from
the authenticated host supervisor session, not a driver-reported condition.
The resolved create-time `SandboxPolicy` is carried by
`DriverSandboxSpec.policy`. The driver provisions a one-shot ProcessContainer,
launches the Windows boundary and separate host supervisor, and monitors both.
The boundary launches the workload only after authenticated confirmation.
The driver defaults its paired runtimes to `info` logging so native workload
launches remain observable. An explicit sandbox log-level setting takes
precedence. The boundary emits structured process activity and the Windows
branch's `MXC agent launched` acknowledgement only after native spawn succeeds.

The driver resolves its gateway endpoint and TLS server-name defaults from
generic gateway inputs. The host supervisor authenticates its gateway session
and retains main-process I/O. MXC has no foreground attachment adapter; create
command workloads with `--detach`. Preflight rejects foreground attachment
before provisioning. TCP readiness remains gated by authenticated session acceptance.

Windows boundary execution is implemented by the `openshell-mxc-boundary`
library behind the dedicated `openshell-windows-sandbox.exe`. The compute driver does not
embed the supervisor, and the sandbox does not link the compute driver.
Dynamic forwarding uses the shared protocol stream, not a dedicated relay
executable or a reverse connection to a new gateway listener.

The boundary establishes its control TCP connection outward from MXC to a
generation-scoped loopback listener in the host isolation backend, matching the
Windows branch relay's connection direction. The shared transport connector
extension preserves pinned boundary TLS identity and supervisor JWT checks;
the driver neither brokers protocol requests nor runs supervision. Discovery
and attachment reuse the backend-owned listener, including reconnects. No host
firewall rule changes are required for this control path.

## Enforcement boundaries

The current port temporarily asserts main's required outer-fence guarantees
to permit Windows-branch compatibility testing. This is an unconditional
MXC-only stub, not verified enforcement evidence or production qualification.
Broad host-loopback access does not establish `NoUnmanagedEgressPath`, and
live access revocation has no verified native evidence. The provisioning TODO
tracks replacing these assertions with real enforcement. Audit metadata labels
egress as `mxc-windows-parity-unverified-egress-stub`. AppContainer identity,
authenticated transport, and generation checks remain required. Do not expose
sensitive host-local services to workloads using this compatibility path.

- MXC supplies the default-deny filesystem fence, AppContainer token, UI
  policy, and loopback-only network fence.
- `openshell-windows-sandbox` consumes its bootstrap files before launching untrusted
  code, authenticates the paired supervisor, and terminates workloads when an
  authenticated supervisor cannot recover within the reconnect deadline.
- The host supervisor owns an authenticated per-generation explicit proxy.
  Missing or cross-sandbox credentials receive HTTP 407 before policy
  evaluation. MXC denies direct Internet egress.
- The explicit proxy resolves the actual socket-owning executable from the
  Windows kernel TCP table, hashes it, and rechecks ownership before policy
  evaluation. Allowing a launcher such as `cmd.exe` does not authorize a child
  such as `curl.exe`; missing, ambiguous, or changed ownership denies the request.
- The loopback fence permits `127.0.0.1/32`; it does not isolate unrelated host
  services bound to that address. Treat the gateway host as trusted.
- Host supervisor tokens and descriptors live beneath an owner-only Windows
  DACL. Boundary bootstrap secrets live in the ProcessContainer staging path
  and are deleted before workload launch.

## Configuration

MXC does not implement external-resource label admission. Do not configure
`resource_admission` under its driver table; unsupported fields are rejected.
Host filesystem grants rely on workload policy and a trusted gateway operator,
not resource labels. Caller-supplied command configuration still requires
`allow_driver_config = true`. Native isolation, authenticated transport, and
outer-fence confirmation remain required.

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
  --driver-config-json $config --detach
```

The command and absolute working directory are required. The working directory
contains the generation-scoped bootstrap staging directory. When no generic canonical
command is supplied, the driver passes `mxc.command` to the supervisor rather
than starting a scratch workload. An explicit generic canonical command retains
precedence. Environment belongs in `--env` or `--env-from`, not gateway configuration.

The optional `mxc.denied_paths` lists paths the workload cannot open, including
inside the policy's filesystem grants: it cannot read, write or delete a denied
file, list a denied directory, or create a denied path by name. The driver
passes the list to MXC as `filesystem.deniedPaths`. For example, with a policy
that grants `C:\work\profile` read-write, to hide the credential files in it:

```powershell
$config = '{"mxc":{"command":["C:\\Windows\\System32\\cmd.exe","/d","/c","agent.cmd"],"cwd":"C:\\work","denied_paths":["C:\\work\\profile\\.env","C:\\work\\profile\\auth.json"]}}'
```

Each entry must be an absolute path that starts with a drive letter, such as
`C:\work\profile\.env`; forward slashes are converted to backslashes. A denied
path may be absent, but its parent directory must exist because MXC refuses to
start the ProcessContainer otherwise; to cover a missing directory, deny the
directory itself. An entry must not equal or contain a filesystem grant,
including the generation staging directory under `cwd` and the sandbox
executable: MXC drops a grant that equals a denied path and keeps access to a
grant nested inside a denied directory.

MXC applies denied paths and grants to paths. The workload can rename a
directory when the directory and its parent are both writable to it, and
everything below that directory then sits at a path no denied path or read-only
grant names. Preflight therefore rejects an entry below such a directory: two
or more levels below a read-write grant root, inside a read-write grant nested
in another read-write grant, or below a read-only grant whose root is two or
more levels inside a read-write grant. The error names the directory; deny it
instead, or move the entry directly into the read-write grant root. Entries
directly inside a read-write grant root whose parent the workload cannot write,
and entries below a read-only grant root that cannot be renamed, are accepted.

MXC resolves 8.3 short names, junctions and letter case, and accepts grants in
the `\\.\C:\`, `\\?\C:\`, `\??\C:\`, `\\?\GLOBALROOT\Device\...` and
`\\?\Volume{...}\` spellings, so preflight compares resolved drive paths
(following symbolic links too). The parts of a drive path that do not exist, or
that cannot be resolved, are compared as written. While `denied_paths` is not
empty, preflight rejects a grant it cannot resolve to a drive path: a UNC path,
which MXC grants no access through, a path without a drive letter, or a device
path that does not resolve.

A denied path protects contents. The file's name, size, timestamps and
attributes remain visible to the workload, for example when it lists the parent
directory, and a hard link to the same file, created on the host before launch
at a path the workload can read, still exposes the contents. MXC does not check
the target of a rename against `deniedPaths`: when the parent directory is
writable, the workload can rename one of its own files onto a denied name,
which replaces a denied file on the host, or creates the file or directory when
it is absent. The original contents stay unreadable, and an existing denied
directory cannot be replaced. Denying the directory that holds such files
prevents this, because nothing can be renamed into a denied directory.

Denied paths only remove access and are fixed at sandbox creation. They require
a host whose `wxc-exec.exe --probe` reports
`probes.baseContainerSupportsDenyPaths: true`. When the list is not empty, the
driver sends MXC `fallback.allowDaclMutation: false`, so on a host without that
support the launch fails and MXC does not change the ACLs of host files.

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

Workloads receive the proxy CA in `NODE_EXTRA_CA_CERTS` and `DENO_CERT`, and a
combined bundle in `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and
`GIT_SSL_CAINFO`. The combined bundle holds the server-authentication roots of
the host user's Windows certificate store followed by the proxy CA, so clients
that read it also verify servers behind `tls: skip` endpoints, which the proxy
does not terminate. Schannel clients such as Windows `curl.exe` ignore these
variables unless the bundle is passed explicitly. Windows adds a Microsoft
program root to the store the first time a Schannel client needs it, so the
bundle lacks program roots that the host has not used yet. If the store roots
encode to more than 896 KiB of PEM, the supervisor logs a warning and the
bundle holds only the proxy CA.

UI controls are startup settings in the sandbox policy:

```yaml
ui:
  allow_graphical_ui: true
  clipboard: read
  allow_input_injection: false
```

Omitted UI settings deny all three capabilities. Clipboard accepts `none`,
`read`, `write`, or `all`, from the workload's perspective. Clipboard and input
injection require graphical UI. Unknown fields/values and unsupported
containment targets are rejected before provisioning. MXC advertises
`openshell.policy.ui.v1` through existing extension metadata. The gateway rejects
explicit UI policy (including `{}`) for drivers missing this capability; those
drivers need no UI-specific handling. UI policy itself does not require the
`allow_driver_config` opt-in. Recreate the sandbox to change these settings.

## Validation

Windows release build tasks stage the pinned, target-matching `libz3.dll` beside
the gateway and verify its architecture and copied SHA256. Conflicting cached
DLLs fail the build instead of selecting an arbitrary runtime. Local E2E requires
this adjacent DLL; rebuild for the native architecture if preflight reports it
missing.

### Remote Windows host

Build on a Windows MSVC development machine and run the unchanged real E2E
harness on a separate MXC host:

```powershell
.\tasks\scripts\test-mxc-remote.ps1 -HostName 172.16.178.137 -UserName test `
  -WxcExecPath 'C:\Tools\MXC\wxc-exec.exe'
```

Install the public SSH key on the target and verify its host key before running.
The script defaults to `~/.ssh/openshell-mxc-test`; override `-IdentityFile` as
needed. Both SSH and SCP must be on PATH locally. The target needs Windows
OpenSSH Server, OpenSSL on its SSH-session PATH, and a qualified MXC runtime,
but does not need Rust, MSVC, mise, or a source checkout.

The script detects native Windows architecture independently of the SSH shell,
uses the existing `windows:build:*` task, and validates the executable PE
architecture before testing. `-BuildDirectory` selects a dedicated Cargo cache.
`-SkipBuild` reuses existing artifacts without claiming they match current
sources. `-Scenario` selects an existing harness scenario.

The package includes `libz3.dll` from the target-specific Cargo build cache.
Windows prebuilt Z3 uses a dynamic runtime DLL. Supply `-Z3DllPath` if multiple
different cached versions exist or when using a custom Z3 build. The remote
host needs the native Visual C++ runtime; the runner validates DLL architecture
and gateway startup before invoking E2E.

The example gateway explicitly enables caller driver config so tests can submit
their workload command and directory. MXC does not implement external-resource
label admission. The temporary outer-fence assertions permit compatibility
testing but do not qualify exclusive network mediation or live revocation.

Uploads are cached by SHA256 and verified before execution. Each run has an
isolated remote directory under `%USERPROFILE%\openshell-mxc-tests`; old runs
are retained. Full logs, host capabilities, source status, artifact hashes, and
the results ZIP return to `target/windows-remote-results` in this checkout.
Signing-key directories are not downloaded. Test failures and incomplete
coverage remain nonzero exits. Missing host-loopback evidence is not a pass,
and a qualified host does not close the outer-fence implementation gaps above.

### Local Windows host

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

The real-MXC HTTPS test uses the authenticated E2E gateway/supervisor harness.
Build native release binaries first; `OPENSHELL_MXC_TEST_BINARY_DIR` optionally
selects another binary directory. Its opt-in `-Scenario https-ca` requires
Internet access to `https://example.com` and Windows curl 8.3 or newer. Curl
explicitly loads the boundary-injected CA bundle and records the peer certificate;
success requires a nonempty response and the OpenShell proxy CA issuer. It does
not install a host trust root or disable CA/hostname verification. The fixture
uses best-effort Schannel revocation because the ephemeral private CA has no CRL
distribution point; it does not qualify revocation enforcement. The default seven E2E
scenarios remain independent of Internet access.

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

The default `host-service` scenario runs an HTTP fixture on host `127.0.0.1`
and a dynamic port. A real MXC workload makes two direct curl requests; both
must return the fixture's nonce and appear in its host-side request log. The
host service is checked before launch and stopped after testing. Select it with
`-Scenario host-service`; no Internet access, LAN address, or firewall changes
are required. This verifies direct localhost connectivity.

The `ws-agent.yaml` and `openclaw-gateway.yaml` policies preserve the Windows
branch's workload grants. `inference.yaml` is a template: replace its filesystem,
curl executable, inference host, and port placeholders before use. Authorize
curl, which owns the network socket, not its cmd launcher. These policies have
parser/mapper regression coverage; they do not add live WebSocket, OpenClaw,
or provider-backed inference scenarios to the seven-scenario E2E runner.

With `-KeepRunning`, the runner restores the caller's environment but retains
the disposable CLI/runtime directory for the live gateway and prints its path.
Remove that directory only after stopping the gateway.

### Focused native qualification

After building the native release binaries, run:

```powershell
mise run --skip-tools windows:test:mxc-boundary
mise run --skip-tools windows:test:mxc-network
mise run --skip-tools windows:test:mxc-loopback
```

The network task runs real injected-CA HTTPS and both child-curl policy cases.
It requires Internet access. Native target selection uses the machine architecture,
including when SSH launches an emulated PowerShell. The loopback task hosts its
test inside a real ProcessContainer with host loopback denied; it is a separate
qualification and never relaxes the fence or reports an unsupported run as a pass.
On the ARM64 test host (Windows build 28120, MXC 1.0.0), this qualification
currently fails with socket error 10013. Enabling the documented private-network
capability while retaining host-loopback denial also fails; no safe OpenShell
workaround has been established.

Provider environment publications reject case-insensitive duplicate names,
invalid environment entries, and names reserved for the six injected TLS trust
variables before installing them. Rejected updates retain the prior revision.

For live ETW audit coverage, set `OPENSHELL_WXC_EXEC_PATH` and run
`mise run --skip-tools windows:test:mxc-audit` after building native release
binaries. This requires elevation or Performance Log Users membership. It checks
the shipped config and coverage classifier before requiring all seven event types
in the durable JSONL output; the ordinary E2E scenarios do not check this path.

On the ARM64 test host (Windows build 28120, MXC 1.0.0), Sandboxing ETW records
come from the shared Appinfo broker rather than the driver-owned executor.
The consumer cannot correlate these records using the executor's PID and process
generation, so live audit qualification currently fails even though the workload
completes. The executor diagnostic log redacts its container identity. A trusted
broker-to-launch correlation is needed; treating the shared broker PID as a
sandbox identity would misattribute concurrent sandboxes and is not supported.
