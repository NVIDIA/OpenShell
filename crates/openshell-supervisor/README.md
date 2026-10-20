# OpenShell supervisor

The supervisor loads and reconciles policy, maintains provider credentials, applies network and MCP inspection, and drives the admitted isolation backend through attachment, confirmation, and workload start.

## Backend startup

The public `run_sandbox` entry point selects the OpenShell Sandbox Protocol backend and collects its startup inputs into a public `SandboxRunConfig`. Shared startup receives that config and the trusted backend setup separately. The `backend_setup` module owns that backend's launch-data decoder, workload policy discovery, and client construction. Descriptor contents cannot select an implementation.

Shared startup checks the admitted backend name before passing the opaque payload to its decoder. It then compares the decoded sandbox, session, and runtime generation with the trusted launch inputs before installing credentials or discovering workload policy. A mismatch stops startup.

The built-in decoder also carries the VM driver's fixed workload identity into shared policy validation. Startup and later policy updates must reject selectors that conflict with that identity. Other launch descriptors do not enable this VM-specific check.

The supervisor admits policy and prepares credentials before constructing and attaching the selected client. It uses the concrete RPC client handles `BoundBoundary` and `ConfirmedBoundary` from `openshell-sandbox-backend`: confirm the attached boundary, prepare network mediation, then start the workload. Backends supply native enforcement evidence through the Sandbox Protocol; the client validates it before exposing the confirmed handle.

The client receives the supervisor's live provider state, bearer-token slot, and CA-path slot. Provider refresh, token rotation, and later CA publication must remain visible through those shared handles. Startup does not create independent copies of their current values.

`backend_setup`, `SandboxRunConfig`, and `run_sandbox_with_backend` are public so the supervisor binary can select a registered backend. External backends should implement the `IsolationBackend` and `SandboxProtocol` services rather than link this crate.

The startup result separates the backend transport payload from optional
authenticated CONNECT listener settings. Shared networking starts the listener
only after boundary attachment and confirmation; the supervisor owns policy
evaluation, live credentials, and listener lifetime. These settings do not add
a proxy hook to the isolation interface or the shared Sandbox Protocol descriptor.

## Session ownership

`run_session` supervises one sandbox generation from a `SessionConfig` and
`SessionControls`. Everything that belongs to that generation is an input or
is created by the session: gateway credentials and their renewal, the Sandbox
Protocol credential, policy, provider credentials and token grants, middleware
credentials, OCSF JSON settings, proxy trust files, the denial history served
by `policy.local`, the backend connection, access plane, readiness, and stop
signal. Gateway clients receive a `GatewayEndpoint`, which pairs the URL with
that session's `GatewayCredentials`; nothing is installed process-wide.

`run_sandbox_with_backend` is the dedicated wrapper. It keeps the existing
process contract: it sets the process-wide OCSF context, reads launch inputs
from the environment, binds the readiness socket and port to session
readiness, and stops the session on SIGTERM or SIGINT. The binary shares one
`GatewayCredentials` between log push and supervision, so renewal by either
keeps both current.

`session_host::SessionHost` runs several sessions in one process. Each session
gets its own Tokio runtime; every thread of that runtime, and the thread
driving it, is bound to the session's OCSF context, OCSF JSON settings, log
sink, and denial log. Spawned tasks, blocking work, callbacks, reconnects, and
renewal therefore inherit the session's identity, and threads outside a
session carry none and push no logs. The OCSF context also supplies the
sandbox identity in middleware requests.

Removing a session stops its workload, shuts down only its runtime, and
revokes its gateway credentials; the key stays registered until the session's
thread has finished. A session that panics reports a failure and is revoked
the same way. A session that is still starting is cancelled at once; the
sandbox runtime then loses supervision and fails closed, as it does when a
dedicated supervisor exits. A hosted session without an explicit proxy trust
directory receives a private one for its lifetime. Hosted processes must
install `LogPushLayer::thread_bound` and an `OcsfShorthandLayer` writing to
`SessionDenialWriter`.

## Console logging

Diagnostics and OCSF shorthand share a bounded, nonblocking stderr writer. With `ocsf_json_enabled=true`, the same writer also receives timestamped `OCSF-JSON` records. Each formatter submits a complete line in one write so concurrent producers cannot interleave records in the queue. The 1,024-line queue drops new lines when full rather than waiting for stderr.

Console JSON is installed independently of optional file appenders and uses an INFO filter independent of the diagnostic filter. Its runtime enabled flag and target schema version are shared with the existing JSONL file layer. The supervisor retains the writer guards until shutdown. The gateway log push layer continues to emit shorthand only.

## Safe runtime and parent liveness

The supervisor drives the safe isolation-backend contract and network/policy
orchestration. Its library and executable forbid unsafe code.

For a VM host supervisor, the VM driver passes its parent-liveness pipe as stdin
and sets the private `--parent-liveness-stdin` flag. A dedicated reader terminates
the supervisor when the driver closes its write endpoint or exits. The driver
protects both original pipe endpoints with close-on-exec and lets `Stdio` transfer
the read endpoint to the child's stdin. The supervisor uses the standard stdin
reader and does not adopt a numeric raw descriptor. This mode reserves stdin for
liveness; sandbox workload input travels over the boundary protocol.

## Portable supervisor access

The supervisor consumes the shared isolation backend contract. Its gateway
session, canonical process attachment, and TCP readiness do not require SSH or
a Unix host.

TCP readiness opens only after the gateway accepts the authenticated session.
Session loss closes readiness; accepted reconnection restores it. Dropping the
readiness guard closes the listener. A requested Unix readiness endpoint fails
explicitly on unsupported hosts, even before session acceptance.

The optional Unix SSH adapter remains separate from boundary-based process I/O.
The process-access multiplexer consumes boundary-provided streams and delegates
terminal resizing and signals through the existing isolation contract. It does
not own local PIDs, PTYs, or process-group signaling; native process operations
belong to the sandbox or isolation backend. Signals use `BoundarySignal`.

These portable control-plane foundations do not qualify a platform isolation
backend or enable a Windows workload runtime.

## Shared supervisor host

`openshell-supervisor --mode=shared --gateway-endpoint <gateway-url> --address <ip:port>` hosts the sessions of many sandboxes in
one process for the Kubernetes gateway supervisor topology. It is Unix-only.

`--gateway-endpoint` selects the gateway each sandbox session dials. The current
admission RPCs still arrive from the gateway at `--address`; moving admission
onto a supervisor-initiated stream is a separate implementation step.

- **Admission.** A mutually authenticated TLS 1.3 listener
  (`--address`, credentials in `--session-control-tls-dir`)
  serves `PUT`, `GET`, and `DELETE /v1/sessions/{route}` and `GET /v1/sessions`
  as JSON. Only a client holding the admission certificate, which Helm gives
  only the gateway, can register sessions. A registration carries one
  generation's runtime descriptor and gateway-issued credentials; the host
  never acts with any other identity and has no Kubernetes identity. An
  identical registration is accepted again; a different one for a registered
  route returns `409`.
- **Sessions.** `shared_host::SharedHost` starts each registration as a
  `SessionHost` session with private files under `--session-root` (proxy CA,
  trust directory, SSH socket). Removal runs on a task the host owns, so it
  completes when the caller disconnects, and the route stays reserved until the
  session has ended and its files are deleted.
- **Runtime connections.** One routed listener (`--runtime-listen`) accepts every
  session's runtime-initiated Sandbox Protocol connections; see
  `openshell-sandbox-backend` for the routing preface.
- **Health.** The chart's kubelet `tcpSocket` probes connect to the
  session-control port (5501) and close without completing TLS, so they report
  only that the process is listening; every request still requires mTLS.
  Session readiness is reported per session over session control. SIGTERM and
  SIGINT stop every session, which ends their workloads' supervision.

Sessions get no upstream proxy, extra CA bundle, or provider workload identity:
the Kubernetes driver refuses the topology when an upstream proxy or provider
SPIFFE identity is configured, so a workload never silently loses them. The
host also initializes no OTLP trace or OCSF exporters, because one process
cannot export each session's records with that session's collector headers and
identity. Its console logs and each session's gateway log push remain, and the
Kubernetes driver warns at startup when the gateway configures supervisor
export.
