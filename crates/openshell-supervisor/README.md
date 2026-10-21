# OpenShell supervisor

The supervisor loads and reconciles policy, maintains provider credentials, applies network and MCP inspection, and drives the admitted isolation backend through attachment, confirmation, and workload start.

## Backend startup

The supervisor binary selects a backend setup and collects its launch inputs into a public `SandboxInstanceConfig`. Shared startup receives that config and the trusted backend setup separately. The `backend_setup` module owns that backend's launch-data decoder, workload policy discovery, and client construction. Descriptor contents cannot select an implementation.

Shared startup checks the admitted backend name before passing the opaque payload to its decoder. It then compares the decoded sandbox, session, and runtime generation with the trusted launch inputs before installing credentials or discovering workload policy. A mismatch stops startup.

The built-in decoder also carries the VM driver's fixed workload identity into shared policy validation. Startup and later policy updates must reject selectors that conflict with that identity. Other launch descriptors do not enable this VM-specific check.

The supervisor admits policy and prepares credentials before constructing and attaching the selected client. It uses the concrete RPC client handles `BoundBoundary` and `ConfirmedBoundary` from `openshell-sandbox-backend`: confirm the attached boundary, prepare network mediation, then start the workload. Backends supply native enforcement evidence through the Sandbox Protocol; the client validates it before exposing the confirmed handle.

The client receives the supervisor's live provider state, bearer-token slot, and CA-path slot. Provider refresh, token rotation, and later CA publication must remain visible through those shared handles. Startup does not create independent copies of their current values.

`backend_setup`, `SandboxInstanceConfig`, `SandboxInstanceBindings`, and `run_sandbox_with_backend` are public so the supervisor binary can select a registered backend. External backends should implement the `IsolationBackend` and `SandboxProtocol` services rather than link this crate.

The startup result separates the backend transport payload from optional
authenticated CONNECT listener settings. Shared networking starts the listener
only after boundary attachment and confirmation; the supervisor owns policy
evaluation, live credentials, and listener lifetime. These settings do not add
a proxy hook to the isolation interface or the shared Sandbox Protocol descriptor.

## Sandbox instance ownership

A sandbox instance is one running generation of a stable Sandbox resource.
Gateway connections, and the gateway supervisor sessions carried over them,
can reconnect within an instance without creating another one; the generation
remains the fencing identifier.

`run_sandbox_instance` supervises one sandbox instance from three inputs.
`SandboxInstanceConfig` is the single launch configuration: identity, command,
policy inputs, auth bundle, backend descriptor, and file locations.
`SandboxInstanceBindings` is the live state its owner prepares once: the
`GatewayCredentials` issued from the auth bundle, the OCSF context and JSON
settings, the log sink, and the denial history served by `policy.local`.
`SandboxInstanceControls` carries the owner's stop signal and readiness.
Everything else, including credential renewal, policy, provider credentials and
token grants, middleware credentials, the backend connection, and the access
plane, is created by the instance. Gateway clients receive a `GatewayEndpoint`,
which pairs the URL with that instance's `GatewayCredentials`; nothing is
installed process-wide.

The dedicated process wrapper keeps the existing process contract. The binary
loads the launch configuration from its arguments and environment and prepares
`SandboxInstanceBindings::dedicated`, sharing one `GatewayCredentials` with log
push and the OCSF JSON settings with its logging layers, so renewal by either
gateway client keeps both current. `run_sandbox_with_backend` sets the
process-wide OCSF context, binds the readiness socket and port to instance
readiness, and stops the instance on SIGTERM or SIGINT.

`sandbox_instance_host::SandboxInstanceHost` runs several sandbox instances in
one process. Each instance gets its own Tokio runtime; every thread of that
runtime, and the thread driving it, is bound to the instance's
`SandboxInstanceBindings`: OCSF context, OCSF JSON settings, log sink, and
denial log. Spawned tasks, blocking work,
callbacks, reconnects, and renewal therefore inherit the instance's identity,
and threads outside an instance carry none and push no logs. The OCSF context
also supplies the sandbox identity in middleware requests.

Removing an instance stops its workload, shuts down only its runtime, and
revokes its gateway credentials; the key stays registered until the
instance's thread has finished. An instance that panics reports a failure and
is revoked the same way. An instance that is still starting is cancelled at
once; the sandbox runtime then loses supervision and fails closed, as it does
when a dedicated supervisor exits. A hosted instance without an explicit proxy
trust directory receives a private one for its lifetime. Hosted processes must
install `LogPushLayer::thread_bound` and an `OcsfShorthandLayer` writing to
`SandboxInstanceDenialWriter`.

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

## Shared host

`openshell-supervisor --mode=shared --gateway-endpoint https://gateway:8080 --address 0.0.0.0:5501`
starts a shared-host placeholder for the Kubernetes gateway supervisor topology.
The listener at `--address` accepts and closes connections, including kubelet
`tcpSocket` probes, and reports process health only. `--gateway-endpoint` selects
the gateway the supervisor will dial for session control. The outbound connection,
control RPCs, sandbox sessions, gateway authentication, and tenant routing are not
implemented yet. Omitting `--mode` keeps the existing dedicated behavior.
`supervisor_topology = "gateway"` deploys this placeholder; sandboxes
continue using dedicated supervisors. SIGTERM and SIGINT close the listener.
Shared mode is Unix-only.
