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

The host is the one registry of its instances. `admit` validates that the key
is a single path component, then, under the registry lock, accepts the same
launch fingerprint for an occupied key again, rejects a different one, and
rejects any admission while the key is being removed. A new instance gets an
empty private directory under the host root, and `sandbox_instance_launch`
prepares its bindings and body there. A failed admission leaves no entry and
no files.

Removing an instance stops its workload, shuts down only its runtime, which
drops its runtime route, and revokes its gateway credentials; only then is its
private directory deleted and its key released, so a replacement can never
meet the old instance's resources. Removal runs on one detached task that
every remover joins, so a caller that disconnects cannot cancel it, and it
checks the entry's serial before releasing the key. If the directory cannot
be deleted, the key stays reserved and reports a failed phase, and the next
removal retries the deletion. An instance that panics reports a failure and
is revoked the same way. An instance that is still starting is cancelled at
once; the sandbox runtime then loses supervision and fails closed, as it does
when a dedicated supervisor exits. A hosted instance without an explicit proxy
trust directory uses its private directory. Hosted processes must install
`LogPushLayer::thread_bound` and an `OcsfShorthandLayer` writing to
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

## Shared supervisor host

`openshell-supervisor --mode=shared --gateway-endpoint <https-gateway-url> --token-file <file> --address <ip:port>`
hosts the sandbox instances of many sandboxes in one process for the
Kubernetes gateway supervisor topology. It is Unix-only. The host opens no
control listener: it dials the gateway and receives its assignments from it.

- **Gateway attachment.** The host dials `--gateway-endpoint` (which must be
  `https`), verifying the gateway with `OPENSHELL_TLS_CA` and
  `OPENSHELL_GATEWAY_TLS_SERVER_NAME` like every sandbox instance does, and
  opens the private `openshell.supervisor.host.v1/SupervisorHost.Attach`
  stream (`proto/supervisor_host.proto`) with the **supervisor token** in
  `--token-file` as its bearer. The gateway mints that token with its
  launch-signing key under a profile of its own (`typ`
  `openshell-supervisor+jwt`, subject `openshell-supervisor:<gateway_id>`,
  no sandbox, generation, or epoch claims) and keeps the file fresh through
  its deployment packaging (the Helm chart's `<release>-supervisor-token`
  Secret). The token authorizes nothing but this stream; sandbox, extension,
  user, operator, and peer credentials are refused on it. The host re-reads
  the file on every connection attempt and treats a missing, malformed, or
  expired token as a reason to retry later, and the gateway ends a stream
  when the token that opened it expires, so the host reconnects with the
  renewed one. The host never acts with any other identity and has no
  Kubernetes identity. The stream starts with a hello carrying a per-process
  instance id and a connection epoch; the gateway supersedes an older stream
  of the same process and refuses a delayed older connection.
- **Assignments.** The gateway owns the desired set and sends it as complete
  `AssignmentSnapshot`s with session-scoped revisions. `shared_host::SharedHost::reconcile`
  validates the snapshot as a whole (at most 256 instances, no route twice),
  decodes each assignment's launch material (the JSON
  `SandboxInstanceRegistration` of `openshell-supervisor-control`), admits it into
  the `SandboxInstanceHost` registry keyed by route with its pool fingerprint
  (see **Pool members**), relinquishes every hosted route the snapshot omits,
  and stops the routes it lists for stopping. A snapshot that is not a pool's
  is refused. An identical assignment is a no-op; one that cannot be admitted
  (invalid material, or a different fingerprint for a live route) is reported
  as a failed instance and never touches the running one. Snapshots are
  reconciled one at a time by one worker that outlives connections, so
  heartbeats and status keep flowing while instances start or stop, and a
  lost connection is replaced without waiting for a slow reconciliation; only
  the newest unapplied snapshot is kept, and work queued by an older
  connection is dropped when a new one begins. On shutdown the worker drops
  queued work and finishes the reconciliation in flight before the host
  relinquishes its instances. Private files live under `--session-root` (proxy CA,
  trust directory, SSH socket); the registry owns removal and keeps the route
  reserved until the instance has ended and its files are deleted.
- **Status.** After each reconciliation and whenever an instance is admitted,
  changes phase or readiness, or is removed, the host sends a complete
  `HostStatus` naming the revision it has reconciled to; readiness is set only
  once the gateway has accepted the instance's own supervisor session.
- **Disconnects.** Losing the gateway stream never stops an instance. The
  host reconnects with backoff, reports what it runs, and applies the first
  snapshot of the new session; only a snapshot that lists an instance for
  stopping stops it. The host uses the timings of
  `openshell_supervisor_control::pool_timing`: it abandons a stream after 3 s
  without hearing from the gateway, bounds sends by the same silence, gives
  each early reconnect attempt one 1 s deadline across connecting, attaching,
  and being accepted, and backs off 100 to 400 ms with jitter, so it reaches a
  responsive gateway replica well before its membership record expires.
- **Runtime connections.** One routed listener (`--runtime-listen`) accepts every
  instance's runtime-initiated Sandbox Protocol connections; see
  `openshell-sandbox-backend` for the routing preface.
- **Health.** `--address` is a plain TCP listener that accepts and closes
  kubelet `tcpSocket` probe connections; it carries no control traffic and
  reports only that the process runs. On SIGTERM or SIGINT the member
  announces that it is leaving, waits for the gateway to move its instances,
  and relinquishes whatever it still hosts; their workloads keep running.
- **Pool members.** `--pool-member-id`, `--pool-member-uid`, and
  `--pool-advertise-ip` (or `OPENSHELL_SUPERVISOR_POOL_MEMBER_ID`,
  `_MEMBER_UID`, `_ADVERTISE_IP`, which the chart fills from the Pod's name,
  UID, and IP) are required with `--mode=shared`: every shared supervisor is a
  member of the gateway's high-availability pool, and its hello names the
  member and its runtime address. Missing values fail startup with the flag
  and variable to set. A pool snapshot lists only
  the instances this process owns. An instance it omits moved to another
  member and is **relinquished**: the instance is cancelled without its stop
  path, so the runtime keeps the workload frozen until the new owner takes
  it over. Only `stop_routes` are stopped, and `keep_routes` are left as
  they are. A pool instance's admission fingerprint is its launch material
  and ownership term, not its credentials, so the same term re-minted by
  another gateway replica keeps the running instance. A takeover term
  replaces the launch credentials with the term's and attaches with its
  grant; the replacement adopts the running workload instead of starting it
  and keeps the launch material's proxy CA and SSH host key. A term that
  arrives without credentials, or whose route is still being released, is
  deferred, reported as starting, and retried at the heartbeat cadence. The
  host follows the gateway's heartbeat interval, offers each instance's
  runtime the recovery deadline of the latest snapshot
  (`recovery_timeout_secs`) when it attaches, feeds the route directory to the
  runtime router for redirects, and on SIGTERM announces that it is
  leaving, waits up to 40 seconds for the gateway to move its instances, and
  relinquishes what remains.

Sandbox instances get no upstream proxy, extra CA bundle, or provider workload identity:
the Kubernetes driver refuses the topology when an upstream proxy or provider
SPIFFE identity is configured, so a workload never silently loses them. The
host also initializes no OTLP trace or OCSF exporters, because one process
cannot export each instance's records with that instance's collector headers and
identity. Its console logs and each instance's gateway log push remain, and the
Kubernetes driver warns at startup when the gateway configures supervisor
export.
