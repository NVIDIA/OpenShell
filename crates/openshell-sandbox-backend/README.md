# OpenShell sandbox backend

This crate implements the concrete supervisor-side RPC client and the versioned
control protocol shared with `openshell-sandbox`.

The protobuf services replace the Rust backend traits. The supervisor holds
concrete lifecycle, process, exec, forwarding, and mediation handles backed by
RPCs. Confirmation consumes the bound handle, validates enforcement evidence,
and produces the ready handle; starting consumes that ready handle. Both the
in-tree Linux runtime and external backends implement the generated services.
Linux process helpers remain internal to the runtime server.

## Boundary startup and routing

The supervisor uses the generated `IsolationBackend` control service to
negotiate capabilities and open a boundary before reading image policy. Each
physical connection repeats that handshake, including credential-epoch changes
and transport recovery. The launch session and generation identify retries;
the descriptor must bind to the same provisioned resource. Reopening returns
the same handle for the runtime's lifetime. Driver deletion terminates the
runtime and invalidates that handle.

Isolation protocol 1.0 includes boundary routing and requires
`openshell.sandbox.protocol` on both peers. The shared extension
negotiator checks major versions and each peer's required capabilities. The
built-in runtime does not advertise `openshell.sandbox.suspend-resume` and
returns `UNIMPLEMENTED` for those optional RPCs.

`SandboxProtocol.Exchange` and `.Mediate` begin with the handle from
`OpenBoundary`. The server authenticates the stream's bearer, checks the handle
against its provisioned sandbox and generation, then accepts typed protobuf
messages. `ExchangeFrame` carries control, process I/O, network decisions, and
TCP relay data. `MediateFrame` carries the OpenMediation handshake and DNS messages.
Missing bindings, repeated bindings, and frames that do not match the operation
or direction are rejected. There is no nested JSON or length/channel framing on
the wire. Private in-process adapters retain the Rust byte-stream interfaces.

Opening a boundary only validates and reserves a route. It neither attaches a
supervisor nor runs workload code. Policy discovery is followed by the existing
attach, mediation setup, confirm, and explicit start sequence. The existing
connection registry continues to govern supervisor replacement and recovery.

Sandbox and generation identity come from the verified bearer, rather than
duplicate fields on `OpenBoundaryRequest`. Attach supplies policy; confirmation
reports resource claims from backend-owned provisioned state, which the
supervisor compares with its trusted launch metadata.

Update the supervisor and sandbox runtime together; an older peer fails during
startup instead of using a fallback path.

## Endpoint-registered backends

`OpenShellRuntimeBackend::registered` constructs the same client and lifecycle
handles for an operator-registered backend. Trusted endpoint registration and `DelegatedLaunch`
metadata are separate from the driver's opaque descriptor, which crosses
`OpenBoundary` unchanged. Common confirmation checks bind identity, session,
generation, resource claims, and the driver's provisioning evidence digest. Native evidence is
validated by the registered backend; Linux evidence validation remains in the
built-in adapter.

The public gRPC contracts are in
[`isolation_backend.proto`](../../proto/isolation_backend.proto) and
[`sandbox_protocol.proto`](../../proto/sandbox_protocol.proto).

## Exec recovery

An exec envelope carries a UUID request ID and a protobuf timestamp set to
30 seconds after creation. Transport recovery preserves the entire request,
including that deadline. Repeated mutations with the same ID and equivalent
decoded fields replay the original result; conflicting reuse is rejected.
Map entry order is immaterial. The receiver computes its local replay
fingerprint; clients do not transmit a digest.
The supervisor and sandbox need synchronized wall clocks.

The sandbox checks expiration before starting or reattaching an exec. It keeps
each admitted request ID until that deadline, independently of process and I/O
retention. An expired request, including a delayed first attempt, is rejected
even after its ID has been discarded. The sandbox never moves its observed
admission clock backwards, so a clock adjustment cannot resurrect discarded
requests. Expired IDs are reclaimed when the next exec request arrives.

There is no lifetime exec request count limit. The existing concurrent process
retention limit still applies. The deadline governs admission and recovery;
it does not terminate an already running command. A recovery timeout can leave
the execution outcome unknown.

Exec envelopes without an expiration time are rejected. Update the supervisor
and sandbox runtime together when deploying this protocol change.

## Boundary audit validation

`OpenShellRuntimeBackend` implements the authenticated host side of the shared
Sandbox Protocol.

For the built-in Linux backend, the client validates native audit evidence and
rejects incomplete or foreign measurements. External backends validate their own
mechanisms and may omit audit data; they do not need to reproduce Linux
measurements. Optional audit data is a UTF-8 JSON value; empty bytes mean absent.
Successful confirmation asserts that the backend can enforce the
admitted policy; unsupported requirements fail before workload start. Both paths
retain generation, session, resource, identity, and provisioning evidence checks.

## Boundary transport establishment

`SandboxTransport` belongs to this backend's runtime descriptor. Core retains
only operator-registered endpoints; `DelegatedLaunch` converts those endpoints
into the backend's transport without changing their serialized representation.

The supervisor chooses one `BoundaryTransport` per runtime descriptor and uses
clones of it for policy discovery and attachment. It dials the descriptor's
endpoint, uses a backend-supplied `BoundaryTransportConnector` for raw stream
establishment, or, for `SandboxTransport::RuntimeInitiatedTcp`, accepts the
connections the sandbox runtime opens. Every stream from every source completes
the same pinned TLS client handshake before it carries a request; the shared
client also keeps session bearer authentication, generation checks, and
reconnection handling.

For runtime-initiated connections, the supervisor authenticates each accepted
socket before queueing it. Concurrent unauthenticated handshakes are bounded in
number and duration, and at most two authenticated spares wait for a client, so
a new connection cannot displace a live channel. The runtime keeps one spare
open, so reconnects and credential rotation never wait for a new dial.

The new variants leave existing encodings unchanged. Binaries that predate them
reject runtime-initiated descriptors instead of falling back to another mode.

`SandboxTransport::RuntimeInitiatedRouted` serves the sandbox instances of a
supervisor shared by many sandboxes from one listener
(`runtime_routed::RuntimeRouter`). A sandbox instance is one running
generation of a stable Sandbox resource. The runtime first sends a fixed
preface: `OSRP`, version `1`, a length byte, and an opaque route handle of 16
to 64 lowercase letters, digits, or hyphens. The handle is untrusted; it only
selects which instance's generation-pinned TLS identity the supervisor then
demands. Unknown, removed, and replaced handles are closed before any
handshake. Handshakes are bounded globally and per route, and an
authenticated connection only fills its own instance's spare queue. A routed
instance waits up to five minutes for its first connection, since it is
registered before its workload Pod is scheduled, and the usual connect window
afterwards. The launch material and status of one hosted instance
(`SandboxInstanceRegistration`, `SandboxInstanceStatusReport`) are defined by
`openshell-supervisor-control`, which depends on this crate for the runtime
descriptor and route validation.

Runtime-initiated transport supports TCP, protected Unix sockets, and host
vsock listeners. These share bounded TLS handshakes, the authenticated spare
queue, and the same generation-pinned runtime identity check. The legacy
supervisor-dialed transports remain available for existing descriptors.
