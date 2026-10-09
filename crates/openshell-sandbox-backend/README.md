# OpenShell sandbox backend

This crate implements the supervisor-side isolation backend and the versioned
control protocol shared with `openshell-sandbox`.

## Boundary startup and routing

The supervisor uses the generated `IsolationBackend` control service to
negotiate capabilities and open a boundary before reading image policy. Each
physical connection repeats that handshake, including credential-epoch changes
and transport recovery. The launch session and generation identify retries;
the descriptor must bind to the same provisioned resource. Reopening returns
the same handle for the runtime's lifetime. Driver deletion terminates the
runtime and invalidates that handle.

Isolation protocol 1.0 includes boundary routing and requires
`openshell.isolation.contract` on both peers. The shared extension
negotiator checks major versions and each peer's required capabilities. The
built-in runtime does not advertise `openshell.isolation.suspend-resume` and
returns `UNIMPLEMENTED` for those optional RPCs.

`DelegatedIsolationBoundary.Exchange` and `.Mediate` begin with the handle from
`OpenBoundary`. The server authenticates the stream's bearer, checks the handle
against its provisioned sandbox and generation, then accepts data fragments.
Missing bindings, repeated bindings, and frames without a payload are rejected.
The fragments retain the existing versioned Sandbox Protocol framing.

Opening a boundary only validates and reserves a route. It neither attaches a
supervisor nor runs workload code. Policy discovery is followed by the existing
attach, mediation setup, confirm, and explicit start sequence. The existing
connection registry continues to govern supervisor replacement and recovery.

Update the supervisor and sandbox runtime together; an older peer fails during
startup instead of using a fallback path.

## Endpoint-registered backends

`DelegatedRuntimeBackend` uses the same client and lifecycle handles for an
operator-registered backend. Trusted endpoint registration and `DelegatedLaunch`
metadata are separate from the driver's opaque descriptor, which crosses
`OpenBoundary` unchanged. Common confirmation checks bind identity, session,
generation, resource claims, and outer-fence evidence. Native evidence is
validated by the registered backend; Linux evidence validation remains in the
built-in adapter.

The language-neutral contract, generation instructions, and interoperability
vectors are in [Sandbox Protocol 1.0](../../proto/sandbox_protocol/v1/README.md).

## Exec recovery

An exec envelope carries a UUID request ID and an absolute expiration time in
Unix milliseconds, set to 30 seconds after creation. The payload digest includes
the expiration time, and transport recovery preserves the entire envelope.
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
