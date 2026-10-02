# OpenShell sandbox backend

This crate implements the supervisor-side isolation backend and the private
control protocol shared with `openshell-sandbox`.

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
## Boundary audit validation

`OpenShellRuntimeBackend` implements the authenticated host side of the shared
Sandbox Protocol.

Backend implementations may inject a `BoundaryAuditValidator` to interpret
their opaque confirmation evidence. The default Linux validator rejects
incomplete or foreign evidence. Confirmation compares the asserted properties
with the properties derived by the selected validator; validator injection does
not bypass generation, session, resource, identity, or outer-fence checks.

Concrete platform validators belong to the implementing backend, not this
shared transport library.

## Boundary transport establishment

Backends may supply a `BoundaryTransportConnector` for raw stream establishment.
The shared client retains TLS peer verification, session bearer authentication,
generation checks, and reconnection handling. The connector is reused for policy
discovery and attachment; it does not define platform launch configuration or
replace the isolation interface.
