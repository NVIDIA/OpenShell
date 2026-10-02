# OpenShell supervisor

The supervisor consumes the shared isolation backend contract. Its gateway
session, canonical process attachment, and TCP readiness do not require SSH or
a Unix host.

TCP readiness opens only after the gateway accepts the authenticated session.
Session loss closes readiness; accepted reconnection restores it. Dropping the
readiness guard closes the listener. A requested Unix readiness endpoint fails
explicitly on unsupported hosts, even before session acceptance.

The optional Unix SSH adapter remains separate from boundary-based process I/O.
Local Unix process signaling retains its existing signal surface, including
`SIGQUIT`. Remote signals use the backend-neutral `BoundarySignal` contract.

These portable control-plane foundations do not qualify a platform isolation
backend or enable a Windows workload runtime.
