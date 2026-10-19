# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Socket attribution tests pass a duplicate connected socket as a spawned child's
stdin. Re-executing the test binary checks multiple holders with the same binary
identity; executing a different binary checks ambiguous shared-socket identity.
The fixture kills and reaps the child when the parent test ends.

The manual proxy performance baseline still counts allocations. Its test-only
global allocator uses `openshell-driver-vm::allocation_tracking`; the unsafe
allocator implementation belongs to the VM crate. The VM dependency disables
default features, so this instrumentation does not
require the compute runtime or Unix-only sandbox library. It is a development
dependency only.

## Session inputs

`run_networking` takes a `NetworkSession` with the sandbox identity, the
session's `GatewayEndpoint`, the SPIFFE Workload API socket for provider token
grants, the `policy.local` denial source, and proxy CA files. None of these
are read from the process environment, so one process can run several
sessions. Each session owns its provider token cache and HTTP client; a token
acquired for one sandbox is never served to another. Without a Workload API
socket, token grants fail closed. A process hosting several sessions serves
`/v1/denials` from a per-session `SessionDenialLog` instead of the shared
shorthand log files.
