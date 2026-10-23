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

## Sandbox instance inputs

`run_networking` takes a `SandboxInstanceNetwork` with the sandbox identity,
the sandbox instance's `GatewayEndpoint`, the `ProviderIdentitySource` for
provider token grants, the `policy.local` denial source, and proxy CA files.
None of these are read from the process environment, so one process can run
several sandbox instances. `run_networking` selects the instance's token grant
resolver once from its identity source; a token acquired for one sandbox is
never served to another.

A dedicated supervisor uses `SpiffeTokenGrantResolver` with its SPIFFE Workload
API socket. That resolver owns the instance's token cache and HTTP client and
uses the gateway only for the intermediate exchange of RFC 8693 grants.
Without a socket, its grants fail closed. Shared sandbox instances use
`GatewayTokenGrantResolver`, which holds only the instance's authenticated
gateway channel, connected on the first grant and reused. Each admitted
operation forwards a configured dynamic credential key and request ID; the
gateway derives the sandbox identity,
validates current authorization, resolves grant parameters, and obtains the
final access token, which the resolver validates. No SPIRE client, SVID,
intermediate token, or grant cache is used in the shared supervisor. `mise run test:spire-delegation` exercises the gateway's
SPIRE acquisition client against a real server and agent. A process hosting several instances serves
`/v1/denials` from a per-instance `SandboxInstanceDenialLog` instead of the shared
shorthand log files.
