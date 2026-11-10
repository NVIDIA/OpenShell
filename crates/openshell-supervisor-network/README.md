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

## Reserved destinations

`preauthorize_transparent_open` matches a staged TCP open against the reserved
OTLP relay address (`openshell_core::sandbox_env::OTLP_RELAY_ADDR`) before host
mapping, policy evaluation, and SSRF checks. The address is an unroutable
label, so the proxy never dials it. When `run_networking` receives a
`ReservedDestination`, the proxy hands the workload stream to its
`ReservedStreamHandler`; a handler that refuses, for example at its connection
cap, turns the open into a resource-exhausted denial. Without a handler, the
proxy denies the open at once. It logs the first attempt at warn and later ones
at debug, and emits no OCSF denial event: a standard OpenTelemetry SDK retries
for the life of the agent, and one event per retry would flood the OCSF log.
The supervisor installs its OTLP relay receiver as the handler while the agent
trace relay is active.

## Static credential placement

Substitution checks the declared request location before writing upstream.
Credentials without placement metadata default to the Authorization header. HTTP placement violations return a safe 403 response;
WebSocket violations close the connection with policy denial. Both paths emit a
domain event and a detection finding without credential values or placeholders.
Explicit body and WebSocket
rewrite flags authorize those locations for ordinary static credentials. SigV4
signing retains the endpoint-scoped resolver's existing trusted access.
