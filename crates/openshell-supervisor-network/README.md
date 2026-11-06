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
the sandbox instance's `GatewayEndpoint`, the SPIFFE Workload API socket for
provider token grants, the `policy.local` denial source, and proxy CA files.
None of these are read from the process environment, so one process can run
several sandbox instances. Each instance owns its provider token cache and
HTTP client; a token acquired for one sandbox is never served to another.
Without a Workload API socket, token grants fail closed. A process hosting
several instances serves `/v1/denials` from a per-instance
`SandboxInstanceDenialLog` instead of the shared shorthand log files.

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

## HTTP enforcement correlation

Inspected HTTP requests create an `openshell.http.request` span with a
`openshell.policy.evaluate` child when policy evaluation runs. A single
valid, sampled W3C `traceparent` becomes its parent. OpenShell treats incoming
trace context as an untrusted correlation hint: malformed or duplicate values
are ignored, `tracestate` is not adopted into the enforcement span, and an
unsampled context becomes a link so a caller cannot suppress local enforcement
telemetry.

The network supervisor assigns each inspected request a UUID. It stores that
value in the enforcement span, in correlated OCSF events, and in the
`x-openshell-request-id` response header. OpenShell removes workload,
middleware, and upstream attempts to set that header on inspected HTTP paths.
The header is a correlation handle, not proof of an enforcement decision. A
consumer must match it to trusted OpenShell OTLP or OCSF output for the same
sandbox and trace, and must never authorize from the header alone. L4 and
passthrough traffic do not provide this anti-spoofing guarantee. Span
attributes distinguish the policy decision from the enforcement action and
final outcome, such as a local denial, an allowed response, or an upstream or
platform failure. An unfinished request is reported as incomplete. The
attributes never include credentials, query values, or request and response
bodies.

Each inspected request emits one primary HTTP Activity record when the final
response head is written, after response middleware selects what can be returned.
Informational responses do not commit that record. If the request ends before
the final head, a guard emits it with the available outcome instead. The byte
observer does not buffer headers or alter transport behavior. A receipt confirms
only observation of a response head, not completion of its body. Process crashes
and requests that remain hung cannot be finalized by the guard.
