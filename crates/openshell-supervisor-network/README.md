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

## Connections without inspection

Before the supervisor forwards a connection it cannot inspect (`tls: skip`, transparent TCP, h2c, unsupported tunnels, SQL passthrough), `uninspectable_traffic_gate` checks the matching middleware chain. Any `fail_closed` entry denies the connection, and an all-`fail_open` chain relays it with a bypass finding. For `tls: skip`, the gate runs before `200 Connection Established`, so a denial is a `403`.

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

Each inspected HTTP request has one UUID shared by middleware, OCSF
`metadata.correlation_uid`, and the protected `x-openshell-request-id` response
header. Application correlation must use another header. The receipt is only a
join key: it does not establish identity, authorization or complete delivery.
L4 and passthrough traffic do not provide this header guarantee.

The emission hook adds request correlation to every OCSF class in the current
request scope, including findings. Policy, middleware, token-grant and finding
records retain their original content, event IDs, timestamps and classification;
they are not merged or delayed. `unmapped.http_event_kind` distinguishes decisions,
findings, connection events and middleware invocations. Explicit control kinds,
such as `token_grant`, remain unchanged. Middleware records retain
`unmapped.middleware_phase`, including HTTP-hook preflight and completion.
`unmapped.request_sequence` starts at 1 per request and describes local emission
order, not downstream delivery order. Count policy outcomes by selecting the
actual policy/firewall control record within a receipt group, not every
`decision` record.

Request IDs and audit outcomes do not depend on OpenTelemetry, sampling or
collector availability. Inspected requests have a supervisor-owned request span
and children around stages that actually run, with valid workload W3C context
only as an untrusted link. Their records never create an extra denial-only span,
even if the request span is disabled or unsampled. Other egress paths retain the
bounded deny-span behavior. Both HTTP tracing and the request's ambient
audit scope end before an upgraded session; later WebSocket frames do not reuse
the handshake receipt. Terminal errors retain their request context explicitly,
and policy-reload cancellation records the active request before dropping it.
Idle connection closures have no HTTP receipt.
The request span ends after its owned stages, not when response headers are logged.
The `openshell.upstream.send` stage measures request writes and flush; response
handling is measured separately. Receipt filtering preserves raw HTTP bytes
and borrows unchanged header blocks. It removes only protected receipt fields
and their `Connection` or `Trailer` nominations, including folded continuations,
without adding general response-header validation.
