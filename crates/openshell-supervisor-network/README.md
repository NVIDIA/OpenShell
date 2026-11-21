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
intermediate token, or grant cache is used in the shared supervisor.
`mise run e2e:kubernetes:shared-supervisor-spiffe` exercises the gateway's
SPIFFE Broker API flow against a real server and agent. A process hosting
several instances serves
`/v1/denials` from a per-instance `SandboxInstanceDenialLog` instead of the shared
shorthand log files.

## Policy DNS expiry

Synthetic identities remain allocated after their DNS mappings expire. New
transparent connections lazily refresh expired, policy-backed mappings through
the same trusted resolver and destination-validation path as sandbox DNS
queries. Refreshes for one address share a lock; failed refreshes back off for
one second and never authorize expired upstream addresses.
`PolicyDnsService::lookup_for_connect` owns refresh coordination and returns
the resulting mapping; the underlying store stays synchronous. Observation-only
mappings, wrong ports, and mappings from a previous policy generation cannot refresh.
Refresh eligibility uses the authored ports, independently of which ports the
latest DNS addresses satisfied. Dispatch reauthorizes mapped connections and
rebuilds their connectors from current pins instead of retaining staged pins
across a refresh.

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
records are individual events with their own timestamps and classification.
`unmapped.http_event_kind` identifies decisions, findings, connection events,
middleware invocations and token grants. Middleware invocations use
`unmapped.middleware_phase` for request, response and WebSocket phases.
`unmapped.request_sequence` starts at 1 per request and describes local emission
order, not downstream delivery order. Count policy outcomes by selecting the
actual policy/firewall control record within a receipt group, not every
`decision` record.

Request IDs and audit outcomes do not depend on OpenTelemetry, sampling or
collector availability. Inspected requests have a supervisor-owned request span
and children around stages that actually run, with valid workload W3C context
only as an untrusted link. Their records never create an extra denial-only span,
even if the request span is disabled or unsampled. Uninspected HTTP denials use
bounded `supervisor.egress.deny` spans. The ambient HTTP audit scope ends before
protocol-start validation; one-shot attribution joins the existing upgrade
handoff record to the handshake and releases the request span before frames.
Later WebSocket frames do not reuse the handshake receipt. Terminal errors carry their request context explicitly,
and policy-reload cancellation records the active request before dropping it.
Idle connection closures have no HTTP receipt.
The request span ends after its owned stages, not when response headers are logged.
The `openshell.upstream.send` stage measures request writes and flush; response
handling is measured separately. Handled middleware failures remain stage errors
even when the local rejection response is delivered successfully. Receipt
filtering preserves raw HTTP bytes
and borrows unchanged header blocks. It removes only protected receipt fields
and their `Connection` or `Trailer` nominations, including folded continuations,
without adding general response-header validation.
