# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Socket attribution tests pass a duplicate connected socket as a spawned child's
stdin. Re-executing the test binary checks multiple holders with the same binary
identity; executing a different binary checks ambiguous shared-socket identity.
The fixture kills and reaps the child when the parent test ends.

## Middleware caller context

The L7 relay retains the process identity resolved at connection admission and
passes its binary path, PID, and nearest-first executable ancestors to request,
response preflight, and WebSocket preflight middleware contexts. The middleware
runtime trims distant ancestors to keep the encoded context within 4 KiB. If
attribution is unavailable, a path cannot be represented as UTF-8, or the
binary cannot fit, the process field is absent. When multiple same-identity
processes hold the socket, the process field retains their common binary and
ancestry but reports PID zero because the sender cannot be identified.

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

## Upstream socket audit

Allowed CONNECT and transparent TCP `NetworkActivity` events record the
immediate upstream socket's local and peer addresses in
`unmapped.upstream_socket_local` and `unmapped.upstream_socket_peer` when both
socket address lookups succeed. A lookup failure omits the tuple without
stopping the allowed connection. The local address is captured from the
connected `PrefixedStream` before relay starts.
For a direct connection without address translation, it matches the peer
address observed by the receiver.
When the destination uses an upstream proxy, the peer address names that
proxy; a bypassed destination names the direct receiver. These
events also include `unmapped.binary_sha256` when the executable digest was
available to the authorization decision. The relay byte stream is unchanged.
