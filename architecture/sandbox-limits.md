# Sandbox Limits

The sandbox supervisor processes untrusted agent traffic while sharing one
process across connections. Limits protect that process from unbounded memory,
work queues, parser effort, and waits. They are safety boundaries, not capacity
targets or compatibility guarantees. OpenShell is still early, so the values
and some ownership boundaries will change as production evidence improves.

This document inventories durable sandbox supervisor and egress limits. It
intentionally omits retry cadence, test-only values, and ordinary buffer chunk
sizes that do not cap aggregate resource use.

## Limit Model

OpenShell uses three kinds of limits:

| Kind | Purpose | Configuration |
|---|---|---|
| Platform ceiling | Protect the supervisor even when policy or an external service is hostile or mistaken. | Fixed in code by default. |
| Operator ceiling | Bound an operator-run integration below the platform maximum. | Configurable within platform validation bounds. |
| Policy inspection bound | State how much application data a policy needs the supervisor to buffer and inspect. | Configurable when the application protocol needs it, preferably below a platform ceiling. |

The component that first allocates, queues, or waits on a resource owns its
limit. Network frame and message assembly belongs to the network supervisor;
middleware RPC and envelope limits belong to the middleware runner; application
inspection limits belong to the corresponding L7 parser.

New limits should follow these rules:

- Enforce the bound before allocation or admission whenever possible.
- Acquire shared capacity before buffering and retain it through the complete
  buffered operation.
- Give partial-progress protocols both an idle bound and an absolute bound when
  either one alone still permits resource pinning.
- Let operator or policy configuration narrow a platform ceiling, never raise
  it silently.
- Define the terminal behavior: reject, close, truncate, shed, or backpressure.
- Do not let `fail_open` bypass a platform safety or protocol-integrity bound.
- Emit safe saturation or limit telemetry without request bodies, credentials,
  query parameters, or external free-form diagnostics.
- Test time bounds with simulated time and test shared budgets under saturation.

## Middleware

Middleware limits are process-wide per sandbox. Registry replacement preserves
the shared work, waiter, and persistent-session admission state so activity
retained by an older generation still consumes the same process-lifetime
budgets as new activity.

| Resource | Current bound | Scope and behavior |
|---|---:|---|
| Concurrent buffered work | 32 | Shared by HTTP requests, WebSocket messages, and WebSocket preflight. One permit covers one complete unit of work. |
| Admission waiters | 64 | Additional work is shed when both the active budget and waiter budget are full. HTTP receives a complete 503 response before its body is buffered. |
| Persistent middleware sessions | 32 | Shared process-wide session budget for streaming middleware protocols. WebSocket preflight uses immediate admission before opening streams and retains one permit while any stage remains active. |
| HTTP body or WebSocket text message | 4 MiB | Platform maximum for input and replacement payloads. Service, operator, and stage limits may narrow it. |
| Middleware configs and stages | 10 | At most 10 configs in policy and 10 selected stages in one chain. |
| Selector patterns | 32 | Combined include and exclude patterns per middleware config. |
| Per-stage RPC | 500 ms default, 10 ms–30 s | An operator timeout caps a binding timeout. |
| Complete message chain | 30 s | Starts after work admission; admission backpressure does not consume the chain budget. |
| WebSocket preflight | 1 s maximum | Caps handshake delay independently of the message RPC timeout. |
| Remote service connect | 5 s | Applies while establishing a middleware gRPC channel. |

Middleware also validates every non-body envelope component. Important examples
include 64 KiB service config, 4 KiB request context, 32 KiB target data, 128
request headers totaling 64 KiB, 64 header mutations, 32 findings per stage,
and 64 metadata entries. The detailed external contract lives in
[Supervisor Middleware](../docs/extensibility/supervisor-middleware.mdx).

The work semaphore bounds aggregate buffered middleware input to approximately
`32 × 4 MiB`, plus bounded envelope and parser overhead. It is a concurrency
safety valve, not rate limiting or a promise that 32 simultaneous maximum-size
messages are inexpensive.

The persistent session semaphore is independent from the work semaphore. One
WebSocket middleware session consumes one permit regardless of its active-stage
fan-out, which is separately capped at 10 stages. All-skip preflight releases
the permit immediately. A retained session releases it at connection end or as
soon as its last active stage is disabled. Session admission does not wait:
capacity exhaustion follows each selected config's `on_error` behavior before
any stream opens. The protocol-neutral registry ownership allows future
streaming HTTP middleware to use the same process-wide budget.

## Egress Framing and Inspection

| Path | Current bound | Terminal behavior |
|---|---:|---|
| Initial CONNECT request headers | 8 KiB | Reject the proxy request. |
| Inspected HTTP/1 request headers | 16 KiB | Reject the request. |
| Credential-rewritten HTTP body | 256 KiB | Reject when rewriting requires a larger buffered body. |
| SigV4 body signing | 10 MiB | Reject when signing requires a larger buffered body. |
| GraphQL request body | 64 KiB default | Policy can set a positive `graphql_max_body_bytes`; there is no shared platform ceiling yet. |
| MCP or JSON-RPC request body | 64 KiB default | Policy can set a positive `max_body_bytes`; there is no shared platform ceiling yet. |
| Parsed WebSocket client text message | 4 MiB | Close with `1009` when the complete or decompressed message is larger. |
| Concurrent parsed WebSocket text assemblies | 32 active, 64 waiters | Shared process-wide across all parsed relays. Additional messages close with `1013` before payload allocation or reading when both bounds are full. |
| Parsed WebSocket fragments per message | 4,096 | Close with `1002`. |
| Parsed WebSocket text assembly | 30 s input idle, 2 min total | Close with `1002`; the total includes initial and continuation payloads, continuation headers, and interleaved control frames. These deliberately permissive initial bounds can be tightened, or made operator-tunable within platform bounds, after production behavior is understood. |
| Parsed WebSocket text forwarding | 2 min total | End the relay and release assembly capacity. A timeout does not append a close frame to a partially written data frame. |
| Parsed raw WebSocket binary frame | 16 MiB | Close with `1002`; binary messages are relayed rather than inspected. |
| HTTP relay waiting for EOF | 5 s input idle | End the relay with a timeout. |
| TLS certificate cache | 256 hosts | Clear the cache before inserting another host. |

Ordinary allowed traffic is streamed rather than accumulated to a
connection-sized buffer. A parsing or transformation feature introduces a
buffer only when it owns an explicit bound.

Every parsed WebSocket text message acquires network-owned assembly capacity before payload allocation or reading, including relays used only for native policy, credential rewriting, compression, or a disabled fail-open middleware session. The process-lifetime budget survives policy reloads, and the assembly retains its permit through decompression, policy and middleware evaluation, credential rewriting, and upstream forwarding. Active middleware sessions additionally acquire shared middleware work before buffering. Input progress resets only the idle deadline. Forwarding uses one total deadline across the complete frame header, payload, and flush. Every timeout and terminal parser error releases both permits through ordinary ownership. Queue exhaustion emits a payload-free network denial event.

The operator middleware `max_payload_bytes` ceiling applies to payloads exposed
through HTTP-body and WebSocket text-message bindings. It does not replace the
raw binary frame safety bound because binary messages are never delivered to V1
middleware. A passed binary logical message still advances the active
middleware session sequence and emits coverage telemetry, so a later text RPC
can contain a valid sequence gap.

## Inference and Upstream Proxying

| Path | Current bound | Terminal behavior |
|---|---:|---|
| `inference.local` request parse buffer | 10 MiB | Return `413` for an oversized request. |
| Chunked inference request | 10 MiB and 4,096 chunks | Reject an invalid or over-limit request. |
| Streaming inference response | 32 MiB and 120 s chunk idle | Truncate the stream and attempt a safe SSE error. |
| Corporate proxy CONNECT response headers | 8 KiB | Fail the tunnel. |
| Corporate proxy CONNECT handshake | 30 s total | Fail the tunnel; validated-address attempts share the aggregate budget. |
| Token-grant HTTP request | 30 s request and connect | Fail credential resolution. |
| Response-derived token cache TTL | 5 min default; 1 h response cap; 30 s expiry margin | A positive profile `cache_ttl_seconds` override replaces the response-derived calculation. |

Streaming response byte limits are integrity-relevant. Protocols whose clients
require one complete buffered object do not use the truncating SSE path.

## Sandbox-Local Surfaces

| Surface | Current bound | Scope and behavior |
|---|---:|---|
| `policy.local` request body | 64 KiB and 15 s read | Reject an oversized or stalled local request. |
| Policy proposal long-poll | 60 s default, 1–300 s | Clamp the requested hold time; clients can issue another poll. |
| `policy.local` denial read | 100 records, 4 KiB per surfaced line | Bound response and log parsing work. |
| Log push reconnect buffer | 200 records | Drop new records above the local batch ceiling while disconnected. |
| Log push reconnect backoff | 30 s maximum | Cap the delay between reconnect attempts. |
| Policy status outbox | No fixed capacity | Preserve FIFO revision status without blocking policy reconciliation. |
| Policy status retry backoff | 32 s maximum | Retain a retryable update and retry independently of enforcement. |

The bounded log batch favors supervisor health over retaining an unbounded
diagnostic backlog. The policy status outbox makes the opposite tradeoff:
revision ordering and delivery survive an extended gateway outage at the cost
of potential queue growth.

## Known Gaps and Review Triggers

The current limits grew with individual features and are not yet a complete
resource model. Known gaps include:

- GraphQL, MCP, and JSON-RPC policy body limits have defaults but no common
  platform maximum.
- A positive token-cache TTL override replaces the response-derived one-hour
  ceiling rather than narrowing it.
- Socket read deadlines are not expressed consistently as idle plus total
  budgets across every parser.
- There is no documented aggregate connection budget or per-destination
  fairness policy in the supervisor.
- The policy status outbox is intentionally unbounded and can grow if policy
  revisions continue while its gateway endpoint remains unavailable.
- Limit telemetry is not yet uniform enough to derive saturation trends across
  all paths.

Revisit this document when adding a parser, body transformation, persistent
stream, shared queue, cache, or external call. A change should state:

1. What untrusted resource can grow or wait.
2. Which component owns the bound.
3. Whether the scope is per message, connection, destination, or sandbox.
4. Whether configuration can narrow the limit.
5. How saturation or timeout terminates.
6. Which telemetry and deterministic tests prove the behavior.
