# Implementation Plan

This plan is intentionally separate from the main RFC so the proposal can stay
direction-focused. The RFC is an incremental roadmap, not one pull request.
Phases 0 through 7 form the compatibility foundation: they restructure current
CONNECT, forward HTTP, raw TCP, and local-service behavior without adding a new
user-facing transport. Phases 8 and later add the forward-looking capabilities
after the shared contracts are authoritative.

## Phase 0 - Compatibility Baseline

- Cover CONNECT and forward HTTP allow/deny responses, including exact status,
  headers, and adapter-specific error bodies.
- Cover forward HTTP pipelining, keep-alive follow-on requests, the current
  `Connection: close` mitigation, `https://` absolute-form rejection, and h2c
  rejection on inspected endpoints.
- Cover the current overlapping-policy outcomes separately for matched policy,
  L7 route selection, TLS, `allowed_ips`, and exact-declared-host.
- Inject failures into L7, TLS, `allowed_ips`, and exact-declared-host queries.
  Record the current fail-open or fail-closed result for each query rather than
  treating all endpoint metadata errors as equivalent.
- Cover control-plane ports, cloud metadata, always-blocked addresses, exact
  declared private endpoints, IP-literal synthesis, trusted gateway aliases,
  and explicit `allowed_ips` through CONNECT and forward HTTP.
- Cover identity-required success/failure, unsupported-platform behavior where
  possible, and intentional endpoint-only evaluation. Prove an empty
  `exec.path` cannot satisfy binary-scoped policy while identity is required.
- Cover static credential injection, token grants, REST body rewrite,
  WebSocket text-frame rewrite and policy, GraphQL, JSON-RPC, and MCP behavior.
- Cover `inference.local`, `policy.local`, metadata loopback, and unchanged
  nftables bypass reject/log behavior.
- Capture stable OCSF event class, activity/action/disposition, severity,
  status, destination, actor, firewall rule, message, and status detail for
  representative allow and deny paths.
- Record a performance baseline for OPA evaluations, per-connection
  allocations, and CONNECT/forward request latency.

## Phase 1 - Adapters And Compatibility Decision Envelope

- Introduce CONNECT and forward HTTP `EgressIntent` construction inside
  `openshell-supervisor-network`.
- Introduce a transitional `EgressDecision` carrying L4 outcome, policy
  generation, process evidence, and endpoint fields while preserving the
  current query timing, precedence, and failure defaults.
- Keep `LookupFailed`/unsupported identity as a denial when identity is
  required. Keep explicitly configured endpoint-only mode behavior unchanged.
- Keep adapter-specific responses and OCSF emission at the protocol boundary.
- Do not claim the transitional decision is one atomic OPA result; document its
  compatibility hydration until Phase 3 cuts over.

This phase is a mechanical extraction. It must be independently shippable and
revertible without changing user-visible policy or relay behavior.

## Phase 2 - Shared Destination Validation

- Move DNS resolution, explicit `allowed_ips`, exact declared endpoints,
  implicit IP-literal handling, trusted gateway aliases, SSRF checks,
  cloud-metadata blocks, and control-plane-port blocks into one validator.
- Represent the selected validation mode explicitly instead of passing an
  ambiguous collection of booleans.
- Return an unopened `UpstreamConnector` so adapters and relays preserve the
  current point at which upstream TCP is created.
- Prove CONNECT and forward HTTP retain their existing denial responses, OCSF
  fields, and dial timing while using the shared validator.

## Phase 3 - Generation-Consistent Authorization Cutover

- Define either rejection of ambiguous overlapping endpoint metadata or one
  documented policy/endpoint precedence key before changing enforcement.
- Add one OPA result that materializes matched policy/source, matched endpoint,
  destination constraints, TLS, HTTP enforcement, credential plan, and
  middleware selection from one policy generation.
- Attach a generation-pinned `TunnelPolicyEngine` to relay context for
  per-request REST, GraphQL, JSON-RPC, MCP, and WebSocket evaluation. Relays do
  not rematerialize connection-level endpoint policy.
- Run the new query in shadow mode beside legacy queries. Emit internal,
  audit-safe mismatch telemetry without changing existing OCSF network/HTTP
  events or enforcement.
- Add reload-race tests proving every materialized field matches the top-level
  generation and stale decisions stop before upstream request write.
- Make deterministic selection and fail-closed L7/TLS metadata errors a
  dedicated cutover only after mismatch cases are understood. Retain the
  legacy evaluator temporarily for immediate rollback.

This is the only phase that intentionally tightens ambiguous or error behavior;
it must not be hidden inside the structural refactor commits.

## Phase 4 - Forward HTTP Adapter

- Keep absolute-form parsing and adapter-specific errors at the forward HTTP
  boundary.
- Pass the buffered first request into a shared HTTP relay, or retain the
  guarded single-request/`Connection: close` path until Phase 5a is ready.
- Preserve `https://` absolute-form rejection and inspected h2c rejection.
- Preserve the invariant that no unevaluated follow-on request can reach raw
  bidirectional copy.

## Phase 5 - Relay Consolidation

### Phase 5a - HTTP request loop

- Centralize HTTP parsing and per-request REST, GraphQL, JSON-RPC, and MCP
  evaluation behind the generation-pinned request-policy handle.
- Evaluate every request before upstream write and preserve the current rule
  that a denied request does not create an upstream session.
- Preserve bounded JSON-RPC/MCP inspection and audit-safe logging that omits
  params and tool arguments.

### Phase 5b - Credential injection

- Unify static target/query/header rewrite, endpoint-bound token grants, and
  opt-in REST request-body rewrite after request allow and before upstream
  write.
- Preserve buffering limits, supported content types, `Content-Length`
  recomputation, redaction, token caching, and fail-closed unresolved secrets.

### Phase 5c - WebSocket

- Move allowed upgrades behind the shared relay while preserving raw upgraded
  passthrough, opt-in text-frame credential rewrite, WebSocket transport policy,
  GraphQL-over-WebSocket policy, and safe compression behavior.

### Phase 5d - Supervisor middleware

- Land only after the supervisor middleware dependency is available.
- Run `HTTP_REQUEST / PRE_CREDENTIALS` after request allow and before static or
  dynamic credential injection.
- Re-parse middleware-transformed bodies and re-evaluate GraphQL, JSON-RPC, and
  MCP policy inputs before credential injection or upstream write. Preserve the
  endpoint's audit or enforce behavior for policy mismatches, and fail closed
  on malformed transformed protocol bodies in either mode.
- Preserve ordering, body caps, `fail_open`/`fail_closed`, safe headers,
  findings, metadata, and rejection of middleware-introduced credential
  placeholders.
- Test allowed requests that middleware rewrites into denied GraphQL, JSON-RPC,
  and MCP operations, including audit-mode forwarding and fail-closed malformed
  replacements.

Each subphase must be independently testable and shippable; Phase 5 is not a
single flag-day cutover.

## Phase 6 - Shared TLS And TCP Relay Boundary

- Move client-side TLS detection and termination before the HTTP/raw-TCP relay
  split without changing handshake, certificate, or upstream-connect timing.
- Keep endpoint TLS behavior on `EgressDecision` and preserve `tls: skip` as the
  explicit raw-tunnel path.
- Use one existing raw `TcpRelay` byte-copy primitive for L4 traffic.
- Add a protocol-processor dispatch contract without enabling a concrete new
  protocol in the compatibility milestone.
- Let processors own their message loop and call the validated connector only
  when protocol state allows. Permit in-tree, middleware-backed, and hybrid
  processors with typed middleware operations.

## Phase 7 - Existing Local Services And Cleanup

- Keep `inference.local` as a local adapter with its existing TLS, route,
  provider-auth, streaming/buffered limit, and OCSF behavior.
- Keep `policy.local` as a local adapter for current policy, bounded denial
  summaries, proposals, and proposal wait.
- Decide whether metadata loopback remains orchestrated by `openshell-sandbox`
  or moves behind a local adapter boundary; preserve startup/failure behavior
  either way.
- Keep the local-routing and destination contracts extensible for issue
  [#1633](https://github.com/NVIDIA/OpenShell/issues/1633), while leaving its
  policy surface and host-loopback authorization to separate feature work.
- Remove compatibility endpoint queries only after Phase 3 is authoritative.
- Remove duplicated destination/relay plumbing without centralizing
  adapter-specific response rendering.
- Update the living architecture documentation once each implemented boundary
  reflects current code.

Completion of Phase 7 is the compatibility milestone: existing user-facing
features and capabilities are preserved on the new internal structure. The
following phases are feature-bearing work and land in separate pull requests or
series.

## Phase 8 - Policy DNS And Transparent TCP

- Add policy DNS registration for native TCP endpoint names.
- Reject names that do not match an eligible native TCP endpoint before making
  an upstream DNS query.
- Replace static host-file mapping with query-driven synthetic DNS answers.
  Resolve eligible names through trusted DNS and filter every real address
  through destination controls.
- Allocate a supervisor-owned synthetic IP and store the normalized name,
  endpoint ID, allowed ports, validated real addresses, policy generation,
  distinct DNS mapping generation, mapping ID, and expiration in active mapping
  state.
- Require every captured connect to correlate with the unexpired mapping
  selected by its synthetic destination and requested port. Do not allow
  unrelated bare-IP traffic to inherit a policy-DNS decision.
- Publish mapping and nftables capture updates atomically from the adapter's
  perspective before returning the synthetic DNS answer.
- Add nftables REDIRECT/TPROXY capture rules ahead of the bypass reject path;
  do not add a parallel iptables path.
- Coordinate capture-rule ownership with
  `openshell-supervisor-process::netns` and preserve reject/log fallback for
  unmatched traffic.
- Recover the original destination, construct a transparent-TCP intent, and run
  normal generation-consistent authorization and destination validation.
- Restrict the connector to the mapping's pinned validated real addresses; do
  not independently re-resolve at connect time.
- Keep direct external DNS blocked and treat DNS-over-HTTPS as ordinary
  policy-controlled HTTPS egress.
- Define synthetic address pools and reuse quarantine, TTL caps, policy-reload
  invalidation, stale-mapping behavior, and rollback before enabling capture by
  default.

## Phase 9 - Native Protocol Processors

- Add concrete Redis, Postgres, MySQL, or other processors one protocol at a
  time, each with a separately reviewed policy schema and operational limits.
- Keep omitted/`tcp` endpoints on raw L4 byte copy; never infer a native
  processor from traffic alone.
- Test multi-message sessions, pre-dial denial, handshake-required dialing,
  per-command/query evaluation, middleware hooks, timeouts, and redaction.
- Capability-gate policy that names a processor unavailable in the running
  proxy build.

## Phase 10 - Runtime Boundary

- Keep embedded and network-only supervisor modes as the migration baseline.
- Define the proxy runtime API needed for a future standalone binary or
  sidecar: configured listeners, policy updates, provider credentials, token
  grants, middleware registry, gateway calls, telemetry, denial/activity
  events, and shutdown.
- Advertise process-identity and protocol-processor capabilities. Reject policy
  that requires unavailable binary/path identity or processor support.
- Represent intentional runtime identity unavailability separately from the
  existing endpoint-only mode and from lookup failure.
- Add gateway capability negotiation if proxy and gateway versions can differ.

## Phase 11 - Final Cleanup

- Remove any compatibility query/evaluator retained for deterministic-decision
  rollback after its observation window closes.
- Remove stale static `/etc/hosts`, iptables, or single-process assumptions from
  proxy design and architecture documentation as the corresponding later phase
  lands.
- Keep adapter-specific response rendering and OCSF contracts at their protocol
  boundaries.

## Testing And Operational Validation

- Unit-test adapter intent construction, response rendering, explicit
  destination modes, identity evidence, and authorization precedence.
- Integration-test destination validation across CONNECT and forward HTTP,
  then reuse the same suite for transparent TCP when Phase 8 lands.
- Integration-test HTTP keep-alive/pipelining, REST, GraphQL, JSON-RPC, MCP,
  WebSocket, credentials, token grants, middleware, and TLS/raw-TCP selection.
- Integration-test `inference.local`, `policy.local`, and metadata loopback body
  limits, timeouts, redaction, and local denial responses.
- Compare OCSF fixtures before and after each migration subphase.
- Exercise policy reload between L4 decision, endpoint materialization, relay
  startup, and long-lived per-request evaluation.
- Add protocol-processor harness tests before adding Redis, Postgres, MySQL, or
  similar enforcement. Each concrete processor adds multi-message, handshake,
  timeout, denial, redaction, and middleware coverage.
- Integration-test policy DNS filtering, denial without an upstream query,
  synthetic answer allocation, TTL and reuse quarantine, distinct mapping
  generations, policy-reload invalidation, atomic capture-rule updates,
  original-destination recovery, allowed-port correlation, connector
  restriction to pinned real addresses, and rejection of unrelated bare-IP
  connects.
- Prove two names that resolve to the same real IP and port receive distinct
  correlations and cannot inherit each other's endpoint policy.
- Test standalone/sidecar capability negotiation and prove missing identity or
  processor support fails during policy validation rather than broadening an
  allow at runtime.
- Re-run the performance baseline after the compatibility envelope, after the
  single-decision query, and after relay consolidation. Treat reduced OPA calls
  as a measured result rather than an assumed benefit.
- Back out structural phases by reverting their isolated commits. Keep shadow
  comparison and the legacy evaluator available through the deterministic
  cutover observation window.
- Gate later transport/runtime phases independently so disabling policy DNS or
  transparent capture restores the existing explicit-proxy and bypass-reject
  behavior without reverting the compatibility foundation.
