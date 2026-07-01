# Implementation Plan

This plan is intentionally separate from the main RFC so the proposal can stay
direction-focused.

## Phase 0 - Regression Tests

- Add tests for forward HTTP pipelining and keep-alive follow-on requests,
  including the current `Connection: close` mitigation.
- Add tests for forward HTTP h2c rejection on inspected endpoints.
- Add tests for overlapping endpoint metadata selection.
- Add tests for endpoint metadata query failures.
- Add tests for control-plane port blocking through all destination validation
  paths.
- Add tests for exact declared private endpoint trust and `allowed_ips`
  behavior across CONNECT and forward HTTP.
- Add tests proving static credential injection works in L4-only HTTP and
  HTTP-inspected paths.
- Add tests proving token grant success injects the configured header and token
  grant failure does not forward upstream.
- Add tests for REST request-body credential rewrite, WebSocket text-frame
  credential rewrite, WebSocket GraphQL policy, and compression handling.
- Add tests for `policy.local` proposal wait behavior and `inference.local`
  buffered/streaming route limits.
- Add tests for metadata loopback startup/failure behavior when provider
  credentials require it.
- Add nftables bypass enforcement tests that verify proxy-bound traffic is
  accepted while direct TCP/UDP egress is rejected and logged when available.

## Phase 1 - Authorization Result

- Introduce `EgressIntent` and `EgressDecision` inside
  `openshell-supervisor-network`.
- Make authorization return matched policy and matched endpoint metadata
  together.
- Include policy source on the decision: user-authored, provider-derived, or
  local-service internal.
- Include protocol enforcement and credential injection plan on the decision.
- Fail closed when required endpoint metadata cannot be materialized.
- Emit consistent OCSF network denial events from the shared boundary.

## Phase 2 - Shared Destination Validation

- Move DNS resolution, allowed IP filtering, SSRF checks, exact declared
  endpoint handling, trusted gateway aliases, and control-plane port checks
  into one destination validation path.
- Return an `UpstreamConnector` rather than an opened upstream socket.
- Add tests proving CONNECT, forward HTTP, and future transparent TCP use the
  same validation behavior.

## Phase 3 - Forward HTTP Adapter

- Convert forward HTTP into an adapter that parses the first absolute-form
  request and builds an egress intent.
- Route the parsed first request into the shared HTTP relay or preserve the
  current guarded single-request relay behavior.
- Preserve `https://` absolute-form rejection.
- Preserve h2c rejection on inspected routes.
- Keep the no-raw-copy invariant after the first request.

## Phase 4 - HTTP, WebSocket, And Credential Relay Consolidation

- Centralize HTTP request parsing, REST policy, GraphQL policy, WebSocket
  upgrade policy, credential resolution, redaction, request rewrite, upstream
  dial, and response relay.
- Evaluate every HTTP request before upstream write.
- Ensure denied HTTP requests do not create upstream TCP sessions.
- Preserve static placeholder rewrite for target, query, and headers.
- Preserve dynamic token grant injection after request allow and before
  upstream write.
- Preserve opt-in REST request-body credential rewrite behind the shared HTTP
  relay, including bounded buffering, supported content-type handling,
  `Content-Length` recomputation, and fail-closed unresolved placeholders.
- Preserve WebSocket upgrade handling behind the shared relay, including
  opt-in client-to-server text-frame credential rewrite, WebSocket transport
  message policy, GraphQL-over-WebSocket policy, and raw passthrough for other
  upgraded protocols.

## Phase 5 - Shared TLS Termination

- Move client-side TLS detection and termination before the HTTP/TCP relay
  split.
- Keep endpoint TLS behavior on `EgressDecision`.
- Treat `tls: skip` as the explicit opt-out for TLS handling.
- Remove duplicate HTTP-specific and TCP-specific TLS termination decisions.

## Phase 6 - TCP Relay And Parser Boundary

- Use `TcpRelay` for byte relay and TCP application parser dispatch.
- Keep `protocol: tcp` or omitted protocol as L4 authorization plus byte copy.
- Add a TCP application parser dispatch point for future protocol enforcement.
- Let TCP application parsers own their message loop and call the connector
  when protocol state allows.

## Phase 7 - Policy DNS And Transparent TCP

- Add policy DNS registration for native TCP endpoint names.
- Replace static host-file mapping with query-driven DNS answers.
- Publish active DNS answer state and capture rules.
- Implement nftables REDIRECT/TPROXY capture rules ahead of the bypass reject
  path; do not add a parallel iptables path.
- Coordinate capture rule ownership with `openshell-supervisor-process::netns`.
- Implement transparent TCP adapter lookup from captured original destination
  to active endpoint generation.
- Decide TTL and stale-generation behavior.

## Phase 8 - Local Service Adapters

- Model `inference.local` as a local adapter with TLS termination, route
  validation, provider auth injection, streaming/buffered limits, and OCSF
  logging.
- Model `policy.local` as a local adapter for current policy, bounded denial
  summaries, policy proposals, and proposal wait.
- Decide whether metadata loopback remains orchestrated in `openshell-sandbox`
  or moves behind a local adapter boundary in `openshell-supervisor-network`.
- Keep these paths outside normal external egress relay while preserving
  credential redaction and route validation.

## Phase 9 - Runtime Boundary

- Keep embedded supervisor mode as the first migration target.
- Treat the existing `openshell-supervisor-network` and
  `openshell-supervisor-process` split as the structural baseline.
- Define the proxy runtime API needed for a future standalone binary:
  configured listeners, policy updates, provider credentials, token grants,
  gateway calls, telemetry, denial/activity events, and shutdown.
- Identify process identity requirements for standalone and sidecar modes.
- Add capability negotiation with the gateway if standalone proxy versions can
  differ from gateway versions.

## Phase 10 - Cleanup

- Remove duplicated endpoint metadata queries from relay paths.
- Remove duplicated destination validation and deny rendering where adapters
  can own response shape.
- Remove any remaining forward HTTP raw-copy fallback.
- Remove stale references to iptables or static `/etc/hosts` native TCP
  mapping from proxy design docs.
- Update architecture docs once implementation lands.

## Testing Plan

- Unit-test each adapter's intent construction and deny response shape.
- Unit-test authorization precedence for overlapping policy and endpoint rules.
- Unit-test provider-derived rule namespace handling and `policy.local`
  filtering.
- Integration-test shared destination validation across CONNECT, forward HTTP,
  and transparent TCP.
- Integration-test HTTP keep-alive and pipelined requests with REST, GraphQL,
  and WebSocket upgrade enforcement.
- Integration-test credential injection in L4-only HTTP and HTTP-inspected
  paths.
- Integration-test token grant success, cache hit, malformed token, resolver
  unavailable, and token endpoint failure.
- Integration-test REST request-body credential rewrite for JSON,
  form-url-encoded, `text/*`, unsupported content types, chunked framing, body
  caps, and unresolved placeholders.
- Integration-test WebSocket text-frame credential rewrite, raw upgraded
  passthrough, WebSocket message policy, GraphQL-over-WebSocket policy, and
  safe compression negotiation.
- Integration-test TLS termination before HTTP/TCP relay split.
- Integration-test `protocol: tcp` byte-copy behavior.
- Add parser harness tests before adding Redis, Postgres, or similar TCP
  application parsers.
- Integration-test policy DNS TTL, stale generation handling, and captured
  connect correlation.
- Integration-test `inference.local`, `policy.local`, and metadata loopback
  body limits, timeout behavior, redaction, and local denial responses.
