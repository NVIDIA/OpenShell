# Appendix: Protocol Extensions

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

V1 includes event-oriented HTTP request and response streams plus a forward-text WebSocket operation. This appendix records remaining extensions the protocol should not preclude.

## Request streaming

`HttpRequestPreCredentials.EvaluateHttp` is bidirectional streaming. Preflight continues without a body, rejects, or selects BUFFERED or STREAM. OpenShell normalizes HTTP/1 fixed and chunked bodies into bounded units, carries validated trailers at body end, and rebuilds transport framing after evaluation.

### Transport streaming vs processing streaming

These are different concepts and are easy to conflate:

- **Transport streaming** - the gRPC operation carries multiple bounded messages. Every body-aware stage uses this transport.
- **Processing streaming** - the middleware can act on partial content before it has the whole body.

Selecting a stream mode governs processing semantics; using the streaming RPC alone does not promise incremental processing.

### Full-body guards choose storage deliberately

Many guards need the entire body to do anything: a JSON-aware redactor must parse the whole document, and a signer may need all bytes before emitting its output head. A guard selects BUFFERED when the complete body fits the negotiated RAM bound. Otherwise it selects STREAM, owns its working storage and cleanup, consumes input independently, and delays output until ready. Incremental guards also select STREAM but may emit output early.

### What streaming provides

The request stream provides three important properties:

- It removes the requirement that a complete request fit in one gRPC message. OpenShell caps request units at 64 KiB.
- Independent pumps let the service change chunk cardinality, retain lookahead, or wait for complete input without blocking OpenShell from continuing to deliver input.
- STREAM assigns output responsibility at preflight without OpenShell retaining a replay copy.

For a chain made only of STREAM stages, OpenShell may forward output upstream before the request ends. A later rejection or failure terminates that upload but cannot retract prior bytes, so the relay never retries or replays it. BUFFERED stages, body-aware policy re-evaluation, and request-body credential rewriting retain a bounded in-memory hold barrier. OpenShell rebuilds framing for both paths and can stop a live upload when the upstream responds early.

The state machine requires one preflight and, after selection, one Begin. BUFFERED has one body and one result. STREAM has nonempty input chunks plus one input end, independent output start/chunks, and finish after input end. Input and output cardinality do not correspond. Unknown, duplicate, missing, or out-of-order events fail closed. A best-effort terminal notification ends the session.

## Additional operation phases

> **Update in PR #2477 - WebSocket middleware:** This section now records `WEBSOCKET_MESSAGE/PRE_CREDENTIALS` as implemented. It keeps `WEBSOCKET_MESSAGE/PRE_RETURN` as a reserved future operation.

V1 supports `HTTP_REQUEST/PRE_CREDENTIALS`, `HTTP_RESPONSE/PRE_RETURN`, and forward-text `WEBSOCKET_MESSAGE/PRE_CREDENTIALS`. Each operation and phase pair encodes a different position in the proxy flow:

- `Connection/before_policy` / `HttpRequest/before_policy` - *before* network/L7 policy admits the request, for earlier classification. Riskier, because request content reaches a service before policy has allowed the request.
- `HTTP_REQUEST/PRE_CREDENTIALS` (v1) - after policy admits the request, before credential injection.
- `HttpResponse/completed` - after an upstream request completes, emit metadata such as status, content length, selected route, selected model, and model usage if available. This is notification-only: no body, no transformation, and no allow/deny verdict. It would let reservation-style budget middleware reconcile a pre-dispatch decision without introducing response-body inspection.
- `HTTP_RESPONSE/PRE_RETURN` (v1) - on the return path, after the upstream responds and before the response reaches the sandbox; inspect, redact, or block upstream responses.
- `WEBSOCKET_MESSAGE/PRE_CREDENTIALS` (v1 forward text) - after a WebSocket upgrade, on each complete client text message before credential placeholder rewriting. Before upstream contact, a concurrent preflight lets each selected stage inspect, voluntarily skip, or authoritatively deny the upgrade. Explicit denial takes precedence over failures and is enforced independently of `on_error`; OpenShell best-effort ends every still-writable opened stage stream with the typed terminal reason. An attached implementation without this binding is not selected and records coverage rather than applying `on_error`. Binary messages pass without inspection, consume a logical sequence, and record unsupported-message coverage for active stages.
- `WEBSOCKET_MESSAGE/PRE_RETURN` - on complete upstream messages before they return to the workload. The enum value is reserved, but manifests advertising it are rejected until return-path inspection is implemented.

Pre-policy phases would run earliest, the two request phases bracket credential resolution, response phases run after the upstream call, and message phases run later on the parsed relay. `HttpResponse/completed` remains a future metadata-only notification hook.

## Semantic context

V1 sends normalized request bytes and lets the middleware interpret them. A future version can carry parsed semantic context (request category, semantic protocol such as OpenAI chat completions or Anthropic messages, and modalities) on request preflight, and let policy target a semantic scope (latest user message, image parts, tool inputs). This also requires corresponding manifest fields so OpenShell can validate that a policy only references scopes and protocols the service supports.

## Content preview

ICAP-style previewing: send only the first N bytes so the service can decide whether it needs the full body before OpenShell buffers it. This reduces buffering cost for large requests that turn out not to require processing.

## Portable feature contracts and binding

A future version can introduce named feature contracts, such as `pii-redaction`, with a mapping from that portable contract to a concrete registered implementation. Policy would then stay portable across interchangeable implementations. V1 references a built-in or operator-owned registration name directly and defers this additional indirection.

## Header mutation rules

V1 preserves duplicate request headers and their wire order. Before an external invocation, OpenShell omits credential-bearing, routing, framing, hop-by-hop, and `Connection`-nominated headers. Results return ordered `write` and `remove` mutations. Writes support append, overwrite, and skip modes. Mutations may target middleware-visible end-to-end headers except the protected categories. OpenShell validates and applies a stage's mutations atomically, so one invalid mutation discards the whole set and follows that config's `on_error` behavior.

## Middleware authentication

Supervisor middleware exposes gRPC services over network endpoints. The stable transport contract requires confidentiality and authentication of the intended middleware service. Endpoint declaration, identity binding, credential material, and rotation must be explicit rather than left as deployment-specific conventions.

Phase 1 may temporarily support unauthenticated plaintext gRPC only when the operator explicitly sets `allow_insecure_transport = true` on the middleware entry. A plaintext `http://` endpoint without this opt-in is rejected. OpenShell emits a prominent warning and records auditable configuration state whenever the exception is enabled, so insecure operation is always deliberate and visible.

This mode is suitable only for trusted local development, loopback services, or isolated research environments where the middleware endpoint is not reachable by untrusted clients. It is not suitable for shared clusters, multi-tenant deployments, public networks, or any environment where inspected request content needs transport confidentiality.

Without middleware authentication and transport security, network observers can read inspected request content, active attackers can impersonate the middleware service, and unauthorized clients can call the middleware directly if it is reachable. Because the middleware can allow, deny, or transform egress, service impersonation is a policy-enforcement bypass, not just an observability risk.

Phase 2 removes plaintext endpoint support and removes `allow_insecure_transport`. Every external middleware connection must then provide authenticated encrypted transport. This is an intentional research-preview breaking change, so phase 1 plaintext configurations have no long-term compatibility guarantee and must migrate before phase 2.

The exact phase 2 mechanism is deferred. Follow-up protocol work should choose and specify mTLS, TLS plus explicit caller authentication, or an equivalent design, including trust roots, client identity, credential delivery, certificate or key rotation, middleware identity binding, and how supervisors receive authentication material.

The alpha mechanism that was subsequently built - TLS with optional operator-provided trust roots plus short-lived, exact-audience gateway-signed JWTs - is recorded in [extension-authentication.md](extension-authentication.md). It supersedes this section's `allow_insecure` design with `allow_insecure_transport` and narrows, but does not close, the phase 2 question: mTLS and overlapping key rotation remain deferred.

Even during the phase 1 plaintext exception, the hook stays before provider credential injection, and OpenShell does not forward original `Authorization`, `Cookie`, or other protected headers to middleware. This preserves the separation between content inspection and upstream credential injection while authenticated transport is completed.
