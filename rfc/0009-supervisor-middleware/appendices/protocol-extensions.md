# Appendix: Protocol Extensions

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

**Updates in PR #2477 and issue #2691:** V1 includes a forward-text WebSocket operation and HTTP response pre-return streaming. The text below separates those implemented operations from future HTTP request streaming and WebSocket return-path work.

The v1 contract is intentionally operation-specific: one buffered unary HTTP request hook, one HTTP response pre-return stream, and one forward-text WebSocket message hook. This appendix records extensions the protocol should not preclude. None of the future shapes below are commitments.

## HTTP Request Streaming

The v1 `EvaluateHttpRequest` RPC is unary. The supervisor buffers the bounded request body, sends one `HttpRequestEvaluation`, and receives one `HttpRequestResult`. Streaming is deliberately left out of that method: if OpenShell later needs chunked payload transport or incremental processing, it should add a separate operation-specific method rather than changing `EvaluateHttpRequest` cardinality.

This section records what such a future streaming operation would need to consider, and importantly what streaming does and does not buy, since the distinction is easy to get wrong.

### Transport streaming vs processing streaming

These are different concepts and are easy to conflate:

- **Transport streaming** - a separate gRPC operation carries multiple messages (chunks). This is what a service would advertise in its manifest and what the supervisor would negotiate.
- **Processing streaming** - the middleware can act on partial content before it has the whole body.

The manifest field would govern only the transport. It would not promise the middleware can process incrementally.

### Full-body guards still buffer

Many guards need the entire body to do anything: a JSON-aware redactor must parse the whole document, and a PII scan must see all of it. Such a guard, even over a streaming transport, accumulates every chunk internally, then parses, then emits a single response at end-of-stream - the decision still arrives after the last byte. Incremental processing only helps narrower cases such as byte-level regex redaction or secret scanning over a text stream.

### Why add a streaming operation later

Even when the middleware must buffer the full body, a separate chunked transport operation would buy two things:

- It moves the large buffer off the supervisor. The supervisor does not hold a multi-MB body to put in a single message; the middleware, which needs it anyway and can be resourced for it, accumulates it.
- It avoids gRPC's per-message size limit (4 MB by default). A 20 MB inference request cannot fit in one message without raising limits, but it can be chunked.

This is the strongest reason to keep the door open for a streaming operation, more so than incremental parsing.

### How it would work

A service would advertise chunked-transport support (and limits) in `Describe`. When supported, the supervisor could use the streaming operation and send the body as a sequence of messages. When not supported, it would continue to use the unary v1 operation, and a body over the unary cap would use the middleware config's `on_error` behavior.

The streaming method should have its own messages instead of reusing `HttpRequestEvaluation` directly. Within a single streamed request, the first message would carry the request context plus the first body bytes, and subsequent messages would carry only further body chunks that the middleware appends; stream close would mark end of request. This keeps the v1 unary messages flat and gives streaming its own cleaner shape.

A cleaner phased design using a `oneof` over `context` and `body_chunk`, in the style of Envoy `ext_proc`, is available for a future streaming operation because it would not need to preserve the unary v1 message shape. V1 keeps the flat unary request because it is simpler for bounded bodies and avoids making every middleware implement streaming mechanics before the need is proven.

## Additional operation phases

> **Updates in PR #2477 and issue #2691:** This section records `WEBSOCKET_MESSAGE/PRE_CREDENTIALS` and `HTTP_RESPONSE/PRE_RETURN` as implemented. `WEBSOCKET_MESSAGE/PRE_RETURN` remains reserved.

V1 supports `HTTP_REQUEST/PRE_CREDENTIALS`, `HTTP_RESPONSE/PRE_RETURN`, and forward-text `WEBSOCKET_MESSAGE/PRE_CREDENTIALS`. A manifest advertises typed operation and phase pairs, while operation-specific RPCs preserve each protocol's lifecycle:

- `Connection/before_policy` / `HttpRequest/before_policy` - *before* network/L7 policy admits the request, for earlier classification. Riskier, because request content reaches a service before policy has allowed the request.
- `HTTP_REQUEST/PRE_CREDENTIALS` (v1) - after policy admits the request, before credential injection.
- `HttpRequest/post_credentials` - after credential injection, immediately before the relay writes the request upstream. This hook is credential-visible, so it is built-in-only: OpenShell marks it as a restricted hook and rejects any externally registered middleware that advertises it during manifest validation. The motivating use is request signing that must run after credentials are injected - for example a built-in `openshell/sigv4` that strips placeholder-signed AWS headers and signs the finalized request with supervisor-resolved credentials just before it is sent upstream.
- `HttpResponse/completed` - after an upstream request completes, emit metadata such as status, content length, selected route, selected model, and model usage if available. This is notification-only: no body, no transformation, and no allow/deny verdict. It would let reservation-style budget middleware reconcile a pre-dispatch decision without introducing response-body inspection.
- `HTTP_RESPONSE/PRE_RETURN` (v1) - after the final non-`1xx` upstream response head and before sandbox delivery. `HttpResponsePreReturn.Evaluate` supports preflight `SKIP` or `INSPECT`, headers-only inspection, bounded whole-body bytes, normalized lockstep stream bytes, body end, normalized trailers, and typed session termination. V1 has no successful response-body denial action.
- `WEBSOCKET_MESSAGE/PRE_CREDENTIALS` (v1 forward text) - after a WebSocket upgrade, on each complete client text message before credential placeholder rewriting. Before upstream contact, a concurrent preflight lets each selected stage inspect, voluntarily skip, or authoritatively deny the upgrade. Explicit denial takes precedence over failures and is enforced independently of `on_error`; OpenShell best-effort ends every still-writable opened stage stream with the typed terminal reason. An attached implementation without this binding is not selected and records coverage rather than applying `on_error`. Binary messages pass without inspection, consume a logical sequence, and record unsupported-message coverage for active stages.
- `WEBSOCKET_MESSAGE/PRE_RETURN` - on complete upstream messages before they return to the workload. The enum value is reserved, but manifests advertising it are rejected until return-path inspection is implemented.

Pre-policy phases run earliest, request phases bracket credential injection, response phases run after the upstream call, and message phases run on the parsed relay. V1 implements the three explicitly marked pairs above. `HttpRequest/post_credentials` remains a built-in-only candidate because it would see injected credentials. `HttpResponse/completed` remains a separate future notification hook for metadata-only post-call reconciliation.

## Semantic context

v1 sends the full request and lets the middleware interpret it. A future version can carry parsed semantic context (request category, semantic protocol such as OpenAI chat completions or Anthropic messages, and modalities) on `HttpRequestEvaluation`, and let policy target a semantic scope (latest user message, image parts, tool inputs). This also requires corresponding manifest fields so OpenShell can validate that a policy only references scopes and protocols the service supports.

## Content preview

ICAP-style previewing: send only the first N bytes so the service can decide whether it needs the full body before OpenShell buffers it. This reduces buffering cost for large requests that turn out not to require processing.

## Portable feature contracts and binding

A future version can introduce named feature contracts, such as `pii-redaction`, with a mapping from that portable contract to a concrete registered implementation. Policy would then stay portable across interchangeable implementations. V1 references a built-in or operator-owned registration name and defers this additional indirection.

## Header mutation rules

V1 preserves duplicate headers and their wire order. Results return ordered `write` and `remove` mutations for visible end-to-end fields without a required prefix. Writes support append, overwrite, and skip modes. One shared validator and atomic applicator enforces syntax and limits, then selects request-, response-, or trailer-specific protected fields. One invalid mutation discards the whole set and follows that config's `on_error` behavior. Response middleware may add only trailer names declared during preflight.

## Middleware authentication

Supervisor middleware exposes gRPC services over network endpoints. The stable transport contract requires confidentiality and authentication of the intended middleware service. Endpoint declaration, identity binding, credential material, and rotation must be explicit rather than left as deployment-specific conventions.

OpenShell supports unauthenticated plaintext gRPC only when the operator explicitly sets `allow_insecure_transport = true` on the middleware registration. A plaintext `http://` endpoint without this opt-in is rejected. OpenShell attaches no bearer credential and emits a prominent startup warning whenever the exception is enabled.

This mode is suitable only for trusted local development, loopback services, or isolated research environments where the middleware endpoint is not reachable by untrusted clients. It is not suitable for shared clusters, multi-tenant deployments, public networks, or any environment where inspected request content needs transport confidentiality.

Without middleware authentication and transport security, network observers can read inspected request content, active attackers can impersonate the middleware service, and unauthorized clients can call the middleware directly if it is reachable. Because the middleware can allow, deny, or transform egress, service impersonation is a policy-enforcement bypass, not just an observability risk.

Authenticated operation uses TLS with optional operator-provided trust roots plus short-lived, exact-audience gateway-signed JWTs, as recorded in [extension-authentication.md](extension-authentication.md). mTLS and overlapping key rotation remain deferred.

Even during the phase 1 plaintext exception, the hook stays before provider credential injection, and OpenShell does not forward original `Authorization`, `Cookie`, or other protected headers to middleware. This preserves the separation between content inspection and upstream credential injection while authenticated transport is completed.
