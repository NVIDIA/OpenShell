# Appendix: Protocol Extensions

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

The v1 contract is intentionally minimal: one HTTP request hook, buffered unary calls, an `allow`/`deny` decision plus optional transformed content, findings, and metadata. This appendix records extensions the proto should not preclude, so v1 stays small without painting future work into a corner. None of these are committed; they exist to validate that the v1 shape is forward-compatible.

## Streaming

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

A cleaner phased design -- a `oneof` over `context` and `body_chunk`, in the style of Envoy `ext_proc` - is available for a future streaming operation because it would not need to preserve the unary v1 message shape. V1 keeps the flat unary request because it is simpler for bounded bodies and avoids making every middleware implement streaming mechanics before the need is proven.

## Additional operation phases

v1 defines a single operation, `method=HttpRequest, phase=pre_credentials`, which runs after network/L7 policy admits a request and before credential injection. The same service interface can host more operations, each advertised through the `Describe` manifest and invoked through an operation-specific method such as `EvaluateHttpRequest`. Each method/phase pair encodes a different position in the proxy flow:

- `Connection/before_policy` / `HttpRequest/before_policy` - *before* network/L7 policy admits the request, for earlier classification. Riskier, because request content reaches a service before policy has allowed the request.
- `HttpRequest/pre_credentials` (v1) - after policy admits the request, before credential injection.
- `HttpRequest/post_credentials` - after credential injection, immediately before the relay writes the request upstream. This hook is credential-visible, so it is built-in-only: OpenShell marks it as a restricted hook and rejects any externally registered middleware that advertises it during manifest validation. The motivating use is request signing that must run after credentials are injected - for example a built-in `openshell/sigv4` that strips placeholder-signed AWS headers and signs the finalized request with supervisor-resolved credentials just before it is sent upstream.
- `HttpResponse/completed` - after an upstream request completes, emit metadata such as status, content length, selected route, selected model, and model usage if available. This is notification-only: no body, no transformation, and no allow/deny verdict. It would let reservation-style budget middleware reconcile a pre-dispatch decision without introducing response-body inspection.
- `HttpResponse/before_return` - on the return path, after the upstream responds and before the response reaches the sandbox; inspect or redact upstream responses.
- `WebSocketMessage/before_forward` / `WebSocketMessage/before_return` - after a WebSocket or streaming protocol upgrade, on each forwarded or returned message, well past the one-shot request path.

Pre-policy phases run earliest, the two request phases (`pre_credentials` and `post_credentials`) bracket credential injection, response notifications and response phases run after the upstream call, and message phases run later - some on a different path entirely. Of these, only `HttpRequest/pre_credentials` is part of v1. `HttpRequest/post_credentials` is the nearest planned request-path follow-up and is kept built-in-only because it sees injected credentials; `HttpResponse/completed` is a separate future notification hook for metadata-only post-call reconciliation.

## Semantic context

v1 sends the full request and lets the middleware interpret it. A future version can carry parsed semantic context (request category, semantic protocol such as OpenAI chat completions or Anthropic messages, and modalities) on `HttpRequestEvaluation`, and let policy target a semantic scope (latest user message, image parts, tool inputs). This also requires corresponding manifest fields so OpenShell can validate that a policy only references scopes and protocols the service supports.

## Content preview

ICAP-style previewing: send only the first N bytes so the service can decide whether it needs the full body before OpenShell buffers it. This reduces buffering cost for large requests that turn out not to require processing.

## Portable feature contracts and binding

A future version can introduce named feature contracts (a portable contract a policy targets, for example `pii-redaction`) with a binding from that contract to a concrete registered service. Policy would then stay portable across interchangeable implementations. v1 references middleware by name directly and defers this indirection.

## Header mutation rules

v1 lets a middleware append a constrained set of request headers, subject to an OpenShell safe-header allow-list. Credential-bearing headers, OpenShell placeholder headers, `Host`, and AWS SigV4 headers are not in scope for external middleware mutation. Future work can expand this only for restricted built-in hooks whose host capabilities make the credential boundary explicit.

## Middleware authentication

Supervisor middleware exposes gRPC services over network endpoints and authenticates with mTLS, bearer invocation tokens, or an explicit insecure mode for local research preview use. The stable middleware contract should make endpoint declaration, identity binding, credential material, and rotation explicit rather than leaving them as deployment-specific conventions.

The initial implementation may support unauthenticated plaintext gRPC only when the operator explicitly enables an insecure mode on the middleware entry (for example `allow_insecure = true`). A plaintext `http://` endpoint without this opt-in is rejected, so insecure operation is always a deliberate, auditable choice rather than an implicit consequence of the URL scheme.

This mode is suitable only for trusted local development, loopback services, or isolated research environments where the middleware endpoint is not reachable by untrusted clients. It is not suitable for shared clusters, multi-tenant deployments, public networks, or any environment where inspected request content needs transport confidentiality.

Without middleware authentication and transport security, network observers can read inspected request content, active attackers can impersonate the middleware service, and unauthorized clients can call the middleware directly if it is reachable. Because the middleware can allow, deny, or transform egress, service impersonation is a policy-enforcement bypass, not just an observability risk.

The v1 protocol shape should not bake unauthenticated plaintext into the stable contract. The auth design should define TLS trust configuration, optional mTLS, gateway-signed invocation tokens or equivalent bearer metadata, certificate or key rotation, middleware identity binding, and how the supervisor receives auth material from gateway configuration.

Even in the insecure research-preview mode, the hook should stay before provider credential injection, and OpenShell should not forward original `Authorization`, `Cookie`, or credential-bearing headers to middleware by default. That preserves the intended separation between content inspection and upstream credential injection while production middleware auth is deferred.
