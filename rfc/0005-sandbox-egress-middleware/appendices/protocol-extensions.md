# Appendix: Protocol Extensions

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

The v1 contract is intentionally minimal: one request hook, buffered unary calls, an `allow`/`deny` decision plus optional transformed content, findings, and metadata. This appendix records extensions the proto should not preclude, so v1 stays small without painting future work into a corner. None of these are committed; they exist to validate that the v1 shape is forward-compatible.

## Streaming

The hot-path RPC is already declared as a bidirectional stream (see the contract in the RFC). v1 uses it in its degenerate form: the supervisor sends one `ProcessRequest` and the middleware returns one `ProcessResponse`. This section records how the same method grows to carry chunked payloads, and importantly what streaming does and does not buy, since the distinction is easy to get wrong.

### Transport streaming vs processing streaming

These are different concepts and are easy to conflate:

- **Transport streaming** - the gRPC call carries multiple messages (chunks). This is what a service advertises in its capabilities and what the supervisor negotiates.
- **Processing streaming** - the middleware can act on partial content before it has the whole body.

The capability governs only the transport. It does not promise the middleware can process incrementally.

### Full-body guards still buffer

Many guards need the entire body to do anything: a JSON-aware redactor must parse the whole document, and a PII scan must see all of it. Such a guard, even over a streaming transport, accumulates every chunk internally, then parses, then emits a single response at end-of-stream - the decision still arrives after the last byte. Incremental processing only helps narrower cases such as byte-level regex redaction or secret scanning over a text stream.

### Why support transport streaming at all

Even when the middleware must buffer the full body, chunked transport buys two things:

- It moves the large buffer off the supervisor. The supervisor does not hold a multi-MB body to put in a single message; the middleware, which needs it anyway and can be resourced for it, accumulates it.
- It avoids gRPC's per-message size limit (4 MB by default). A 20 MB inference request cannot fit in one message without raising limits, but it can be chunked.

This is the strongest reason to keep the door open for streaming, more so than incremental parsing.

### How it would work

A service advertises chunked-transport support (and limits) in `GetCapabilities`. When supported, the supervisor may send the body as a sequence of messages; when not supported (or in v1), it buffers the bounded body and sends a single message, and a body over the cap takes the fail-closed/skip path.

Because the method is already a stream, chunking is field-additive rather than a signature change. Within a single streamed request, the first message carries the request context plus the first body bytes, and subsequent messages carry only further `body` bytes that the middleware appends; stream close marks end of request. This keeps the v1 messages flat and lets v1 stay a true single-message exchange.

A cleaner phased design -- a `oneof` over `context` and `body_chunk`, in the style of Envoy `ext_proc` - is the alternative, but it is a now-or-never choice rather than a later add-on. v1's flat message sets the context fields and `body` together, which a phase `oneof` forbids (only one member may be set), so a `oneof` cannot be retrofitted over the v1 message compatibly. We keep the flat shape because the append convention already covers the memory and message-size goals without forcing v1 into a multi-message exchange.

## Additional hooks

v1 defines a single hook, `http.request.pre_credentials`, which runs after network/L7 policy admits a request and before credential injection. The same service interface can host more hook stages, each advertised through `GetCapabilities.hooks` and invoked by its own RPC. Each name encodes a different position in the proxy flow:

- `connection.before_policy` / `request.before_policy` - *before* network/L7 policy admits the request, for earlier classification. Riskier, because request content reaches a service before policy has allowed the request.
- `http.request.pre_credentials` (v1) - after policy admits the request, before credential injection.
- `http.request.post_credentials` - after credential injection, immediately before the relay writes the request upstream. This hook is credential-visible, so it is built-in-only: OpenShell marks it as a restricted hook and rejects any externally registered middleware that advertises it during capability validation. The motivating use is request signing that must run after credentials are injected - for example a built-in `openshell-sigv4` that signs the finalized request just before it is sent upstream.
- `response.before_return` - on the return path, after the upstream responds and before the response reaches the sandbox; inspect or redact upstream responses.
- `message.before_forward` / `message.before_return` - after a WebSocket or streaming protocol upgrade, on each forwarded or returned message, well past the one-shot request path.

Pre-policy hooks run earliest, the two request hooks (`pre_credentials` and `post_credentials`) bracket credential injection, and response and message hooks run later - some on a different path entirely. Of these, only `http.request.pre_credentials` is part of v1; `http.request.post_credentials` is the nearest planned follow-up, kept built-in-only because it sees injected credentials.

## Semantic context

v1 sends the full request and lets the middleware interpret it. A future version can carry parsed semantic context (request category, semantic protocol such as OpenAI chat completions or Anthropic messages, and modalities) on `ProcessRequest`, and let policy target a semantic scope (latest user message, image parts, tool inputs). This also requires corresponding `Capabilities` fields so OpenShell can validate that a policy only references scopes and protocols the service supports.

## Content preview

ICAP-style previewing: send only the first N bytes so the service can decide whether it needs the full body before OpenShell buffers it. This reduces buffering cost for large requests that turn out not to require processing.

## Portable capabilities and binding

A future version can introduce named capabilities (a portable contract a policy targets, for example `pii-redaction`) with a binding from capability to a concrete registered service. Policy would then stay portable across interchangeable implementations. v1 references middleware by name directly and defers this indirection.

## Header mutation rules

v1 lets a middleware set a constrained set of request headers, subject to an OpenShell allow-list. Future work can formalize exactly which headers a middleware may mutate, and whether credential-bearing headers are ever in scope (today they are not; credential injection runs after the hook).

## Middleware authentication

The research preview intentionally does not define production authentication between the supervisor and an external middleware service. The initial implementation may support unauthenticated plaintext gRPC only when the operator explicitly enables an insecure mode on the middleware entry (for example `allow_insecure = true`). A plaintext `http://` endpoint without this opt-in is rejected, so insecure operation is always a deliberate, auditable choice rather than an implicit consequence of the URL scheme.

This mode is suitable only for trusted local development, loopback services, Unix-socket-like deployment shapes, or isolated research environments where the middleware endpoint is not reachable by untrusted clients. It is not suitable for shared clusters, multi-tenant deployments, public networks, or any environment where inspected request content needs transport confidentiality.

Without middleware authentication and transport security, network observers can read inspected request content, active attackers can impersonate the middleware service, and unauthorized clients can call the middleware directly if it is reachable. Because the middleware can allow, deny, or transform egress, service impersonation is a policy-enforcement bypass, not just an observability risk.

The v1 protocol shape should not bake unauthenticated plaintext into the stable contract. A follow-up auth design should define TLS trust configuration, optional mTLS, gateway-signed invocation tokens or equivalent bearer metadata, certificate or key rotation, middleware identity binding, and how the supervisor receives auth material from gateway configuration.

Even in the insecure research-preview mode, the hook should stay before provider credential injection, and OpenShell should not forward original `Authorization`, `Cookie`, or credential-bearing headers to middleware by default. That preserves the intended separation between content inspection and upstream credential injection while production middleware auth is deferred.
