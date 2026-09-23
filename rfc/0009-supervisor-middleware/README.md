---
authors:
  - "@pimlock"
state: accepted
links:
  - https://github.com/NVIDIA/OpenShell/issues/1043
  - https://github.com/NVIDIA/OpenShell/issues/1733
  - https://github.com/NVIDIA/OpenShell/issues/1734
  - https://github.com/NVIDIA/OpenShell/issues/1919
  - https://github.com/NVIDIA/OpenShell/issues/2010
  - https://github.com/NVIDIA/OpenShell/pull/2027
---

# RFC 0009 - Supervisor Middleware

## Revision history

| Date | References | Change |
|------|------------|--------|
| 2026-07-17 | [#2010](https://github.com/NVIDIA/OpenShell/issues/2010) | Added HTTP request middleware with built-in and operator-run services. |
| 2026-07-28 | [#2428](https://github.com/NVIDIA/OpenShell/issues/2428) | Added WebSocket preflight and text-message evaluation, and aligned the middleware API names, limits, and diagnostics. |
| 2026-09-17 | [#2431](https://github.com/NVIDIA/OpenShell/issues/2431), [#3307](https://github.com/NVIDIA/OpenShell/issues/3307) | Replaced the HTTP body hook with the shared BUFFERED/STREAM contract, explicit capability negotiation, bounded independent pumps, and mandatory fail-closed behavior. |

## Summary

This RFC proposes the introduction of supervisor middleware: a supervisor-side extension system for hooks that can inspect, transform, block, and annotate supervisor-managed operations at specific operation phases. The first hook family is supervisor egress middleware for outbound sandbox HTTP requests, but the framework is intentionally named and shaped so later supervisor hooks can cover other protocols or supervisor operations without renaming the feature.

## Motivation

OpenShell already controls *where* a sandbox can connect. The supervisor enforces network policy on every outbound connection and only allows egress to approved endpoints. Today, that control stops at the destination: once a connection is allowed, the request can carry any payload. Network policy can decide whether a sandbox may talk to `api.openai.com`, but it cannot decide whether a particular request to `api.openai.com` should be allowed based on what that request contains.

Users have a need to control the content that leaves the sandbox. Agents routinely send prompts, tool arguments, uploaded files, which may contain sensitive information. Acting on that traffic, requires inspecting the request itself (e.g. redacting PII or secrets before they leave the sandbox, blocking requests that carry confidential documents, requiring sensitive content to be processed by a local model).

This RFC introduces supervisor middleware and its first hook family, supervisor egress middleware: hooks that run within the supervisor proxy flow and can inspect, transform, block, and annotate outbound requests based on their content. Rather than building a fixed set of content checks into OpenShell, the middleware contract lets operators process selected requests through trusted services that implement their own logic. OpenShell cannot embed every useful detection and transformation approach. We want to allow dedicated PII tools such as Presidio or NeMo Anonymizer, organization-specific classifiers, and experimental research scanners to be plugged in. A stable contract lets teams and researchers iterate on different implementations without changing OpenShell itself.

OpenShell may still ship first-party middleware for a small number of operations where it makes sense. First-party middleware uses the same request-processing model where possible, but restricted hooks may expose supervisor-only host capabilities that external middleware can never receive.

### Use-case: Privacy Guard

Privacy Guard is the motivating use case for this RFC. It is middleware that inspects outbound request content for sensitive data and applies a mitigation before the request leaves the sandbox. We use it throughout this document as a concrete example because it exercises every property the contract needs: policy-controlled placement in the proxy flow, an external service configuration, a request/response contract, failure behavior, and audit-safe findings.

Consider an agent configured with a cloud model. The operator wants uploaded images to never reach that model. With supervisor middleware, they configure Privacy Guard on requests bound for the model endpoint. When the agent uploads an image and asks the model about it, the middleware inspects the request content, detects the image, and redacts it - replacing it with a placeholder (for example, `image upload is disabled for this model`) before the request leaves the sandbox.

Beyond redaction, middleware also produces structured findings and string metadata about a request. That metadata is only an annotation surface in v1; the model-router work will define any routing-grade typed contract later.

## Non-goals

- **Model routing.** This RFC defines the v1 string metadata that middleware can emit, but not the component that consumes findings or metadata to pick a model. Routing a request to a different model based on findings is a separate concern tracked in [#1734](https://github.com/NVIDIA/OpenShell/issues/1734). Here we only avoid blocking a future routing contract: v1 middleware decisions stay `allow`/`deny`, and any later route-selection hook should be limited to OpenShell-managed routes rather than arbitrary rewrites from one external endpoint to another.
- **A general-purpose OpenShell plugin framework.** The first version targets supervisor-owned request processing, beginning with outbound HTTP requests in the supervisor proxy flow. It is not an arbitrary plugin system for every extension point in OpenShell, and it does not cover gateway control-plane hooks, compute driver behavior, or non-supervisor extension points.
- **Constraining or sandboxing the middleware itself.** A middleware gets raw access to request content. OpenShell routes payloads to a service the operator chose to trust; it does not sandbox the middleware, verify its behavior, or prevent a malicious one from mishandling the data it inspects. Authenticated encrypted transport protects the connection but does not make the service trustworthy. Stronger service isolation, such as running middleware in its own sandbox, remains follow-up work.
- **Runtime management of middleware.** Middleware is declared in gateway configuration. A runtime CLI or API to add, list, or validate middleware - and ergonomic tooling to make registration easy, such as a dedicated command or an agent skill that scaffolds and registers a new service - is deferred to follow-up work once the contract stabilizes.
- **Guaranteeing detection correctness.** OpenShell places the hook and enforces the decision the middleware returns, but it does not guarantee that a middleware actually catches all sensitive content. Detection quality is the middleware's responsibility.
- **Support for every deployment mode.** The first version supports in-process built-ins and statically registered external middleware services. Other shapes such as WASM middleware, OpenShell-managed images, sidecars, and running middleware inside its own sandbox are not designed in this RFC. They remain explicitly open for later evaluation rather than being baked into the initial contract. See [appendices/deployment-options.md](appendices/deployment-options.md).

## Terminology

This RFC uses the following terms with specific meanings.

- **Egress.** An outbound request a sandbox sends to an upstream destination through the supervisor proxy. The v1 middleware hook acts on the parsed request the supervisor has already admitted and is about to forward, not on raw packets or arbitrary network activity.
- **Middleware.** A service that inspects, transforms, blocks, or annotates supervisor operations through the contract defined in this RFC. In the v1 egress hook, a middleware owns its detection and transformation logic and never makes the upstream call itself; the supervisor always owns the upstream call.
- **Registered middleware.** An external middleware service an operator declares in gateway configuration under a stable registration name plus a gRPC endpoint. Registration is an administrative action that establishes which endpoints may receive raw request content. Policy attaches the complete service by this operator-owned name; `Describe` reports its supported operation and phase bindings.
- **Built-in middleware.** A middleware that ships inside the supervisor binary and runs in-process, with no network hop and no gateway registration. Built-in names use the reserved `openshell/` namespace, for example `openshell/regex`.
- **Operation.** The typed method plus typed phase that identifies the point where OpenShell invokes middleware. This RFC's v1 middleware evaluates `method=HTTP_REQUEST, phase=PRE_CREDENTIALS`.
- **Hook.** A named middleware API contract for one operation. Middleware hook names are part of the middleware API, not arbitrary strings supplied by the caller. The v1 hook is `HTTP_REQUEST/PRE_CREDENTIALS`, which runs in the HTTP relay once the request is parsed and admitted by policy and before credential injection. The design allows more typed operations later without changing the v1 hook's request shape.
- **Evaluation.** One invocation of middleware for a specific operation, request context, bounded unit or body, and middleware config. Middleware keeps operation-specific streaming services because inputs and outputs differ by protocol or operation type.
- **Result.** The response to an evaluation. For the v1 HTTP request hook, the result carries an allow/deny decision, optional replacement content and safe header mutations, findings, metadata, and safe error information.
- **Middleware config.** A policy entry stored under a stable policy-local map key that namespaces metadata and diagnostics. The optional `name` field is a human-readable label and defaults to the map key. The `middleware` field selects a built-in or operator-owned registration name, while the remaining fields define service-specific configuration, endpoint selectors, failure behavior, and ordering.
- **Manifest.** The self-description a middleware returns from `Describe`: its service version and service-owned bindings for the hooks it supports. The protobuf package `openshell.middleware.v1` defines the wire-version boundary; requests and manifests do not carry a duplicate API-version string.
- **Decision.** The allow-or-deny outcome a middleware returns for a request. `allow` lets the request proceed (possibly transformed); `deny` short-circuits it. This vocabulary matches the rest of the OpenShell policy system.
- **Failure policy.** HTTP hooks are fail-closed: a missing, invalid, or incomplete result denies or aborts delivery. `on_error: fail_open` remains available only to WebSocket-only implementations.
- **Transformation.** A middleware returning replacement content, and any allowed header mutations, that the supervisor forwards in place of the original request. A later middleware in a chain sees the previous stage's transformed content.
- **Finding.** A structured, audit-safe observation a middleware reports about a request, such as a machine-readable type, safe label, count, confidence, and optional severity. A finding never carries raw matched values, redacted spans, or the original sensitive content. The supervisor maps findings into OCSF `DetectionFinding` events.
- **Metadata.** Namespaced string key/value annotations a middleware emits into a request-local bag. V1 metadata never carries raw sensitive values. Routing-grade typed metadata, including usage markers such as audit-safe, routing-safe, or internal-only, is deferred until a component consumes it.
- **Chain.** The ordered set of middleware configs that applies to a single request. Each config runs in turn, a later stage sees the previous stage's transformed content, a `deny` short-circuits the remaining stages, and each matching config runs at most once per request.

## Proposal

The first version makes supervisor middleware concrete through one egress hook family without prematurely standardizing every future deployment model. It supports first-party built-ins that run inside the supervisor and external services that the operator runs and statically registers. OpenShell routes selected egress through the resulting chain, and each stage returns a decision plus optional transformed content, findings, and metadata. This keeps the first iteration focused on the contract, failure behavior, and sandbox integration while leaving other deployment shapes open (see [appendices/deployment-options.md](appendices/deployment-options.md)).

External middleware services are exposed over gRPC network endpoints. The stable contract requires authenticated encrypted transport; phase 1 alone may explicitly opt into plaintext for trusted local or isolated research environments, and phase 2 removes that exception. See [appendices/protocol-extensions.md](appendices/protocol-extensions.md#middleware-authentication).

### Architecture

Three components participate:

- **Gateway (control plane).** Registers middleware, validates that each registered service supports the policies that reference it, and distributes the effective middleware configuration to supervisors. The gateway never sees live request bodies; it stays off the hot path.
- **Supervisor proxy (data plane).** Calls the middleware on the request hot path, enforces the returned decision, forwards only the content the middleware returns, and carries emitted metadata forward. The supervisor owns the upstream call.
- **Middleware implementation.** Inspects the request and returns a decision, optional transformed content, findings, and metadata. A middleware can be a first-party built-in installed in-process or an operator-run service reached over gRPC. Both use the same chain and result semantics and never make the upstream call. Restricted built-ins may access supervisor-only capabilities unavailable to external services.

```mermaid
graph LR
    subgraph CP["Control Plane"]
      GW["Gateway"]
    end
    subgraph SB["Sandbox"]
      AGENT["Agent process"]
      SUP["Supervisor proxy"]
    end
    subgraph MI["Middleware implementation"]
      BI["Built-in<br/>(in-process)"]
      MW["Operator-run service<br/>(gRPC)"]
    end
    UP["Upstream service"]

    GW -. "config (supervisor-initiated)" .- SUP
    AGENT -->|"outbound request"| SUP
    SUP -->|"in-process stage"| BI
    BI -->|"decision + transformed content"| SUP
    SUP -->|"request content + context"| MW
    MW -->|"decision + transformed<br/>content + metadata"| SUP
    SUP -->|"forwards allowed request"| UP
```

### Operation phases and placement

A middleware service provides hook implementations that the supervisor invokes at defined operation phases in the proxy flow. V1 defines `HTTP_REQUEST/PRE_CREDENTIALS`, `HTTP_RESPONSE/PRE_RETURN`, and `WEBSOCKET_MESSAGE/PRE_CREDENTIALS`. The supervisor invokes the request hook after policy admission and before credential injection.

```mermaid
graph LR
    REQ["Sandbox request"] --> L4["Network / L4 policy"]
    L4 --> SSRF["SSRF checks"]
    SSRF --> L7["L7 policy<br/>(when protocol set)"]
    L7 --> SELECT["Host selector<br/>(middleware chain)"]
    SELECT --> HOOK["HTTP_REQUEST / PRE_CREDENTIALS<br/>(middleware stage)"]
    HOOK -->|"deny"| DENY["Request denied"]
    HOOK -->|"allow + transformed content"| RECHECK["Body-aware L7<br/>policy re-evaluation"]
    RECHECK -->|"deny"| DENY
    RECHECK -->|"next stage or complete"| ROUTE["Route selection"]
    ROUTE --> CRED["Credential injection"]
    CRED --> UP["Upstream forwarding"]
```

This ordering is deliberate:

- Network policy (and L7 policy, where the endpoint declares a `protocol`) runs first, so OpenShell never sends already-denied traffic to a middleware service.
- Middleware selection uses the admitted request host and is independent of which user, provider, or merged network rule admitted the request. This gives the effective policy one stable selection model after policy composition.
- Middleware runs before credential injection, so a middleware never receives OpenShell-managed upstream credentials.
- After a stage replaces the request body, OpenShell re-evaluates body-aware GraphQL, JSON-RPC, or MCP policy before invoking the next stage or forwarding upstream. A policy evaluation error or an unparseable replacement is a hard denial. An enforced policy denial stops and denies. In audit mode, OpenShell records the denial, stops the remaining middleware chain, and forwards the transformed request.
- A middleware's explicit denial and `fail_closed` behavior are enforcement decisions in their own right and remain blocking even when the network endpoint uses `enforcement: audit`.
- Route selection - choosing which upstream, and in future which model, serves the request - runs after the hook, so the later model-router work has a clear handoff point for any middleware findings or metadata it chooses to consume. There is no model router in v1; this box marks where one would plug in. Middleware does not forward traffic itself, and v1 deliberately has no `forward_to` decision. Any later route-selection phase should return an OpenShell-owned route decision for managed destinations, not an arbitrary rewrite from one external endpoint to another.
- The upstream call stays owned by the supervisor, never the middleware.

The hook operates on a parsed HTTP request, so it runs wherever OpenShell can parse one. The supervisor proxy TLS-terminates and HTTP-parses every egress connection that is not marked `tls: skip` and is not opaque, non-HTTP traffic, so the hook fires on those requests regardless of whether the endpoint also declares a `protocol`. Declaring a `protocol` additionally subjects the request to L7 Rego policy; an endpoint without one is still terminated and parsed and the middleware hook runs on it. The only traffic the hook cannot inspect is traffic OpenShell never parses: `tls: skip` endpoints and opaque TCP or TLS passthrough. Policy validation rejects any middleware selector whose possible hosts overlap an endpoint configured with `tls: skip`, so selector-based middleware cannot be silently bypassed by an unparsed path.

> **Update in PR #2477 - WebSocket middleware:** The following text extends the original HTTP-only scope. It adds operation-specific selection, client WebSocket text-message inspection, and explicit coverage for traffic that an attached middleware cannot inspect.

If an HTTP chain becomes uninspectable at runtime, OpenShell denies the request because HTTP middleware is always fail-closed. For a WebSocket-only chain, OpenShell denies when any selected stage is `fail_closed`; an all-`fail_open` chain may continue after emitting a bypass `DetectionFinding`. This chain-level rule prevents one permissive WebSocket stage from overriding a required stage.

Attachment and operation selection are separate. A destination host selector attaches a policy config, then the implementation manifest decides whether that config participates in `HTTP_REQUEST/PRE_CREDENTIALS`, `HTTP_RESPONSE/PRE_RETURN`, `WEBSOCKET_MESSAGE/PRE_CREDENTIALS`, or multiple phases. The absence of an operation binding is a declared capability boundary rather than a middleware failure, so `on_error` does not apply. OpenShell records informational coverage when an attached config does not join the WebSocket chain.

WebSocket sits on this boundary. The upgrade request is a normal HTTP/1.1 request that an HTTP binding can inspect, allow, or deny. A separate V1 operation covers complete client-to-upstream text messages after upgrade. Binary messages, control frames, and upstream-to-client messages remain outside that operation. To keep the v1 boundary unambiguous:

**In scope for v1:**

- Inspectable HTTP/1.x requests that OpenShell terminates and parses, after L4 and SSRF admit them (and L7 policy too, where the endpoint declares a `protocol`).
- Final HTTP/1.x responses before delivery, using header-only or whole-body inspection. Response streaming is reserved for a later rollout.
- WebSocket upgrade (handshake) requests - the HTTP request that initiates the upgrade.
- Complete client-to-upstream WebSocket text messages for implementations that advertise `WEBSOCKET_MESSAGE/PRE_CREDENTIALS`.
- Fixed-length and chunked request bodies normalized into bounded units, including bodies larger than one gRPC message.
- Safe metadata output for later routing or audit.

**Out of scope for v1:**

- HTTP/2 and HTTP/3. The proxy's TLS termination pins ALPN to `http/1.1` today, so these are not introspected.
- Binary and control WebSocket messages and upstream-to-client WebSocket messages.
- Opaque TCP streams and endpoints with `tls: skip`.
- Unbounded request processing. STREAM is duplex, but queues, units, and timeouts remain bounded and middleware owns any processing storage.
- Multipart or compressed body semantics, unless a selected service's manifest and policy explicitly support them within the size limits.

The request hook opens one bidirectional stream for every selected stage. Timeout, failure behavior, lifecycle validation, and backpressure are load-bearing parts of the design. Preflight continues without a body, rejects, or selects one of two modes. BUFFERED carries one complete body in bounded RAM and returns explicit unchanged or replacement bytes. STREAM has independent input and output pumps; output may start before input ends, cardinalities need not match, and middleware owns any processing storage. OpenShell caps request units at 64 KiB, uses bounded byte/message queues, never creates a middleware disk spool, and never retains a recovery copy. A pure STREAM chain may forward output upstream as it arrives; BUFFERED, body-aware policy re-evaluation, and request-body credential rewriting hold a bounded complete representation. OpenShell never replays a partially forwarded request. Request body receipt, middleware processing, and output delivery share a two-minute wall-clock deadline. HTTP failures are always closed. The hook remains before credential rewrite, which keeps OpenShell-managed credentials away from external middleware.

### The middleware contract

The contract has two parts: a configuration-time handshake and a request-time evaluation. The evaluation runs on the *hot path* - the synchronous, per-request path through the supervisor proxy, as opposed to the control-plane path used to fetch config. Middleware only sits on this path for sandboxes whose policy configures it: a sandbox with no middleware in its policy is unaffected and pays no per-request cost. Middleware is therefore an explicit opt-in, and this change is transparent to existing usage.

Configuration-time:

- `Describe` reports a service-provided diagnostic name, service version, and service-owned bindings for the typed operation and phase pairs it supports. A binding includes its maximum accepted body size and may override the service RPC timeout.
- `ValidateConfig` lets the service validate its own service-specific configuration fragment.

Request-time:

- `HttpRequestPreCredentials.EvaluateHttp` and `HttpResponsePreReturn.EvaluateHttp` share a bidirectional `HttpEvent`/`HttpResult` schema. Preflight carries request or response context, safe headers, offered modes, and effective limits.
- BUFFERED sends one complete body and receives explicit unchanged or replacement bytes.
- STREAM sends independent input chunks plus input end and receives output start, independent output chunks, and finish. Finish is valid only after input end.
- A best-effort terminal notification completes the lifecycle.

A simplified sketch of the gRPC contract:

```protobuf
service SupervisorMiddleware {
  // Configuration-time
  rpc Describe(google.protobuf.Empty) returns (MiddlewareManifest);
  rpc ValidateConfig(ValidateConfigRequest) returns (ValidateConfigResponse);
}

// operation=HTTP_REQUEST, phase=PRE_CREDENTIALS.
service HttpRequestPreCredentials {
  rpc EvaluateHttp(stream HttpEvent) returns (stream HttpResult);
}

service HttpResponsePreReturn {
  rpc EvaluateHttp(stream HttpEvent) returns (stream HttpResult);
}

message MiddlewareManifest {
  string name = 1;                      // service-provided diagnostic name
  string service_version = 2;           // service implementation version, informational
  repeated MiddlewareBinding bindings = 3;
}

message MiddlewareBinding {
  SupervisorMiddlewareOperation operation = 1;
  SupervisorMiddlewarePhase phase = 2;
  uint64 max_payload_bytes = 3;         // zero for preflight-only HTTP bindings
  google.protobuf.Duration request_timeout = 104;
  uint32 http_protocol_version = 5;
  repeated HttpBodyMode supported_http_body_modes = 6;
}

message HttpEvent {
  oneof event {
    HttpPreflight preflight = 1;
    HttpBegin begin = 2;
    HttpInputChunk input_chunk = 3;
    HttpInputEnd input_end = 4;
    HttpBufferedBody buffered_body = 5;
    MiddlewareSessionEnd session_end = 6;
  }
}

message HttpResult {
  oneof result {
    HttpPreflightResult preflight_result = 1;
    HttpBufferedResult buffered_result = 2;
    HttpOutputStart output_start = 3;
    HttpOutputChunk output_chunk = 4;
    HttpFinish finish = 5;
    HttpReject reject = 6;
  }
}

message HttpPreflight {
  oneof head {
    HttpRequestPreflightHead request = 1;
    HttpResponsePreflightHead response = 2;
  }
  repeated HttpBodyMode permitted_body_modes = 3;
  repeated HttpBodyMode late_header_modes = 4;
  HttpBodyLimits limits = 5;
  // Original admitted representation length; later body events may differ.
  optional uint64 declared_input_bytes = 6;
}

enum HttpBodyMode {
  HTTP_BODY_MODE_UNSPECIFIED = 0;
  HTTP_BODY_MODE_BUFFERED = 1;
  HTTP_BODY_MODE_STREAM = 2;
}

message HttpPreflightResult {
  oneof decision {
    HttpContinue continue_without_body = 1;
    HttpInspect inspect = 2;
  }
  repeated HeaderMutation header_mutations = 3;
  MiddlewareDiagnostics diagnostics = 4;
}

message HttpInspect {
  oneof mode {
    HttpBufferedMode buffered = 1;
    HttpStreamMode stream = 2;
  }
}

message HttpBufferedBody {
  bytes data = 1;
  repeated HttpHeader visible_trailers = 2;
}

message HttpBufferedResult {
  oneof body {
    HttpUnchanged unchanged = 1;
    bytes replacement = 2;
  }
  repeated HeaderMutation trailer_mutations = 4;
  MiddlewareDiagnostics diagnostics = 5;
}

message HttpInputChunk {
  bytes data = 1;
}

message HttpInputEnd {
  repeated HttpHeader visible_trailers = 1;
}

message HttpOutputStart {
  optional uint64 output_body_bytes = 2;
}

message HttpOutputChunk {
  bytes data = 1;
}

message HttpFinish {
  repeated HeaderMutation trailer_mutations = 1;
  MiddlewareDiagnostics diagnostics = 2;
}

message RequestContext {
  string request_id = 1;
  string sandbox_id = 2;
  Process originating_process = 3;      // optional, per-connection
  string sandbox_name = 4;              // display and logging only
  string workspace = 5;                 // display and logging only
}

message HttpRequestTarget {
  string scheme = 1;
  string host = 2;
  uint32 port = 3;
  string method = 4;
  string path = 5;
  string query = 6;                     // raw request query string; never log
}

// Mirrors the originating process OpenShell already resolves for network policy and OCSF audit.
message Process {
  string binary = 1;                    // resolved binary path
  uint32 pid = 2;
  repeated string ancestors = 3;        // ancestor binary paths from the process-tree walk
}

message Finding {
  string type = 1;                       // e.g. "pii.email"
  string label = 2;                      // safe display label
  uint32 count = 3;                      // number of matches, never raw values
  string confidence = 4;                 // service-defined confidence marker
  string severity = 5;                   // service-defined severity marker
}

message HttpHeader {
  string name = 1;
  string value = 2;
}

message HeaderMutation {
  oneof operation {
    WriteHeader write = 1;
    RemoveHeader remove = 2;
  }
}

message WriteHeader {
  string name = 1;
  string value = 2;
  ExistingHeaderAction on_existing = 3; // APPEND, OVERWRITE, or SKIP
}

message RemoveHeader {
  string name = 1;
}

```

The event and result streams compose as a chain over one request representation. A stage's accepted body and safe header or trailer mutations feed the next stage; an explicit rejection short-circuits the rest. STREAM transfers output responsibility at preflight and does not imply input/output correspondence. See [Middleware ordering](#middleware-ordering) for how chains are assembled and ordered.

Headers use a repeated representation so duplicate lines and wire order survive evaluation and chaining. Before an external call, OpenShell omits credential-bearing, routing, framing, hop-by-hop, and `Connection`-nominated headers. A result may return ordered writes and removals for middleware-visible end-to-end headers. Writes support append, overwrite, and skip modes. Credential-bearing, routing, framing, hop-by-hop, `Connection`-nominated, and OpenShell credential headers remain protected. Header values containing control characters or credential placeholders are invalid. OpenShell validates and applies a stage's mutations atomically. If any mutation is invalid, none are applied. HTTP fails closed; WebSocket-only stages follow their configured `on_error` behavior.

> **Update in PR #2477 - WebSocket middleware:** The following contract text adds the bidirectional `EvaluateWebSocketSession` RPC, WebSocket preflight, message limits, and the WebSocket binding for the built-in regex middleware.

The interface is gRPC. HTTP bindings explicitly advertise protocol version `1` and supported body modes; an empty mode list declares preflight-only handling. OpenShell rejects missing versions, unknown modes, and attempts to inspect a body through a preflight-only binding. HTTP requests and responses use distinct `EvaluateHttp` method paths with the shared two-mode schema; client-to-upstream WebSocket text messages use `EvaluateWebSocketSession`. Built-in middleware uses the same logical contracts in-process. `openshell/regex` advertises request and WebSocket bindings. Endpoint `credential_signing` fields continue to configure the existing proxy-side SigV4 path; moving SigV4 into middleware is separate work.

V1 applies explicit public envelope limits before invoking a service or accepting its result: 64 KiB for encoded config, 4 KiB for request context, 32 KiB for the target, 128 header lines and 64 KiB of encoded headers, 4 MiB for a buffered payload or advertised unit, 64 KiB for each request stream unit, 4 KiB for a reason, 64 header mutations with at most 32 KiB of validated name/value data and 64 KiB encoded, 32 findings per stage with each finding at most 4 KiB encoded, and 64 metadata entries totaling at most 32 KiB. STREAM also advertises bounded input and output queues. A chain has at most 10 stages and therefore at most 320 findings.

For WebSocket traffic, a service advertises `WEBSOCKET_MESSAGE/PRE_CREDENTIALS` with `max_payload_bytes`, which limits one complete message or replacement rather than the whole session. For HTTP request traffic, the field limits a whole-body representation or individual stream unit. A preflight-only HTTP binding advertises no body modes, may leave `max_payload_bytes` at zero, and can only continue with optional header mutations or reject. On continue, the body bypasses that stage unchanged. An attached service without the exact operation binding does not join that chain and does not apply `on_error`. OpenShell opens one phase-specific stream per selected stage. Preflight exposes only the admitted destination, sandbox context, attached middleware name, validated config, and bounded safe headers. Each stage returns inspect, voluntary skip, or authoritative deny before body processing begins. Explicit denial is a successful decision enforced independently of `on_error`; failures follow the stage's failure policy. OpenShell sends a terminal reason to each still-writable opened stream at most once.

Inspectable WebSocket text input and replacements share the 4 MiB platform cap. The operator's `max_payload_bytes` is the shared HTTP-body and WebSocket-text ceiling, further constrained by each operation binding's capability. It does not bound binary pass-through, which retains a separate raw-frame safety limit. Logical messages use a protobuf `oneof` with `string text` and `bytes binary` variants; results use an optional matching replacement `oneof`, whose presence also represents an empty replacement without a separate boolean. Protobuf decoding enforces UTF-8 for text, and OpenShell rejects replacement variants that would change the message type. A complete text message holds one process-wide admission permit for its entire chain; preflight fan-out holds one permit until every stage resolves. Permit waiting is backpressure and does not consume the per-message deadline. Per-stage timeouts are also bounded by a 30-second chain budget for one WebSocket message, one HTTP body-unit pass, or one HTTP finalization pass. This is not an accepted-stream lifetime or rate limit. Request body receipt, middleware processing, and output delivery have a separate two-minute total deadline.

The `originating_process` is the same identity OpenShell resolves on the egress path - the binary, pid, and ancestor chain it uses for binary-scoped network policy and OCSF audit. It is per-connection rather than strictly per-request and is optional. Middleware must treat missing process data as unavailable rather than as an authorization failure. The initial implementation leaves this field unset until reliable propagation is available.

### Relationship to RFC 0010

[RFC 0010](https://github.com/NVIDIA/OpenShell/pull/1927) defines gateway interceptors: gateway control-plane extensions that evaluate gateway RPCs such as `CreateSandbox`. This RFC defines supervisor middleware: supervisor data-plane extensions that evaluate supervisor-managed operations such as `HTTP_REQUEST/PRE_CREDENTIALS`. The feature names may differ because the API surfaces and mechanics differ, but the two extension systems should align on shared plumbing where doing so avoids duplicate infrastructure.

Shared mechanics:

- **Endpoint exposure and auth.** Both extension systems use gRPC network endpoints. Their stable transport contract requires confidentiality and service authentication. During phase 1 only, supervisor middleware may explicitly opt into plaintext for trusted local or isolated research environments. Endpoint declaration, identity binding, credential material, and rotation should use shared mechanics where practical.
- **Manifest description.** Both extension systems use `Describe` to return a manifest that declares a diagnostic service name, implementation version, and service-owned bindings for supported hook points.
- **Operation phases.** Both systems hook into a named operation plus phase. The phase sets differ by system, but the concept is the same: `method=CreateSandbox, phase=pre_request` for a gateway interceptor, and `HTTP_REQUEST/PRE_CREDENTIALS` for v1 supervisor middleware.
- **Evaluation and result.** Both systems run evaluate-style exchanges. Middleware keeps operation-specific streaming services such as `HttpRequestPreCredentials` because inputs and outputs differ by protocol or operation type; interceptor methods and messages are defined by RFC 0010.
- **Failure policy.** HTTP middleware is fail-closed. WebSocket-only middleware retains `on_error: fail_closed|fail_open`; gateway interceptors keep their own failure contract.
- **Observability.** Both systems emit OCSF events with the details relevant to the extension point, while preserving the same no-secrets logging rules.
- **Ordering.** Both systems apply multiple configured extensions in deterministic order.

Intentional differences:

- **Selection model.** Supervisor middleware is selected per sandbox at runtime through policy and API state. Gateway interceptors are selected for the gateway at deploy time by operators in `gateway.toml`.
- **Method naming.** Gateway interceptors register against RPC method strings that are not themselves part of the interceptor API. Supervisor middleware exposes named operation-specific services such as `HttpRequestPreCredentials`; those names are part of the middleware API contract.
- **Control responsibility.** Gateway interceptors may enforce that sandbox requests include approved middleware configuration, but they do not replace the per-sandbox middleware selection model.

### Contract versioning

The middleware gRPC contract lives under a major-versioned protobuf package (`openshell.middleware.v1`), the same convention the compute-driver contract uses in [RFC 0001](../0001-core-architecture/README.md). Within a stable major version, changes stay additive and backward compatible - new fields, RPCs, operation phases, and manifest fields can be added - while breaking wire or semantic changes require a new major version. The research preview may still make intentional breaking changes before the contract is declared stable.

The protobuf package and each HTTP binding's explicit protocol version form the wire-version handshake. `Describe` reports a diagnostic service name, implementation version, operation/phase bindings, and HTTP body capabilities. Manifest validation is mandatory: if OpenShell cannot fetch the manifest, bindings conflict, capabilities are missing, or policy asks for an unsupported implementation or invalid config, the gateway rejects the relevant configuration before traffic can depend on it. HTTP runtime invocation failures are fail-closed.

### Registration and delivery

The operator registers available external middleware services in gateway configuration under `openshell.supervisor.middleware`. The namespace identifies the subsystem whose behavior is extended, not the process that reads the configuration. The gateway loads, validates, and distributes these registrations to supervisors. Each entry has an operator-owned name, gRPC endpoint, maximum payload size, optional RPC timeout, and transport settings. Policy authors select that registration name; they cannot point traffic at an arbitrary endpoint. The service-reported manifest name remains diagnostic metadata.

The v1 transport is gRPC over a network endpoint reachable from every supervisor across Docker, Podman, VM, and Kubernetes drivers. In local single-player deployments, a loopback endpoint such as `127.0.0.1:1234` may be translated to `host.openshell.internal` so a supervisor can reach a service running on the local host. That loopback shorthand is not an HA deployment model: Kubernetes and other shared deployments should register a routable service DNS name or address that every supervisor can reach directly. Other deployment shapes are deferred until OpenShell has a universal way to make those endpoints reachable from the relevant supervisor environments.

```toml
[[openshell.supervisor.middleware]]
name = "anonymizer"
grpc_endpoint = "http://127.0.0.1:1234"
max_payload_bytes = 4194304
timeout = "500ms"
allow_insecure_transport = true

[[openshell.supervisor.middleware]]
name = "agent-traces-exporter"
grpc_endpoint = "https://middleware.example.internal:443"
max_payload_bytes = 1048576
```

The stable transport requirement is confidentiality plus authentication of the intended middleware service. Phase 1 may temporarily accept a plaintext `http://` endpoint only when the same entry explicitly sets `allow_insecure_transport = true`. OpenShell rejects plaintext without that opt-in, warns prominently, and records the insecure registration as auditable configuration state. This escape hatch is limited to trusted local development and isolated research environments. Phase 2 removes plaintext support and the opt-out field, requiring authenticated encrypted transport. That removal is an intentional research-preview breaking change with no long-term compatibility obligation. The exact phase 2 mechanism, such as mTLS or TLS plus caller authentication, is follow-up protocol work.

For each payload-bearing binding, the operator's `max_payload_bytes` must be positive and must not exceed the binding capability returned by `Describe` or the 4 MiB platform maximum. The gateway rejects an invalid registration rather than silently clamping it. A service with only preflight-only HTTP bindings may configure zero; those bindings ignore the shared operator limit. BUFFERED uses the effective limit for the complete input and replacement separately; STREAM uses it per unit, with request units further capped at 64 KiB.

RPC timeouts use an integer with an `ms` or `s` suffix, range from 10 ms through 30 s, and default to 500 ms. A binding may advertise its own timeout through `Describe`; OpenShell uses the smaller of that timeout and the operator setting. The operator timeout applies to `Describe` and `ValidateConfig`; the effective binding timeout applies to stream open and individual request exchanges.

The external-service endpoint is trusted operator infrastructure in v1. The auth design must make both directions explicit: the supervisor proves to the middleware that the call is authorized for the specific middleware identity, and the supervisor verifies it is calling the intended middleware service.

Middleware names may be bare (`anonymizer`) or namespaced with `/` (`nvidia/anonymizer`, `acme/security/pii-redactor`). Empty path segments are invalid, so `/foo`, `foo/`, and `foo//bar` are rejected. The `openshell/` namespace is reserved for built-in OpenShell middleware, such as `openshell/regex`. Policy config map keys remain stable local identities for metadata namespacing and diagnostics; the `middleware` field selects the built-in or operator registration.

Built-in middleware ships in the supervisor binary and needs no external registration. Supervisors install built-in bindings before attempting external connections.

At gateway startup, OpenShell connects to every registered service and calls `Describe`. Startup rejects unavailable or invalid services, duplicate registration names, conflicting operation/phase bindings, restricted external phases, and external claims in the reserved `openshell/` namespace. Sandbox policy creation and update call the owning service's `ValidateConfig` before persistence.

Supervisors receive policy plus the external service registrations required by the effective policy through the existing `GetSandboxConfig` response. Built-in registrations are not delivered because they are already installed in-process. The gateway stays off the request hot path; supervisors connect to the required services and invoke them directly.

Runtime changes are prepared off to the side. Policy and middleware registry swap as one generation only after the complete candidate is ready. A policy-only update reuses an already connected registry. If preparation fails, the supervisor preserves the complete last-known-good runtime and continues retrying. If an external service is unavailable when a supervisor starts or reloads, built-ins remain active, HTTP requests fail closed, WebSocket-only stages use each selected config's `on_error`, and a polling loop retries the service independently of policy revision changes.

Middleware registration lives in gateway configuration, which is not hot-reloaded ([RFC 0003](../0003-gateway-configuration/README.md) lists this as a non-goal): changing the registered set requires restarting the gateway. Middleware selection is separate from registration. Registration declares what implementations are available to supervisors; per-sandbox policy and API updates decide which middleware configs apply to a given sandbox at runtime. On restart, supervisors re-sync the effective configuration over their existing connection, so running sandboxes pick up a newly added middleware rather than only newly created sandboxes seeing it - there is no per-sandbox snapshot of the registered set.

Removing a registered middleware that an active policy config still binds to makes HTTP traffic fail closed. WebSocket-only stages follow the affected config's `on_error`; `fail_closed` is the default. For now, the operator is responsible for removing policy configs before removing the registration. Runtime process or network failures follow the same rule while the supervisor retries the connection.

V1 does not define a separate health-check RPC. Connection establishment, `Describe`, per-request invocation, timeout, `on_error`, and the registry retry loop provide the required availability behavior. A dedicated health API may improve alerting later but is not required for correctness.

Multitenancy is handled by OpenShell policy selection, not by giving middleware its own tenant-routing model. A shared middleware service may receive requests from many sandboxes, but the service should treat `sandbox_id`, policy name, and endpoint context as audit context only unless a later OpenShell domain object defines stronger grouping semantics. Middleware-specific tenant grouping is possible but not part of the OpenShell contract.

### Policy integration

Policy decides which middleware runs for which traffic, how it is configured, and what happens on failure. Middleware configs live once in the top-level `network_middlewares` map, represented as `map<string, NetworkMiddlewareConfig>` in `SandboxPolicy`. Each map key is the stable policy-local identity. Each config selects destination hosts directly through `endpoints.include` and `endpoints.exclude`; network policies and endpoints do not carry middleware attachment lists.

A middleware config may include an optional human-readable `name`, which defaults to the map key and does not replace that key as the config identity. `middleware` is a stable built-in or operator-owned registration name. Different map keys may reference the same implementation and run as separate stages with different selectors or configuration.

Each entry supplies implementation-owned configuration, `on_error` behavior, numeric `order`, and endpoint selectors. `fail_closed` is the default. `order` defaults to `0` and must be unique across the complete policy, even when selectors do not overlap, so policies with multiple configs normally set it explicitly. OpenShell validates the structure and asks the owning implementation to `ValidateConfig` before the gateway persists a policy.

Selection occurs after network and L7 admission and depends only on the admitted request host. It does not depend on which user-authored, provider-derived, broad, specific, or merged network rule admitted the request. This independence is important because effective policy composition may change the admitting rule without changing the intended content controls.

Every config requires a non-empty `include` list. `exclude` is optional and takes precedence over `include`. Matching is case-insensitive and uses the same host-pattern implementation as network endpoints: `*` matches exactly one DNS label, `**` matches one or more DNS labels, and intra-label wildcards such as `*-api.example.com` are supported. Brace alternates are rejected; authors list each alternative explicitly. A config accepts at most 32 combined include and exclude patterns. A policy accepts at most 10 middleware configs, and runtime selection defensively rejects a chain longer than 10 stages.

The hook is a supervisor-side Rust enforcement stage selected by policy data, not a Rego rule. L4 policy admits the connection and, where the endpoint declares a `protocol`, L7 policy admits the parsed request. The supervisor then selects the chain, opens event streams, applies valid results, and re-evaluates body-aware protocol policy after each body replacement. Body-aware protocols retain a bounded hold barrier for this re-evaluation. Other HTTP/1 paths either forward pure STREAM output incrementally or retain a bounded body in RAM when BUFFERED or policy re-evaluation needs it. OpenShell does not create a middleware disk spool. Request bodies do not otherwise become a new general Rego input surface.

```yaml
network_middlewares:
  regex-redactor:
    name: Redact sensitive tokens
    middleware: openshell/regex
    order: 10
    config:
      mode: redact
    on_error: fail_closed
    endpoints:
      include: ["*.example.com"]
      exclude: ["trusted.example.com"]

  anonymize:
    middleware: acme/anonymizer
    order: 20
    config:
      pii: redact
    on_error: fail_closed
    endpoints:
      include: ["api.example.com"]

  export-traces:
    middleware: acme/trace-exporter
    order: 30
    config:
      exclude_images: true
    on_error: fail_closed
    endpoints:
      include: ["api.example.com"]
```

With this policy, a request to `api.example.com` runs `regex-redactor`, `anonymize`, and `export-traces` in that order. A request to `trusted.example.com` does not run `regex-redactor` because exclusion wins. `openshell/regex` is a best-effort example that applies a fixed set of regular-expression replacements to UTF-8 bodies; it is not parser-aware and does not guarantee detection or complete removal of sensitive values. If `anonymize` fails, the request is denied. If `export-traces` fails, the stage is bypassed, the rest of the chain continues, and OpenShell emits a detection finding.

V1 middleware configs are policy-local and are not embedded in provider profiles. Their host selectors run after effective policy assembly, so they cover provider-supplied endpoints without mutating or attaching data to the provider policy. Reusable cross-sandbox middleware profiles and provider-profile opt-ins remain follow-up design work.

### Middleware ordering

When more than one middleware config matches a request, the supervisor sorts them by ascending numeric `order`. Order values must be unique across the policy and duplicate values are rejected during validation. `order` defaults to `0`, so policies with multiple configs normally set explicit values. Each matching config runs once. Different map keys that reference the same binding remain separate stages and may therefore run more than once with distinct configuration.

A later stage sees the earlier stage's accepted body and header mutations. A middleware rejection or HTTP-stage failure short-circuits the chain and fails closed. WebSocket-only stages may use `fail_open` as described in the WebSocket contract.

`before` and `after` constraints are deferred until reusable middleware profiles or cross-policy composition creates a demonstrated need for partial ordering. Implementation-defined ordering is rejected because middleware can transform request content, so operators require deterministic and reviewable behavior.

### Metadata and downstream routing

Beyond allow/deny and transformation, middleware emits string metadata (for example `modalities = "text,image"`, `sensitivity = "restricted"`, `requires_local_model = "true"`) into a request-local metadata bag. The supervisor stores that metadata under the middleware config's stable map key, so `anonymize.sensitivity` and `budget.sensitivity` do not collide even if two services return the same key. V1 metadata is intentionally string-only and never carries raw sensitive values. This gives early middleware a safe annotation surface while deferring routing-grade typed metadata and usage markings to the model-router work; the router itself is out of scope ([#1734](https://github.com/NVIDIA/OpenShell/issues/1734)).

Because `HTTP_REQUEST/PRE_CREDENTIALS` runs before route selection and credential injection, v1 does not guarantee that metadata visible at this hook includes the final routed model or upstream route. Budget-style middleware that needs post-call status, final route/model, content length, or token usage needs a later metadata-only notification hook such as `HttpResponse/completed`; that hook is listed as a future extension in the [protocol-extensions appendix](appendices/protocol-extensions.md#additional-operation-phases), not part of the v1 request hook.

The namespace is the policy-local middleware config map key, not the optional human-readable `name` or registered implementation name. This means two configs that use the same implementation still produce separate metadata buckets, and changing a display label or the registered service behind a config does not rename downstream annotations.

### Audit and logging

A middleware decision is observable sandbox behavior, so it is recorded as an OCSF event, consistent with how the supervisor already logs network and L7 enforcement. This RFC commits to the event categories and the safety rules; exact field mappings are an implementation detail.

> **Update in PR #2477 - WebSocket middleware:** The coverage-boundary event below is new. It distinguishes an unsupported operation or message type from a middleware invocation or failure.

- **Per-invocation decisions** are `HttpActivity` events, since middleware is an L7 enforcement point. Each stage records the policy-local config key, registered implementation name, decision, transformation state, latency, and policy and endpoint context. Allowed requests are `Informational`; denials are `Medium`.
- **Enforcement failures and bypasses** also emit `DetectionFinding` events. HTTP-stage failures, invalid responses, uninspectable HTTP traffic, and body-aware policy evaluation failures are `High`. A WebSocket-only `fail_open` bypass is still a finding so operators can alert on reduced enforcement.
- **Coverage boundaries** emit informational `NetworkActivity` events separately from invocations and failures. `binding_not_selected` records an attached config whose manifest lacks the WebSocket binding. `unsupported_message_type` records binary pass-through for an active stage with its internal config identity, logical sequence, message class, and size.
- **Configuration events** are `ConfigStateChange` events: middleware registration validation, registry reload success or failure, and policy validation outcome.

These events must never leak the content they describe. The OCSF JSONL may be shipped to external systems, so:

- Raw request content, matched values, redacted spans, and service-config secrets are never logged.
- Built-ins may preserve contract-defined audit-safe reasons and finding fields. Operator-run reason text, finding text, mutation errors, and diagnostic metadata are untrusted input. OpenShell replaces or omits them in denied responses and security logs, using stable platform-owned messages derived from the validated binding and failure category.
- Events carry only safe summaries: policy-local config keys, validated implementation names, decisions, latency, platform-owned failure categories, and aggregate counts.

This mirrors the middleware response contract, which already forbids the service from returning raw matched values.

## Implementation plan

Supervisor egress middleware stays opt-in throughout: until a policy declares a matching middleware config, no sandbox invokes one and the proxy hot path is unchanged. The initial usable slice proves built-in and external execution together; the phase boundary is transport hardening, not whether external middleware exists.

> **Update in PR #2477 - WebSocket middleware:** Phase 1 now also includes the forward-text WebSocket operation, bounded WebSocket messages, and the WebSocket binding for the built-in regex middleware.

**Phase 1 - research-preview contract and execution.** Define `openshell.middleware.v1` with `Describe`, `ValidateConfig`, bidirectional HTTP request/response streams, and forward-text `EvaluateWebSocketSession`; ship `openshell/regex`; and support statically registered operator-run services. Policy uses a top-level selector-based `network_middlewares` map with stable config keys, unique numeric `order`, fail-closed HTTP handling, bounded units and bodies, bounded RPC timeouts, atomic header mutations, post-transformation policy re-evaluation, and OCSF observability. Gateway startup validates external manifests, policy writes validate implementation-owned config, effective sandbox config carries only required external registrations, and supervisors install policy plus registry as one last-known-good runtime generation. Phase 1 requires encrypted authenticated transport for normal use but temporarily permits plaintext `http://` only with explicit `allow_insecure_transport = true` for trusted local development or isolated research. OpenShell warns and emits auditable configuration state whenever that exception is used.

**Phase 2 - mandatory authenticated encryption.** Remove plaintext middleware transport and remove `allow_insecure_transport`. Every external connection must provide transport confidentiality and authenticate the intended service, with the final mechanism and credential delivery model defined by follow-up protocol work. Because phase 1 is explicitly a research preview, removing its insecure escape hatch is an intentional breaking change and does not create a long-term compatibility obligation. Operator-run service deployment otherwise keeps the same binding, policy, validation, delivery, reload, and invocation model.

### Backwards compatibility and migration

Existing sandbox policies and gateway configs that declare no middleware remain valid and pay no per-request cost. The HTTP API change is intentionally breaking within the research preview: services must implement `EvaluateHttp`, advertise protocol version `1` and body capabilities, follow the two-mode lifecycle, and register the phase-specific gRPC service beside `SupervisorMiddleware`. There is no fallback. Middleware configs that opt into phase 1 plaintext are intentionally temporary and must migrate to authenticated encrypted endpoints before phase 2. The research-preview contract may make other breaking changes before stability.

### Research preview

The first release is a research preview. The contract, policy surface, and scope are provisional and may change without the usual compatibility guarantees. Plaintext is a phase 1 exception, not part of the stable design. Production and shared deployments must use authenticated encrypted transport, and phase 2 removes the exception entirely (see [appendices/protocol-extensions.md](appendices/protocol-extensions.md#middleware-authentication)). The goal is to validate the contract and operational model through early experiments with a built-in middleware plus a small number of trusted external services before committing to long-term stability.

## Risks

Adding a synchronous, content-aware hook to the egress path has real costs. The most significant:

> **Update in PR #2477 - WebSocket middleware:** OpenShell now bounds concurrent middleware work and buffered memory. It does not add request-rate limiting. The updated rate-limit risk below keeps that distinction explicit.

- **Hot-path latency and a new per-request dependency.** Each selected external stage makes a synchronous call and blocks on its reply, so middleware latency becomes request latency and the service becomes a new failure surface on the data plane. This is bounded by opt-in host selectors, per-middleware timeouts, and built-ins running in-process with no network hop, but for matching traffic the tax is unavoidable.
- **Fail-closed breaks workloads.** Denying traffic when a required middleware is unavailable, times out, or returns a malformed response is the safe default, but it converts a middleware outage into a sandbox outage. The opposite default leaks the very content the middleware exists to control. There is no choice that is both safe and always available; `on_error` makes the tradeoff explicit per middleware, but operators can still pick a default that surprises them.
- **Storage and size limits.** BUFFERED retains a bounded body in supervisor RAM. STREAM reduces protobuf-message and relay-memory pressure but does not remove finite unit, queue, timeout, or optional total limits. Middleware owns any processing storage and cleanup. OpenShell retains no recovery copy and never spools middleware bodies to disk.
- **No OpenShell-side rate limiting.** OpenShell bounds concurrent middleware work and buffered memory, but does not throttle fast calls. A middleware that is slow, overloaded, or unavailable is handled by admission backpressure, its timeout, and `on_error`, so operators must still size, scale, and protect the service.
- **Trusting an unsandboxed service with raw content.** Middleware receives raw request payloads, and OpenShell does not sandbox it, verify its behavior, or prevent it from mishandling or exfiltrating what it inspects. A buggy or malicious middleware is a direct data-exposure path. Trust in the middleware is the operator's responsibility, the same as trust in a sandbox image, but the blast radius here is in-flight request content.
- **A false sense of coverage.** The hook runs only on traffic OpenShell terminates and parses. Opaque TCP or TLS passthrough, encrypted or otherwise opaque bodies, endpoints outside every selector, and content the middleware fails to detect can still leave without effective inspection. Policy validation rejects selector overlap with `tls: skip`, and runtime uninspectability follows the matching chain's failure policy, but detection correctness and traffic outside the selected host set remain inherent limitations.
- **Phase 1 plaintext is risky.** The research-preview exception permits plaintext gRPC only with explicit `allow_insecure_transport = true`. Because middleware can allow, deny, or transform egress, an impersonated or eavesdropped service is a policy-enforcement bypass, not just an observability gap. The exception is unsuitable for shared or untrusted networks, produces an explicit warning and audit event, and is removed in phase 2.
- **Added surface to build, version, and maintain.** A new gRPC contract, policy schema, gateway configuration table, and manifest handshake are all long-lived surfaces with compatibility obligations, and middleware chains add ordering semantics operators must reason about. The research-preview framing keeps the contract provisional for now, but the long-term maintenance cost is real and is the main argument for keeping v1 deliberately small.

The cost of *not* doing this is leaving content-level egress control entirely outside OpenShell: operators who need to redact, block, or annotate outbound content based on what it contains would have to build bespoke proxies around the sandbox, losing the policy integration, audit, and trust boundary the supervisor already provides.

## Alternatives

- **Build content checks into OpenShell directly.** A fixed, built-in set of DLP/redaction rules avoids a contract and an external service. Rejected as the primary model: OpenShell cannot embed every useful detection and transformation approach, and a stable contract lets dedicated tools and research scanners iterate without changing OpenShell. First-party built-in middleware still ships for narrow cases, over the same contract.
- **REST instead of gRPC.** A REST/JSON hook is simpler to call, and with OpenAPI it could still offer a manifest handshake and a typed contract. Rejected because gRPC's typing and bidirectional streaming support match the lifecycle, and OpenShell already uses gRPC across its service contracts. Staying on a single toolchain avoids a second RPC stack to build, secure, and maintain.
- **Other deployment modes (WASM, sidecar, in-sandbox).** In-process WASM filters or sidecars avoid a network hop and can tighten the trust boundary. Deferred rather than rejected: v1 supports native built-ins and statically registered external services, while other shapes remain open. See [appendices/deployment-options.md](appendices/deployment-options.md).
- **Doing nothing.** The cost of declining is covered at the end of Risks: content-level egress control stays outside OpenShell, and operators must build bespoke proxies that lose the policy integration, audit, and trust boundary the supervisor already provides.

## Prior art

Calling an external service from a proxy to inspect, transform, or block in-flight traffic is well-established. The closest analogs:

- **Envoy `ext_proc` (External Processing).** The primary model for this RFC. Envoy streams request headers and body to an external gRPC service that can mutate the body (for example redaction), allow, or deny, and the proxy and the processing service scale independently. `HTTP_REQUEST/PRE_CREDENTIALS` follows the same event-oriented boundary while defining explicit BUFFERED and independent STREAM semantics.
- **Envoy `ext_authz` (External Authorization).** A narrower sibling: an external service returns an allow/deny decision per request. It validates the "delegate the per-request decision to an external service in the hot path" pattern, without the content-transformation half that this RFC needs.
- **ICAP (RFC 3507).** HTTP proxies offload content adaptation, virus scanning, DLP, and content filtering to external ICAP servers that can modify or block request/response content. It is the closest *functional* precedent for content-aware egress control. ICAP's pipelining and preview concepts map to our ordered chain and preflight. We avoid its dated text protocol; gRPC provides typed event streams and explicit ownership accounting.
- **HashiCorp `go-plugin` (Terraform, Vault).** Third-party plugins run as separate processes and communicate with the core exclusively over gRPC. It shows a strictly typed gRPC contract is a robust way to manage cross-language third-party extensions, which informs our registration plus manifest handshake (`Describe`, `ValidateConfig`).
- **Kubernetes CSI / KMS.** Vendor-specific integrations are offloaded to external gRPC services rather than compiled into the core. Same "core defines the contract; integrators implement it out-of-process" split we use for middleware.
- **Proxy-Wasm (Envoy/Istio Wasm filters).** In-process WebAssembly extensions with strong default-deny sandboxing and no IPC latency. Relevant to the future WASM deployment mode (see the deployment-options appendix); set aside for v1 because it is currently weak for GPU-backed or memory-heavy semantic guards.

## Decisions and explicit deferrals

This section closes the current review themes.

### Decisions

> **Update in PR #2477 - WebSocket middleware:** The operation-scope and failure-behavior decisions below now include WebSocket bindings, client text messages, binary pass-through, and capability coverage.

- **Middleware naming.** Use the feature name "supervisor middleware." The first operation family is egress middleware, but the higher-level feature name stays extensible for future supervisor hooks. The service can inspect, transform, deny, and annotate, so narrower names such as "transformer" or "request processor" describe only part of the contract.
- **Middleware names.** Policy selects built-ins or operator-owned external registrations through the `middleware` field. The service manifest name is diagnostic. Names use `/` for namespaces, `openshell/` is reserved for built-ins, and empty path segments are invalid.
- **Operation naming.** Use typed operation and phase enums such as `HTTP_REQUEST/PRE_CREDENTIALS`. The operation describes the middleware API payload, and the phase describes the proxy position. Later protocols can add typed operations such as WebSocket message or TCP connect without renaming the v1 hook.
- **Operation scope of v1.** `HTTP_REQUEST/PRE_CREDENTIALS` applies to every HTTP/1.x request that OpenShell terminates and parses, whether or not the endpoint declares a `protocol`; WebSocket upgrade requests are included. `WEBSOCKET_MESSAGE/PRE_CREDENTIALS` applies only to complete client-to-upstream text messages for attachments whose manifest advertises it. Binary and return-path messages, HTTP/2, HTTP/3, opaque TCP, and `tls: skip` traffic are excluded from those operation bindings.
- **Route selection and forwarding.** V1 has no `forward_to` decision. Middleware never makes the upstream call. Future route-selection hooks may choose among OpenShell-managed destinations, such as model routes, but must not become arbitrary external endpoint rewrites.
- **SigV4/request signing.** Endpoint policy continues to configure the existing proxy-side SigV4 implementation. A stacked follow-up can move it behind a trusted built-in contract without exposing resolved credentials to external middleware.
- **Composability and ordering.** Middleware is chainable and ordered by ascending numeric `order`. Order values must be unique across the policy. A stage receives the previous stage's transformed body and header mutations; `deny` short-circuits the chain; and different config map keys may invoke the same binding as separate stages.
- **Header mutation.** Headers preserve duplicates and wire order. External writes and removes may target middleware-visible end-to-end headers and writes support append, overwrite, or skip. Credential-bearing, routing, framing, hop-by-hop, `Connection`-nominated, and OpenShell credential headers remain protected. Each stage's mutations are atomic.
- **Finding shape.** Findings never include matched values or raw content. Built-ins may provide contract-defined audit-safe labels. Operator-run text and metadata are untrusted and are replaced or omitted in security outputs in favor of validated implementation names, platform labels, and aggregate counts.
- **Actor data.** Actor process data is optional and per-connection. Middleware must treat it as context, not a reliable per-request identity or authorization input.
- **Metadata namespacing.** Metadata is stored under the policy-local middleware config map key rather than the optional human-readable name. This prevents collisions without a central key registry and lets two configs using the same implementation emit independent metadata.
- **Selector-only placement.** V1 uses only config-level `endpoints.include` and `endpoints.exclude` selectors. Policy-level and endpoint-level attachment lists are not part of the schema. Selection is independent of the network rule that admitted the request and therefore remains stable after effective-policy composition.
- **Failure behavior.** HTTP middleware errors, timeouts, malformed responses, and over-cap inspectable payloads fail closed. WebSocket-only stages use `on_error`; `fail_closed` is the default. An absent operation binding and binary WebSocket messages are capability coverage states, not failures, and pass with informational telemetry under both WebSocket error modes.
- **Limits.** V1 caps policies at 10 middleware configs, selectors at 32 combined patterns per config, complete buffered bodies and advertised units at 4 MiB, request stream units at 64 KiB, findings at 32 per stage, and all non-body fields at the public envelope limits in the contract section. STREAM queues are bounded independently.
- **Delivery and reload.** `GetSandboxConfig` delivers only external registrations required by the effective policy. Built-ins are installed locally. Supervisors prepare candidate policy and registry state off-path, swap them as one generation, reuse connections for policy-only changes, and preserve the complete last-known-good runtime on failure.
- **Chunked and compressed bodies.** V1 normalizes fixed and chunked HTTP/1 request bodies into bounded units and preserves validated trailers. BUFFERED remains bounded by the stage limit. STREAM middleware may own larger finite working state subject to advertised limits. Compressed bodies remain opaque unless a binding explicitly supports them.
- **Post-transformation enforcement.** Every body replacement is re-evaluated by body-aware GraphQL, JSON-RPC, or MCP policy before the next stage or upstream. An enforced denial blocks. In audit mode, a denial is logged, the remaining chain stops, and the transformed request is forwarded. Evaluation failure or an unparseable replacement is a hard denial. Middleware deny and `fail_closed` remain blocking regardless of endpoint audit mode.
- **Trust boundary and phases.** Stable external middleware transport requires confidentiality and service authentication. Phase 1 may temporarily allow plaintext only with explicit `allow_insecure_transport = true`, a warning, and an audit event in trusted local or isolated research environments. Phase 2 removes plaintext and `allow_insecure_transport` as an intentional research-preview breaking change.
- **Multitenancy.** OpenShell controls middleware application through policy selection. A middleware may receive sandbox and policy context for audit, but OpenShell does not define a middleware-owned tenant grouping model in v1.
- **API maturity qualifier.** Use `openshell.middleware.v1`, not `v1alpha1`. The project is already alpha-stage; the RFC labels this contract as a research preview, so an additional per-contract alpha package adds little.

### Explicit deferrals

- **Provider-profile middleware.** V1 middleware configs live in sandbox policy, not provider profiles. Provider-supplied network policies can be targeted after effective policy assembly. Provider-profile opt-ins and reusable cross-sandbox middleware profiles are follow-up design work.
- **Authenticated transport mechanism.** Phase 2 requires authenticated encrypted transport. The exact choice between mTLS, TLS plus caller authentication, or an equivalent mechanism, including credential delivery and rotation, is follow-up protocol work.
- **Health checks.** V1 relies on connection establishment, `Describe`, per-request invocation, timeout, `on_error`, and registry polling. A dedicated health RPC can improve alerting later but is not required for correctness.
- **Registration ergonomics and ownership.** V1 middleware registration is an operator concern: middleware services are declared in gateway configuration and changing the registered set requires a gateway restart. Runtime user-managed registration, CLI/API helpers, SDK helpers, and an agent skill for scaffolding or registering middleware are useful follow-ups after the policy and service contract stabilize.
- **Post-call budget reconciliation.** Budget-style middleware that needs final route/model, status, content length, or token usage needs a metadata-only hook such as `HttpResponse/completed`. That hook is listed as a future extension and is not part of the v1 request hook.
- **Deployment modes and timelines.** V1 commits to externally managed services plus in-process built-ins. WASM, sidecar, OpenShell-managed image, and in-sandbox middleware have no committed timeline in this RFC.
