# Technical Design Appendix

This appendix carries implementation-level design details behind the main RFC.

## Existing Runtime Boundary

`openshell-supervisor-network::run::run_networking` is the current networking
startup boundary. It builds policy-local context, waits for policy binary
symlink resolution, creates the identity cache, writes the TLS CA, builds TLS
state, resolves inference routes, wires provider credentials and token grants,
and starts the proxy. The supervisor middleware work extends this boundary with
middleware registry construction and reload behavior.

This is a useful outer boundary, but it is not yet the proxy adapter boundary.
The proxy still needs internal `EgressIntent` and `EgressDecision` boundaries
so CONNECT, forward HTTP, local routes, and future native TCP capture do not
duplicate policy and relay orchestration. The first implementation milestone
wires only current surfaces; later milestones add new adapters to the same
contract.

## Shared Data Boundaries

### EgressIntent

`EgressIntent` is the normalized description of what userland is trying to do.

It should carry:

- entry transport: CONNECT, forward HTTP, transparent TCP, local HTTP, policy
  DNS, or metadata loopback;
- requested destination host/port or captured original IP/port;
- optional process identity inputs collected by the adapter/runtime;
- optional first HTTP request for forward proxy traffic;
- optional local service route;
- policy generation and, for policy DNS/transparent TCP, a distinct DNS
  mapping generation and correlation handle.

Adapters build intents. They should not query endpoint metadata, select TLS
mode, or select relays.

### EgressDecision

`EgressDecision` is the policy result consumed by validation and relay code.

It should carry:

- allow or deny;
- one top-level policy generation used for every policy-derived field;
- deterministic matched policy identifier;
- whether the policy is user-authored, provider-derived, or local-service
  internal;
- deterministic matched endpoint identifier and endpoint metadata;
- process identity availability and any identity fields used for evaluation;
- destination and allowed IP constraints;
- TLS behavior;
- protocol enforcement;
- credential injection plan;
- supervisor middleware plan;
- the request-policy selection needed to create a pinned per-request L7
  evaluator when HTTP inspection is configured;
- logging context and denial reason.

Relay code should read this decision. It should not query OPA again for
endpoint metadata, TLS mode, allowed IPs, credential behavior, middleware
selection, or relay selection. Long-lived HTTP relays still evaluate each
request through the generation-pinned L7 evaluator carried in `RelayContext`;
that is request authorization, not endpoint rematerialization. Later native
protocol processors use the same pattern with a generation-pinned protocol
evaluator for per-command or per-query decisions.

## Protocol Enforcement

Use a protocol enforcement value derived from endpoint policy:

| Policy protocol | Enforcement | Relay behavior |
|-----------------|-------------|----------------|
| omitted / `tcp` | None | L4 authorization plus byte relay, with optional HTTP sniff for credential injection |
| `rest` | HTTP | HTTP request parser with REST rules, plus opt-in request-body and WebSocket text-frame credential rewrite |
| `graphql` | HTTP | HTTP request parser with GraphQL-over-HTTP rules |
| `json-rpc` | HTTP | HTTP request parser plus bounded JSON-RPC-over-HTTP method inspection |
| `mcp` | HTTP | HTTP request parser plus bounded MCP Streamable HTTP method/tool inspection |
| `websocket` | HTTP | HTTP upgrade policy followed by WebSocket frame policy or GraphQL-over-WebSocket policy |
| future `redis`, `postgres`, `mysql`, ... | Protocol processor | Protocol-specific processor owns framing, middleware hooks, and the message loop |

`protocol: tcp` is effectively the default L4 mode. It should not run native
protocol processors. Avoid using the term "provider" for processor concepts
because providers are already a first-class credential and routing domain in
OpenShell. Concrete native processors land after the shared dispatch contract.

## Suggested Types

The exact Rust shape can evolve, but the boundaries should look like this:

```rust
enum EgressTransport {
    Connect,
    ForwardHttp,
    TransparentTcp,
    PolicyDns,
    LocalHttp,
    MetadataLoopback,
}

struct EgressIntent {
    transport: EgressTransport,
    destination: RequestedDestination,
    process: ProcessIdentityEvidence,
    first_request: Option<ParsedHttpRequest>,
    local_route: Option<LocalRoute>,
    correlation: Option<ResolvedEndpointCorrelation>,
}

struct EgressDecision {
    policy_generation: PolicyGeneration,
    outcome: PolicyOutcome,
    matched_policy: Option<MatchedPolicy>,
    endpoint: Option<MatchedEndpoint>,
    process: EvaluatedProcessIdentity,
    request_processing: RequestProcessingPlan,
    log_context: EgressLogContext,
}

enum ProcessIdentityEvidence {
    Available(ProcessIdentity),
    Unavailable(ProcessIdentityUnavailableReason),
}

enum ProcessIdentityUnavailableReason {
    EndpointOnlyMode,
    DeclaredRuntimeMode(RuntimeMode),
    UnsupportedPlatform,
    LookupFailed,
}

struct EvaluatedProcessIdentity {
    evidence: ProcessIdentityEvidence,
    fields_used: Vec<ProcessIdentityField>,
}

struct MatchedPolicy {
    id: PolicyId,
    source: PolicySource,
}

enum PolicySource {
    User,
    ProviderDerived,
    LocalService,
}

struct MatchedEndpoint {
    id: EndpointId,
    destination: DestinationValidationPlan,
    tls: TlsPolicy,
    enforcement: ProtocolEnforcement,
}

struct DestinationValidationPlan {
    address_authorization: AddressAuthorization,
}

enum AddressAuthorization {
    DefaultPublicOnly,
    ExplicitAllowedIps(Vec<IpNet>),
    ExactDeclaredHost,
    ImplicitIpLiteral(IpAddr),
    TrustedGatewayAlias { expected_ip: IpAddr },
}

struct RequestProcessingPlan {
    middleware: SupervisorMiddlewarePlan,
    credentials: CredentialInjectionPlan,
}

enum ProtocolEnforcement {
    None,
    Http(HttpL7Config),
    ProtocolProcessor(ProtocolProcessorConfig),
}

enum HttpL7Protocol {
    Rest,
    Graphql,
    JsonRpc,
    Mcp,
    Websocket,
}

struct HttpL7Config {
    protocol: HttpL7Protocol,
    path: EndpointPathScope,
    allow_encoded_slash: bool,
    enforcement_mode: L7EnforcementMode,
    websocket_credential_rewrite: bool,
    request_body_credential_rewrite: bool,
    websocket_graphql_policy: bool,
    graphql_max_body_bytes: usize,
    json_rpc_max_body_bytes: usize,
    mcp_strict_tool_names: bool,
}

struct CredentialInjectionPlan {
    static_placeholders: StaticPlaceholderPlan,
    token_grant: Option<TokenGrantPlan>,
}

struct StaticPlaceholderPlan {
    http_target_query_header: bool,
    rest_request_body: bool,
    websocket_text_frames: bool,
}

struct TokenGrantPlan {
    provider_key: String,
    auth_style: TokenGrantAuthStyle,
    token_endpoint: String,
}

struct SupervisorMiddlewarePlan {
    stages: Vec<SupervisorMiddlewareStage>,
    min_body_limit: Option<usize>,
    registry_generation: PolicyGeneration,
}

struct SupervisorMiddlewareStage {
    policy_name: String,
    binding_id: String,
    operation: MiddlewareOperation,
    phase: MiddlewarePhase,
    order: i32,
    on_error: MiddlewareOnError,
    config: MiddlewareConfig,
}

enum MiddlewareOperation {
    HttpRequest,
    Future(String),
}

enum MiddlewarePhase {
    PreCredentials,
    Future(String),
}

struct RelayContext {
    decision: EgressDecision,
    request_policy: Option<PinnedRequestPolicy>,
    protocol_policy: Option<PinnedProtocolPolicy>,
    connector: UpstreamConnector,
    deadlines: RelayDeadlines,
    telemetry: RelayTelemetry,
}

struct ResolvedEndpointCorrelation {
    policy_generation: PolicyGeneration,
    mapping_generation: DnsMappingGeneration,
    mapping_id: DnsMappingId,
    synthetic_ip: IpAddr,
}

struct PinnedRequestPolicy {
    generation: PolicyGeneration,
    evaluator: TunnelPolicyEngine,
}

struct PinnedProtocolPolicy {
    generation: PolicyGeneration,
    evaluator: ProtocolPolicyEngine,
}
```

`UpstreamConnector` is the relay-owned dial boundary. It encapsulates the
validated destination and lets relays or processors open an upstream connection
only after current request or protocol policy allows it.

`DestinationValidationPlan` selects one current validation mode. All modes
retain control-plane-port and cloud-metadata blocks. Default and explicit IP
paths retain the always-blocked loopback, link-local, and unspecified-address
checks. `ImplicitIpLiteral` is synthesized only for an explicitly declared IP
host. `TrustedGatewayAlias` may accept the one runtime-discovered gateway IP but
does not become a general private-address exemption.

`policy_generation`, the optional pinned request/protocol evaluators, endpoint
metadata, and middleware selection must describe one policy snapshot.
Authorization asserts that every sub-materialization used that generation. If
the generation changes before relay startup, the adapter receives a
stale-policy denial rather than a mixed decision.

## Process Identity Availability

Process identity is evidence, not a string to fabricate when lookup fails.
Embedded mode normally populates binary, PID, ancestry, command-line path, and
binary hash data. When binary identity is required, `LookupFailed` and
`UnsupportedPlatform` remain denials. An explicitly configured endpoint-only
runtime records `Unavailable(EndpointOnlyMode)` and keeps the current
endpoint-only policy behavior. This RFC does not silently turn one state into
the other or change the endpoint-only trust contract.

A future standalone or sidecar runtime that intentionally lacks local identity
uses `DeclaredRuntimeMode`, not `EndpointOnlyMode`, and advertises that
capability to policy validation. The runtime contract must define binary/path
predicates as unavailable and reject incompatible policy before traffic starts,
unless a later accepted policy design specifies a different fail-closed rule.

The decision records identity availability and fields used so OCSF logs and
deny responses distinguish a binary policy denial, an identity lookup failure,
and intentional endpoint-only evaluation. Tests must prove an empty synthetic
`exec.path` cannot satisfy a binary-scoped rule while identity is required.
Adding new identity-less deployment modes, or changing how binary predicates
behave in endpoint-only mode, requires the capability work in the later runtime
phase and cannot be smuggled into the compatibility refactor.

## Current Owners And Proposed Cleanup

| Current owner | Current responsibility | Proposed cleanup |
|---------------|------------------------|------------------|
| `openshell-sandbox` | Orchestrator, policy poll loop, denial/activity channels, metadata loopback startup, network-only lifecycle | Keep as orchestration; avoid embedding per-entry proxy policy decisions |
| `openshell-supervisor-network::run` | Networking startup and handles | Become the stable runtime API for embedded and future standalone modes |
| `openshell-supervisor-network::proxy` | CONNECT, forward HTTP, local route dispatch, destination validation, denial rendering | Split into adapters, authorization, destination, relay selection, and adapter response rendering |
| `openshell-supervisor-network::opa` | Policy engine and Rego queries | Return deterministic `EgressDecision` data instead of separate policy and endpoint lookups |
| `openshell-supervisor-network::l7` | REST, GraphQL, JSON-RPC, MCP, WebSocket, inference helpers, TLS, token grants | Keep as protocol/relay implementation behind shared relay boundaries |
| `openshell-supervisor-network::policy_local` | `policy.local` state and routes | Model as a local adapter with explicit limits and proposal/wait behavior |
| `openshell-supervisor-middleware` | Middleware registry, built-ins, service contract, and chain execution | Treat as a relay hook dependency selected by `EgressDecision`, not as adapter-specific policy logic |
| `openshell-supervisor-process::netns` | nftables bypass rules and namespace helpers | Remain owner of bypass enforcement; coordinate future capture rules with network proxy mappings |
| `openshell-supervisor-process::bypass_monitor` | nftables LOG parsing and OCSF bypass telemetry | Remain telemetry producer for bypass violations |
| `openshell-core::secrets` and provider credential state | Static placeholder sources and dynamic credential metadata | Feed credential injection plans; do not leak secrets into decision logs |

## Policy DNS And Resolved TCP State

Policy DNS is query-driven rather than a static `/etc/hosts` snapshot.

1. Policy load registers eligible native TCP endpoint names.
2. Userland performs a DNS lookup.
3. Policy DNS checks whether the normalized name matches an endpoint whose
   transport and protocol contract enables native TCP through policy DNS in the
   current policy generation.
4. An ineligible name receives a local policy-denial DNS response without an
   upstream query.
5. Policy DNS resolves an eligible name through trusted upstream DNS and
   filters every answer through endpoint metadata and SSRF controls.
6. The adapter allocates a supervisor-owned synthetic IP and creates an active
   mapping containing the synthetic IP, normalized name, endpoint identifier,
   allowed ports, validated real addresses, policy generation, distinct DNS
   mapping generation, opaque mapping ID, and expiration.
7. The adapter publishes the mapping and capture state atomically before
   returning the synthetic IP to userland with a bounded TTL.
8. Userland later calls `connect(synthetic_ip:port)`.
9. Transparent TCP recovers the synthetic original destination and requires an
   unexpired exact mapping whose allowed ports contain the requested port.
10. Normal egress authorization and relay selection run against a policy
    generation consistent with the mapping contract.
11. The connector dials only a real address pinned in that mapping. It does not
    re-resolve the name independently at connect time.

The resolved endpoint store is active state produced by policy-eligible lookups
and consumed by transparent TCP connects. Policy generation and DNS mapping
generation are separate values: a DNS refresh can replace mappings without a
policy reload, while a policy reload can invalidate mappings whose endpoint
contract is no longer current. A captured connection with no mapping, a stale
mapping, or a mismatched endpoint/port fails closed. An unrelated bare-IP
connection cannot inherit a policy-DNS authorization merely because it targets
a real IP present in the mapping store. Synthetic IPs are correlation handles,
not upstream destinations, and must never be routed directly or reassigned
while a stale answer could still refer to the prior mapping.

The mapping is sandbox-scoped rather than process-scoped. Process identity is
looked up and evaluated independently when the captured TCP connection is
authorized. It is not used to join DNS and TCP because name resolution may be
cached, delegated to a resolver helper, or consumed by a different process, and
multiple names resolved by one process may share a real address and port.

## nftables Boundary

Current main uses nftables, not iptables, for sandbox network bypass
enforcement. The installed `inet` table accepts traffic to the sandbox proxy,
loopback, and established/related flows, then rejects and optionally logs other
TCP/UDP traffic. The bypass monitor reads those log lines and emits OCSF
network and detection events.

Transparent TCP capture builds on this same nftables substrate in a later
feature phase:

- capture rules run before the generic bypass reject rules;
- capture rules are scoped to active synthetic-IP and allowed-port mappings;
- mapping and capture-rule updates are atomic from the adapter's perspective;
- direct external DNS remains blocked; policy DNS is the sandbox resolver, and
  DNS-over-HTTPS remains ordinary policy-controlled HTTPS egress;
- reject/log rules remain the fallback for unmatched TCP/UDP egress;
- VM or Podman driver nftables rules are infrastructure NAT/isolation and are
  not the proxy policy enforcement point.

The initial CONNECT/forward refactor does not change the installed table. This
section defines the consumer contract that the shared adapter and decision
boundaries must support when transparent capture lands.

## Endpoint Selection And OPA

Today the matched policy name, L7 candidates, first TLS/`allowed_ips` endpoint,
and exact-declared-host signal are selected through independent rules. OPA/Rego
should return policy and endpoint metadata through one deterministic
authorization result. It should not let those fields describe different
matches.

Two acceptable approaches:

- Reject overlapping endpoint metadata at load or merge time.
- Define a single deterministic precedence key and use it for both policy name
  and endpoint metadata.

Endpoint metadata query failures should fail closed when metadata is required
for the selected endpoint. They should not silently downgrade to L4 behavior.
The top-level decision generation must also match every policy-derived field;
reload during materialization yields a stale decision instead of mixing
generations.

This semantic cutover is separate from introducing the Rust types. The new
query first runs in shadow mode beside the legacy queries, records audit-safe
mismatches through internal telemetry, and preserves legacy enforcement. After
the precedence rule is accepted and mismatch cases are understood, a dedicated
change switches the authoritative result and retains the legacy evaluator long
enough for immediate rollback.

Provider-derived policies use a reserved rule-name namespace. The gateway and
sandbox sync should prevent user-authored `_provider_*` rules, and
`policy.local` proposal surfaces should not expose provider-derived rules as
editable user policy. `EgressDecision` should still identify provider-derived
matches for logging and debugging.

## Credential Injection Boundary

Credential injection belongs in the HTTP/WebSocket relay after policy allow and
supervisor middleware, and before upstream write.

1. Authorization selects the endpoint and computes a credential injection plan.
2. Supervisor middleware runs on the admitted request before credentials are
   visible.
3. If middleware replaces the body, the relay re-parses body-dependent
   protocol inputs and re-evaluates request policy.
4. The HTTP relay resolves credentials only when it still has an allowed
   request under the endpoint's enforcement mode.
5. Static placeholder values are resolved and redacted from logs.
6. Endpoint-bound token grants obtain or reuse a dynamic access token.
7. The final upstream request or WebSocket frame is rewritten immediately
   before write.

Both L4-only HTTP and HTTP-inspected paths can inject credentials. The
difference is whether REST, GraphQL, or WebSocket policy is evaluated before
the rewrite.

Credential rewrite slots should be explicit:

- request target, query values, and headers for HTTP-family traffic;
- REST request bodies only when `request_body_credential_rewrite` is enabled;
- client-to-server WebSocket text frames only when
  `websocket_credential_rewrite` is enabled;
- GraphQL-over-WebSocket connection/control messages when they are carried in
  text frames and the endpoint enables the WebSocket rewrite path;
- token grant headers for endpoint-bound provider credentials.

Request-body rewrite is REST-only. It should buffer bounded UTF-8 textual
bodies, including JSON, form-url-encoded, and `text/*`, recompute
`Content-Length`, preserve unsupported bodies that contain no reserved
credential markers, and fail closed when a reserved placeholder cannot be
resolved safely. Binary WebSocket frames are not rewritten.

Token grants are dynamic credential injection. They use provider metadata to
request a SPIFFE JWT-SVID, exchange it for an OAuth2 access token, cache the
token, and inject either an `Authorization: Bearer` header or a configured
custom header. Token grant failures should return a local relay error and must
not forward the request upstream.

Middleware-transformed content should be treated as untrusted input from a
credential perspective. External middleware must not receive OpenShell-managed
credentials, and it should not be able to synthesize new reserved credential
placeholders that OpenShell later resolves into secrets. Unless a future hook
is explicitly built-in-only and credential-capable, the relay should fail
closed or strip newly introduced reserved placeholders before static
placeholder rewrite and token grant injection.

## Supervisor Middleware Boundary

Supervisor middleware is a typed relay hook, not a replacement for protocol
framing. The relay or protocol processor must first parse enough structure to
construct the operation-specific middleware input.

For v1, the operation is `HTTP_REQUEST / PRE_CREDENTIALS`:

1. Network policy, destination validation, and request policy admit the
   request.
2. The HTTP relay selects the middleware chain from the request processing
   plan.
3. The relay buffers the request body within the smallest selected stage limit.
4. The chain evaluates in deterministic order.
5. A deny short-circuits before credential injection or upstream write.
6. An allow can replace the request body, add approved headers, emit findings,
   and pass metadata forward.
7. When the body changes, the relay re-parses and re-evaluates body-dependent
   request policy inputs.
8. The transformed request enters credential injection and upstream write only
   after that re-evaluation admits it under the endpoint's enforcement mode.

The re-evaluation uses the original request method, path, and query because v1
middleware cannot mutate them. It re-derives the GraphQL operation, JSON-RPC
method, and MCP method or tool name from the transformed body. A policy mismatch
preserves the endpoint's audit or enforce behavior. A malformed or
unclassifiable transformed protocol body fails closed in both modes because the
relay can no longer prove which operation it would forward.

Middleware selection is independent from the matched endpoint policy. It is a
request processing plan selected by admitted destination host, order, and
binding metadata. The decision boundary should materialize it with the same
policy generation used for endpoint selection so a long-lived tunnel cannot mix
old endpoint policy with a new middleware registry.

V1 middleware can inspect WebSocket upgrade requests because those are HTTP
requests. It does not inspect post-upgrade WebSocket frames. A future frame
hook should be a separate operation such as `WEBSOCKET_MESSAGE /
BEFORE_FORWARD` owned by the WebSocket relay.

## Protocol Processor Boundary

Protocol processors operate on streams owned by the relay.

- HTTP parsing converts bytes into request metadata, evaluates request policy,
  runs the `HTTP_REQUEST / PRE_CREDENTIALS` middleware hook when configured,
  and loops for keep-alive or pipelined requests.
- JSON-RPC and MCP processing are HTTP L7 processors: they parse bounded
  JSON-RPC-over-HTTP request bodies after HTTP parsing and before upstream
  forwarding. Generic JSON-RPC policy matches methods; MCP policy can also
  match `tools/call` tool names.
- WebSocket parsing starts only after an allowed HTTP upgrade. It validates the
  handshake/frame stream and owns client-to-server text-frame inspection when
  credential rewrite, transport message policy, GraphQL-over-WebSocket policy,
  or compression handling is configured.
- Native TCP protocol processors read client and upstream streams as needed and
  own their message loop.
- A protocol processor can deny before dialing, dial for a server handshake, or
  keep evaluating commands or queries throughout the session.
- A protocol processor may be in-tree, middleware-backed, or a hybrid where
  in-tree framing exposes typed middleware operations for content evaluation.

HTTP and WebSocket relays receive the generation-pinned request evaluator
because request policy must continue throughout long-lived sessions. No
processor rematerializes endpoint, TLS, allowed-IP, credential, or middleware
selection. This avoids a separate dial-strategy enum: each processor knows
which protocol milestone is sufficient to call the validated connector.

## Local Service Adapter Boundary

Local services are network surfaces but not normal external egress:

- `inference.local` terminates local client traffic, validates known inference
  routes, strips caller auth, injects provider routing/auth, and applies
  streaming or buffered limits based on route type.
- `policy.local` serves policy snapshots, denial summaries, proposal
  submission, and proposal wait. It should never expose secrets or provider
  rules as editable policy.
- Metadata loopback serves provider metadata credentials for SDKs that bypass
  HTTP proxy variables. It should use the same provider credential state and
  redaction discipline as other credential paths.

These adapters may call gateway APIs or local credential helpers, but they
should not bypass policy and credential invariants that apply to external
egress.

Issue [#1633](https://github.com/NVIDIA/OpenShell/issues/1633) is a prospective
consumer of these boundaries, not a feature defined by this RFC. A
policy-declared host-local endpoint should use an explicit local-routing adapter
or destination mode; it must not become a general loopback exemption in the
external destination validator. Its feature design still needs to choose the
policy surface (reserved hostname versus endpoint flag), define authorization
before the supervisor connects to host loopback, and specify driver/runtime
capabilities. That work can reuse `EgressIntent`, adapter-specific responses,
and the unopened connector boundary without changing this RFC's compatibility
milestone.

## Timeout And Resource Ownership

| Owner | Resource |
|-------|----------|
| Adapter | Client-side parse timeout and adapter-specific deny response |
| Authorization | OPA deadline and policy evaluation telemetry |
| Destination validator | DNS timeout, allowed IP checks, SSRF checks, control-plane port checks |
| TLS terminator | Client TLS handshake timeout and certificate selection |
| HTTP relay | Per-request read/write deadlines, body caps, request-body rewrite caps, upstream reuse |
| WebSocket relay | Upgrade validation, frame limits, text-frame rewrite, compression limits, message policy |
| TCP relay | Byte-copy idle timeout and half-close handling |
| Protocol processor | Protocol message timeouts, middleware hook timeouts, and processor-specific limits |
| Local service adapter | Local route body limits, response caps, gateway call timeout |
| Token grant resolver | SPIFFE Workload API timeout, token endpoint timeout, cache TTL |
| Middleware runner | Service timeout, body cap, failure policy, registry generation |

Timeouts should be recorded in telemetry at the owner boundary that can explain
the failure.
