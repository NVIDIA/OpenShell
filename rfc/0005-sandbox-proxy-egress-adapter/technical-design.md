# Technical Design Appendix

This appendix carries implementation-level design details behind the main RFC.

## Existing Runtime Boundary

`openshell-supervisor-network::run::run_networking` is the current networking
startup boundary. It builds policy-local context, waits for policy binary
symlink resolution, creates the identity cache, writes the TLS CA, builds TLS
state, resolves inference routes, wires provider credentials and token grants,
and starts the proxy.

This is a useful outer boundary, but it is not yet the proxy adapter boundary.
The proxy still needs internal `EgressIntent` and `EgressDecision` boundaries
so CONNECT, forward HTTP, local routes, and future native TCP capture do not
duplicate policy and relay orchestration.

## Shared Data Boundaries

### EgressIntent

`EgressIntent` is the normalized description of what userland is trying to do.

It should carry:

- entry transport: CONNECT, forward HTTP, transparent TCP, local HTTP, policy
  DNS, or metadata loopback;
- requested destination host/port or captured original IP/port;
- process identity inputs collected by the adapter/runtime;
- optional first HTTP request for forward proxy traffic;
- optional local service route;
- policy generation or DNS mapping generation when relevant.

Adapters build intents. They should not query endpoint metadata, select TLS
mode, or select relays.

### EgressDecision

`EgressDecision` is the policy result consumed by validation and relay code.

It should carry:

- allow or deny;
- deterministic matched policy identifier;
- whether the policy is user-authored, provider-derived, or local-service
  internal;
- deterministic matched endpoint identifier and endpoint metadata;
- process identity used for evaluation;
- destination and allowed IP constraints;
- TLS behavior;
- protocol enforcement;
- credential injection plan;
- logging context and denial reason.

Relay code should read this decision. It should not query OPA again for
endpoint metadata, TLS mode, allowed IPs, credential behavior, or parser
selection.

## Protocol Enforcement

Use a protocol enforcement value derived from endpoint policy:

| Policy protocol | Enforcement | Relay behavior |
|-----------------|-------------|----------------|
| omitted / `tcp` | None | L4 authorization plus byte relay, with optional HTTP sniff for credential injection |
| `rest` | HTTP | HTTP request parser with REST rules, plus opt-in request-body and WebSocket text-frame credential rewrite |
| `graphql` | HTTP | HTTP request parser with GraphQL-over-HTTP rules |
| `websocket` | HTTP | HTTP upgrade policy followed by WebSocket frame policy or GraphQL-over-WebSocket policy |
| future `redis`, `postgres`, `mysql`, ... | TCP application | Protocol-specific TCP parser owns the message loop |

`protocol: tcp` is effectively the default L4 mode. It should not run TCP
application parsers. Avoid using the term "provider" for parser concepts
because providers are already a first-class credential and routing domain in
OpenShell.

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
    process: ProcessIdentity,
    first_request: Option<ParsedHttpRequest>,
    local_route: Option<LocalRoute>,
    generation: Option<PolicyGeneration>,
}

struct EgressDecision {
    outcome: PolicyOutcome,
    matched_policy: Option<MatchedPolicy>,
    endpoint: Option<MatchedEndpoint>,
    log_context: EgressLogContext,
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
    allowed_ips: AllowedIpPolicy,
    tls: TlsPolicy,
    enforcement: ProtocolEnforcement,
    credentials: CredentialInjectionPlan,
}

enum ProtocolEnforcement {
    None,
    Http(HttpL7Config),
    TcpApplication(TcpApplicationConfig),
}

enum HttpL7Protocol {
    Rest,
    Graphql,
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

struct RelayContext {
    decision: EgressDecision,
    connector: UpstreamConnector,
    deadlines: RelayDeadlines,
    telemetry: RelayTelemetry,
}
```

`UpstreamConnector` is the relay-owned dial boundary. It encapsulates the
validated destination and lets relays/parsers open an upstream connection only
after protocol policy allows it.

## Current Owners And Proposed Cleanup

| Current owner | Current responsibility | Proposed cleanup |
|---------------|------------------------|------------------|
| `openshell-sandbox` | Orchestrator, policy poll loop, denial/activity channels, metadata loopback startup, network-only lifecycle | Keep as orchestration; avoid embedding per-entry proxy policy decisions |
| `openshell-supervisor-network::run` | Networking startup and handles | Become the stable runtime API for embedded and future standalone modes |
| `openshell-supervisor-network::proxy` | CONNECT, forward HTTP, local route dispatch, destination validation, denial rendering | Split into adapters, authorization, destination, relay selection, and adapter response rendering |
| `openshell-supervisor-network::opa` | Policy engine and Rego queries | Return deterministic `EgressDecision` data instead of separate policy and endpoint lookups |
| `openshell-supervisor-network::l7` | REST, GraphQL, WebSocket, inference helpers, TLS, token grants | Keep as protocol/relay implementation behind shared relay boundaries |
| `openshell-supervisor-network::policy_local` | `policy.local` state and routes | Model as a local adapter with explicit limits and proposal/wait behavior |
| `openshell-supervisor-process::netns` | nftables bypass rules and namespace helpers | Remain owner of bypass enforcement; coordinate future capture rules with network proxy mappings |
| `openshell-supervisor-process::bypass_monitor` | nftables LOG parsing and OCSF bypass telemetry | Remain telemetry producer for bypass violations |
| `openshell-core::secrets` and provider credential state | Static placeholder sources and dynamic credential metadata | Feed credential injection plans; do not leak secrets into decision logs |

## Policy DNS And Resolved TCP State

Policy DNS should be query-driven rather than a static `/etc/hosts` snapshot.

1. Policy load registers eligible native TCP endpoint names.
2. Userland performs DNS lookup.
3. Policy DNS checks whether the name is registered for native TCP.
4. Policy DNS resolves through trusted upstream DNS.
5. Answers are filtered against endpoint metadata and SSRF controls.
6. The adapter publishes the DNS answer, endpoint generation, and capture rule.
7. Userland later calls `connect(ip:port)`.
8. Transparent TCP recovers the original destination and maps it to the active
   endpoint generation.
9. Normal egress authorization and relay selection run.

The resolved endpoint store is therefore not a preemptive global DNS snapshot.
It is active state produced by policy-eligible lookups and consumed by
transparent TCP connects.

## nftables Boundary

Current main uses nftables, not iptables, for sandbox network bypass
enforcement. The installed `inet` table accepts traffic to the sandbox proxy,
loopback, and established/related flows, then rejects and optionally logs other
TCP/UDP traffic. The bypass monitor reads those log lines and emits OCSF
network and detection events.

Transparent TCP capture should build on this same nftables substrate:

- capture rules must run before the generic bypass reject rules;
- capture rules should be scoped to active policy DNS IP/port mappings;
- capture state should be updated atomically with endpoint generation changes;
- reject/log rules remain the fallback for unmatched TCP/UDP egress;
- VM or Podman driver nftables rules are infrastructure NAT/isolation and
  should not be treated as the proxy policy enforcement point.

## Endpoint Selection And OPA

OPA/Rego should return policy and endpoint metadata through one deterministic
authorization result. It should not let policy name and endpoint config be
selected by different precedence rules.

Two acceptable approaches:

- Reject overlapping endpoint metadata at load or merge time.
- Define a single deterministic precedence key and use it for both policy name
  and endpoint metadata.

Endpoint metadata query failures should fail closed when metadata is required
for the selected endpoint. They should not silently downgrade to L4 behavior.

Provider-derived policies use a reserved rule-name namespace. The gateway and
sandbox sync should prevent user-authored `_provider_*` rules, and
`policy.local` proposal surfaces should not expose provider-derived rules as
editable user policy. `EgressDecision` should still identify provider-derived
matches for logging and debugging.

## Credential Injection Boundary

Credential injection belongs in the HTTP/WebSocket relay after policy allow and
before upstream write.

1. Authorization selects the endpoint and computes a credential injection plan.
2. The HTTP relay resolves credentials only when it has an allowed request.
3. Static placeholder values are resolved and redacted from logs.
4. Endpoint-bound token grants obtain or reuse a dynamic access token.
5. The final upstream request or WebSocket frame is rewritten immediately
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

## Parser Boundary

Protocol parsers operate on streams owned by the relay.

- HTTP parsing converts bytes into request metadata, evaluates request policy,
  and loops for keep-alive or pipelined requests.
- WebSocket parsing starts only after an allowed HTTP upgrade. It validates the
  handshake/frame stream and owns client-to-server text-frame inspection when
  credential rewrite, transport message policy, GraphQL-over-WebSocket policy,
  or compression handling is configured.
- TCP application parsers read client and upstream streams as needed and own
  their message loop.
- A TCP parser can deny before dialing, dial for a server handshake, or keep
  evaluating commands/queries throughout the session.

This avoids a separate dial strategy enum. The parser knows which protocol
milestone is sufficient to call the validated connector.

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
| TCP parser | Protocol message timeouts and parser-specific limits |
| Local service adapter | Local route body limits, response caps, gateway call timeout |
| Token grant resolver | SPIFFE Workload API timeout, token endpoint timeout, cache TTL |

Timeouts should be recorded in telemetry at the owner boundary that can explain
the failure.
