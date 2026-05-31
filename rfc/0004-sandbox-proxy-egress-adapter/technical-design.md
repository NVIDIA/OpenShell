# Technical Design Appendix

This appendix carries the implementation-level design details behind the main
RFC.

## Shared Data Boundaries

### EgressIntent

`EgressIntent` is the normalized description of what userland is trying to do.

It should carry:

- entry transport: CONNECT, forward HTTP, transparent TCP, or local HTTP;
- requested destination host/port or captured original IP/port;
- process identity inputs collected by the adapter/runtime;
- optional first HTTP request for forward proxy traffic;
- optional local service route.

Adapters build intents. They should not query endpoint metadata or select
relays.

### EgressDecision

`EgressDecision` is the policy result consumed by validation and relay code.

It should carry:

- allow or deny;
- deterministic matched policy identifier;
- deterministic matched endpoint identifier and endpoint metadata;
- process identity used for evaluation;
- destination and allowed IP constraints;
- TLS behavior;
- protocol enforcement;
- logging context and denial reason.

Relay code should read this decision. It should not query OPA again for
endpoint metadata, TLS mode, allowed IPs, or parser selection.

## Protocol Enforcement

Use a protocol enforcement value derived from endpoint policy:

| Policy protocol | Enforcement | Relay behavior |
|-----------------|-------------|----------------|
| omitted / `tcp` | None | L4 authorization plus byte relay, with optional HTTP sniff for credential injection |
| `rest` | HTTP | HTTP request parser with REST rules, plus opt-in request-body and WebSocket text-frame credential rewrite |
| `graphql` | HTTP | HTTP request parser with GraphQL rules |
| `websocket` | HTTP | HTTP upgrade policy followed by WebSocket frame policy or GraphQL-over-WebSocket policy |
| future `redis`, `postgres`, `mysql`, ... | TCP application | Protocol-specific TCP parser owns the message loop |

`protocol: tcp` is effectively the default L4 mode. It should not run TCP
application parsers.

Avoid using the term "provider" for these parser concepts because providers
are already a first-class credential and routing domain in OpenShell.

## Suggested Types

The exact Rust shape can evolve, but the boundaries should look like this:

```rust
enum EgressTransport {
    Connect,
    ForwardHttp,
    TransparentTcp,
    LocalHttp,
}

struct EgressIntent {
    transport: EgressTransport,
    destination: RequestedDestination,
    process: ProcessIdentity,
    first_request: Option<ParsedHttpRequest>,
    local_route: Option<LocalRoute>,
}

struct EgressDecision {
    outcome: PolicyOutcome,
    matched_policy: Option<MatchedPolicy>,
    endpoint: Option<MatchedEndpoint>,
    log_context: EgressLogContext,
}

struct MatchedEndpoint {
    id: EndpointId,
    allowed_ips: AllowedIpPolicy,
    tls: TlsPolicy,
    enforcement: ProtocolEnforcement,
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
    allow_encoded_slash: bool,
    websocket_credential_rewrite: bool,
    request_body_credential_rewrite: bool,
    websocket_graphql_policy: bool,
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

## Module Layout

A future split could look like:

| Module | Responsibility |
|--------|----------------|
| `proxy::adapter::connect` | Parse CONNECT and render CONNECT responses |
| `proxy::adapter::forward_http` | Parse absolute-form HTTP and preserve first request |
| `proxy::adapter::transparent_tcp` | Recover captured original destination |
| `proxy::adapter::policy_dns` | Answer eligible DNS queries and publish active mappings |
| `proxy::adapter::local` | Implement `inference.local` and `policy.local` surfaces |
| `proxy::auth` | Build decisions from intents and OPA results |
| `proxy::destination` | Resolve, filter, and validate destinations |
| `proxy::netfilter` | Own nftables bypass and future transparent capture rules |
| `proxy::relay::http` | HTTP request loop, credentials, REST/GraphQL/WebSocket upgrade policy |
| `proxy::relay::websocket` | WebSocket frame validation, text-frame rewrite, and message policy |
| `proxy::relay::tcp` | TCP byte relay and TCP application parser dispatch |
| `proxy::relay::tls` | Shared client-side TLS termination |
| `proxy::parser` | HTTP, WebSocket, and TCP application parser traits/config |
| `proxy::telemetry` | OCSF and tracing helpers |

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

## Credential Injection Boundary

Credential injection belongs in the HTTP relay:

1. Authorization selects the endpoint and confirms credentials may be used.
2. The HTTP relay resolves credentials only when it has an allowed HTTP request.
3. Secrets are redacted from logs and policy-visible metadata.
4. The final upstream request or frame is rewritten with real credentials
   immediately before write.

Both L4-only HTTP and HTTP-inspected paths can inject credentials. The
difference is whether REST, GraphQL, or WebSocket policy is evaluated before
the rewrite.

Credential rewrite slots should be explicit:

- request target, query values, and headers for HTTP-family traffic;
- REST request bodies only when `request_body_credential_rewrite` is enabled;
- client-to-server WebSocket text frames only when
  `websocket_credential_rewrite` is enabled;
- GraphQL-over-WebSocket connection/control messages when they are carried in
  text frames and the endpoint enables the WebSocket rewrite path.

Request-body rewrite is REST-only. It should buffer bounded UTF-8 textual
bodies, including JSON, form-url-encoded, and `text/*`, recompute
`Content-Length`, preserve unsupported bodies that contain no reserved
credential markers, and fail closed when a reserved placeholder cannot be
resolved safely. Binary WebSocket frames are not rewritten.

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

Timeouts should be recorded in telemetry at the owner boundary that can explain
the failure.
