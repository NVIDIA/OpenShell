---
authors:
  - "@johntmyers"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/issues/1107
  - https://github.com/NVIDIA/OpenShell/pull/1083
  - https://github.com/NVIDIA/OpenShell/pull/1151
  - https://github.com/NVIDIA/OpenShell/pull/1286
  - https://github.com/NVIDIA/OpenShell/pull/1511
---

# RFC 0005 - Sandbox Proxy Egress Adapter Model

<!--
See rfc/README.md for the full RFC process and state definitions.
-->

## Summary

Refactor sandbox egress around one shared authorization and relay pipeline.
CONNECT, forward HTTP, native TCP capture, policy DNS, `inference.local`,
`policy.local`, and metadata loopback should become narrow adapters that
translate userland entry points into common runtime intents. Policy evaluation,
destination validation, credential injection, request-body rewrite, WebSocket
handling, protocol parsing, and upstream dialing should happen behind shared
boundaries.

The codebase has already moved in this direction by splitting networking into
`openshell-supervisor-network` and process/netns work into
`openshell-supervisor-process`. This RFC proposes the next internal boundary:
make proxy entry mechanisms pluggable without duplicating authorization,
destination validation, or relay behavior.

Supporting detail lives in:

- [Current shape appendix](current-shape.md)
- [Technical design appendix](technical-design.md)
- [Implementation plan](implementation-plan.md)

## Motivation

The sandbox proxy supports several connection surfaces: explicit CONNECT,
forward HTTP, local inference and policy APIs, metadata loopback, TLS
termination, REST and GraphQL inspection, WebSocket inspection, credential
injection, and nftables-backed bypass detection. These features are valuable,
but changes to policy and enforcement still tend to touch multiple entry paths.

The risk is asymmetric enforcement. A security fix can be added to CONNECT and
missed in forward HTTP; endpoint metadata can be selected differently from the
logged policy; a credential path can gain request-body or WebSocket support
without the same behavior existing in another relay mode.

The target shape separates three concerns:

- **Adapters** describe how userland reached the networking component.
- **Authorization** decides whether the egress is allowed and what endpoint
  behavior applies.
- **Relays** own bytes, credentials, protocol parsing, and upstream dialing.

This also prepares the proxy for future deployment modes. Today the proxy runs
inside the sandbox supervisor process. The networking leaf can already run in a
network-only mode, and a future standalone binary or sidecar should be possible
if it implements the same userland surfaces, gateway APIs, and policy
enforcement contracts.

## Non-goals

- Replace CONNECT with forward proxy as the only explicit proxy mode.
- Add SOCKS support.
- Add HTTP/2 L7 parsing in this refactor. Inspected HTTP paths should continue
  to reject unsupported h2c upgrades instead of silently upgrading to raw
  traffic.
- Redesign provider credential storage.
- Reintroduce iptables as the sandbox packet filtering backend.
- Use eBPF connect hooks for transparent capture. Native TCP capture needs a
  userland proxy in the byte stream for TLS termination and protocol parsing.

## Proposal

### Migration Big Rocks

1. **Transport and local-service adapters.** CONNECT, forward HTTP,
   transparent TCP, policy DNS, `inference.local`, `policy.local`, and metadata
   loopback become small adapters. They parse their surface and produce either
   an egress intent, a local response, or a DNS answer. They do not duplicate
   policy evaluation.
2. **Egress intent and decision.** Shared authorization evaluates L4 policy and
   endpoint selection once per connection intent and returns one decision
   containing the matched policy, matched endpoint, process identity, allowed
   IP metadata, TLS behavior, protocol enforcement, and credential injection
   plan.
3. **Relays.** Relays receive an authorized destination connector, not an
   already-open upstream socket. HTTP relays evaluate every request before
   upstream write. TCP relays copy bytes for L4-only endpoints or hand the
   stream to a protocol parser when endpoint policy requires native protocol
   enforcement.

### Unified Adapter Flow

```mermaid
flowchart TD
    User["Userland payload / harness"]

    subgraph ExplicitProxy["Explicit proxy listener"]
        ProxyBytes["HTTP proxy bytes"]
        IsConnect{"CONNECT request?"}
        Connect["CONNECT adapter"]
        Forward["Forward HTTP adapter"]
        ProxyBytes --> IsConnect
        IsConnect -- Yes --> Connect
        IsConnect -- No --> Forward
    end

    subgraph NativeTcp["Policy DNS + native TCP"]
        NameLookup["Userland DNS lookup"]
        PolicyDns["Policy DNS adapter"]
        DnsAnswer["DNS answer + active mapping"]
        NativeConnect["Userland connect(ip:port)"]
        TcpAdapter["Transparent TCP adapter"]
        NameLookup --> PolicyDns
        PolicyDns --> DnsAnswer
        DnsAnswer --> NativeConnect
        NativeConnect --> TcpAdapter
    end

    subgraph LocalApis["Sandbox-local services"]
        InferenceReq["Request to inference.local"]
        PolicyReq["Request to policy.local"]
        MetadataReq["Request to metadata loopback"]
        InferenceAdapter["Inference local adapter"]
        PolicyAdapter["Policy local adapter"]
        MetadataAdapter["Metadata loopback adapter"]
        InferenceReq --> InferenceAdapter
        PolicyReq --> PolicyAdapter
        MetadataReq --> MetadataAdapter
    end

    subgraph Shared["Shared external egress pipeline"]
        Intent["EgressIntent"]
        Auth["Authorize and select endpoint"]
        Decision["EgressDecision"]
        Validate["Resolve and validate destination"]
        Relay["Relay"]
        Deny["Adapter-specific deny response"]
        Intent --> Auth
        Auth --> Allowed{"Allowed?"}
        Allowed -- No --> Deny
        Allowed -- Yes --> Decision
        Decision --> Validate
        Validate --> Relay
    end

    User --> ProxyBytes
    User --> NameLookup
    User --> NativeConnect
    User --> InferenceReq
    User --> PolicyReq
    User --> MetadataReq

    Connect --> Intent
    Forward --> Intent
    TcpAdapter --> Intent
    InferenceAdapter --> InferenceResp["Local inference response"]
    PolicyAdapter --> PolicyResp["Local policy response"]
    MetadataAdapter --> MetadataResp["Local metadata credential response"]
```

Each adapter still owns its response shape. If authorization denies a CONNECT
intent, the CONNECT adapter returns a tunnel denial. If forward HTTP is denied,
the forward adapter returns an HTTP denial. If policy DNS refuses a name, it
returns the appropriate DNS response. The shared layer decides the outcome; the
adapter renders it for its protocol.

### Relay Flow

```mermaid
flowchart TD
    Start["Authorized egress + destination connector"]
    Start --> FirstReq{"First HTTP request already parsed?"}

    FirstReq -- Yes --> ForwardMode{"decision.endpoint.enforcement"}
    ForwardMode -- "None" --> HttpCred["HTTP relay<br/>credential injection only"]
    ForwardMode -- "Http" --> HttpL7["HTTP relay<br/>REST/GraphQL/WebSocket policy"]
    ForwardMode -- "TcpApplication" --> BadForward["Deny: HTTP request for TCP app endpoint"]

    FirstReq -- No --> TlsPolicy{"TLS handling skipped?"}
    TlsPolicy -- Yes --> Readable["Readable client stream"]
    TlsPolicy -- No --> Peek["Peek client bytes"]
    Peek --> Tls{"TLS ClientHello?"}
    Tls -- Yes --> Terminate["Shared TLS terminator"]
    Tls -- No --> Readable
    Terminate --> Readable

    Readable --> Enforce{"decision.endpoint.enforcement"}
    Enforce -- "None" --> Sniff{"Looks like HTTP?"}
    Sniff -- Yes --> HttpCred
    Sniff -- No --> TcpRelay["TcpRelay<br/>byte copy"]

    Enforce -- "Http" --> MustHttp{"Looks like HTTP?"}
    MustHttp -- Yes --> HttpL7
    MustHttp -- No --> DenyHttp["Deny: expected HTTP"]

    Enforce -- "TcpApplication" --> TcpParser["TcpRelay<br/>protocol parser owns loop"]

    HttpCred --> ReqLoop["HTTP request loop"]
    HttpL7 --> ReqLoop
    ReqLoop --> ReqPolicy{"Request allowed?"}
    ReqPolicy -- No --> ReqDeny["Local HTTP deny<br/>no upstream write"]
    ReqPolicy -- Yes --> StaticCreds["Resolve static placeholders"]
    StaticCreds --> TokenGrant["Apply endpoint token grant if configured"]
    TokenGrant --> Rewrite["Rewrite configured credential slots"]
    Rewrite --> HttpDial["Connect or reuse upstream"]
    HttpDial --> HttpResponse["Write request and relay response"]
    HttpResponse --> Upgrade{"101 WebSocket upgrade?"}
    Upgrade -- No --> ReqLoop
    Upgrade -- Yes --> WsInspect{"WebSocket inspection or rewrite configured?"}
    WsInspect -- No --> RawUpgrade["Raw upgraded stream"]
    WsInspect -- Yes --> WsRelay["WebSocket relay<br/>text-frame rewrite / message policy"]

    TcpParser --> ParserDial["Parser calls connector when protocol allows"]
    TcpRelay --> TcpDial["Connect upstream"]
    TcpDial --> ByteCopy["Copy bytes"]
```

Relay rules:

- HTTP credential injection happens in both HTTP modes: L4-only HTTP and
  HTTP-inspected.
- Credential injection includes static placeholder rewrite and endpoint-bound
  dynamic token grants. Token grants run after policy allow and before upstream
  write; failures deny without forwarding the request.
- Static credential rewrite covers request target, query, headers, opt-in REST
  request bodies, and opt-in client-to-server WebSocket text frames.
- HTTP L7 policy is evaluated before upstream write for each request.
- WebSocket upgrade policy is evaluated as HTTP first. After an allowed `101`
  upgrade, the WebSocket relay owns frame parsing when text-frame credential
  rewrite, WebSocket transport policy, GraphQL-over-WebSocket policy, or safe
  compression handling is configured. Other upgraded streams remain raw.
- Forward HTTP must stay in the shared HTTP relay loop or in an equivalent
  guarded single-request relay. It must not evaluate one request and then
  switch to raw bidirectional copy.
- `protocol: tcp` or an omitted protocol means L4 authorization plus byte copy,
  except that HTTP-looking streams may still use HTTP credential injection.
- Future native protocol parsers, such as Redis, Postgres, or MySQL, own the
  full message loop and can parse multiple commands or queries on one TCP
  session.

### Adapter Responsibilities

CONNECT remains the generic explicit proxy mode for HTTPS and arbitrary TCP.
The CONNECT adapter parses `CONNECT host:port` into an `EgressIntent`, asks the
shared authorization boundary for an `EgressDecision`, returns the tunnel-ready
response only after the connection is allowed, and then hands the tunnel to the
relay. The upstream connection is opened by the HTTP relay or TCP parser when
payload policy allows it.

Forward HTTP is compatibility for clients that send absolute-form HTTP
requests. The adapter parses the first request, rewrites proxy framing only at
the relay boundary, rejects `https://` absolute-form requests, rejects
unsupported h2c upgrades on inspected routes, and either stays in a shared HTTP
request loop or forces `Connection: close` for a guarded single request.

Transparent TCP is for native clients that do not know they are using a proxy.
It depends on policy DNS and nftables capture: DNS answers create active
endpoint mappings, userland later calls `connect(ip:port)`, nftables redirects
matching traffic to a userland listener, and the TCP adapter recovers the
original destination before building an intent.

Policy DNS replaces static `/etc/hosts` snapshots for native TCP names. It is
query-driven: check whether the name is policy-eligible, resolve through
trusted DNS, filter returned IPs, publish the active endpoint mapping, and
answer userland. The later `connect(ip:port)` still runs through normal
authorization.

Local service adapters stay outside the normal external egress relay:
`inference.local` routes chat, completion, model discovery, embeddings, and
provider-specific inference traffic through the router with local limits;
`policy.local` exposes current policy, denial summaries, proposal submission,
and proposal wait routes; metadata loopback serves provider metadata
credentials to SDKs that bypass HTTP proxy variables.

### Network Enforcement Substrate

Current main uses nftables for sandbox bypass enforcement. It accepts
proxy-bound traffic, loopback, and established flows, then rejects and
optionally logs other TCP/UDP traffic for the bypass monitor. That is
enforcement, not native TCP capture.

```mermaid
flowchart TD
    Packet["Userland packet"] --> ProxyDest{"Proxy destination?"}
    ProxyDest -- Yes --> AcceptProxy["nftables accept"]
    ProxyDest -- No --> Capture{"Future native TCP capture match?"}
    Capture -- Yes --> Redirect["nftables redirect/TPROXY to transparent adapter"]
    Capture -- No --> Reject["nftables log + reject bypass"]
    Reject --> Monitor["Bypass monitor emits OCSF"]
```

Transparent TCP work should extend this nftables model with explicit capture
rules that run before the reject path and are scoped to active policy DNS
mappings. It should not add a parallel iptables path.

### Deployment Modes

| Mode | Shape | Status |
|------|-------|--------|
| Embedded supervisor | `openshell-sandbox` orchestrates `openshell-supervisor-network` and `openshell-supervisor-process` | Current |
| Network-only supervisor | Networking, policy, proxy, local services, and background tasks run without a payload process leaf | Current runtime mode |
| Standalone proxy binary | Supervisor launches networking as a separate process with explicit APIs | Future packaging/API work |
| Sidecar proxy | Proxy runs outside the payload container but inside the sandbox boundary | Future isolation mode |

A pluggable proxy must expose the right userland surfaces, implement the
gateway APIs it needs, and prove equivalent policy enforcement through tests.
The nftables rules that force or reject userland traffic belong to the sandbox
network boundary even if the proxy process later moves into a standalone binary
or sidecar.

## Implementation plan

The detailed migration plan lives in [implementation-plan.md](implementation-plan.md).
The intended order is:

1. Add regression coverage around the current split, forward HTTP invariants,
   endpoint selection, token grants, WebSocket/body rewrite, metadata loopback,
   and nftables bypass enforcement.
2. Introduce `EgressIntent` and `EgressDecision` inside
   `openshell-supervisor-network`.
3. Move destination validation and endpoint metadata materialization behind the
   shared decision and connector boundary.
4. Consolidate forward HTTP, CONNECT HTTP inspection, credential injection,
   request-body rewrite, and WebSocket handling behind shared HTTP/WebSocket
   relay code.
5. Move TLS detection and termination ahead of the HTTP/TCP relay split.
6. Add the TCP relay/parser boundary, then policy DNS and native TCP capture.
7. Treat local services and deployment modes as explicit runtime contracts.

## Risks

- Tightening endpoint metadata failures from fail-open to deny may expose
  latent policy or Rego errors.
- Deterministic endpoint selection may reject policies that currently load but
  only work by accident.
- Token grants add a runtime dependency on SPIFFE Workload API and token
  endpoints. Failures should remain fail-closed and sanitized.
- Transparent TCP capture adds network namespace interception complexity and
  must coexist with the nftables bypass reject/log table.
- Sidecar mode needs a reliable identity source for binary/path scoped policy.
- Metadata loopback and `policy.local` expand sandbox-local control surfaces
  and need strict route validation, body limits, redaction, and authentication
  boundaries.
- Provider-composed policy rules use a reserved namespace. Decisions and logs
  must distinguish provider-derived policy from user-authored policy without
  exposing provider rules as editable sandbox proposals.

## Alternatives

### Keep patching each entry path

This has the lowest short-term cost but keeps security behavior duplicated
across CONNECT, forward HTTP, and local services. It also makes future TCP
application protocol support harder because each parser must be wired through
multiple entry mechanisms.

### Replace CONNECT with forward proxy

Forward proxy only covers plaintext absolute-form HTTP requests. It is not a
replacement for HTTPS tunnels, WebSocket tunnels, or arbitrary TCP clients.
CONNECT should remain the generic explicit proxy mode.

### Build only transparent TCP

Transparent TCP helps native clients but does not replace explicit proxy
support used by common HTTP tooling. It also requires policy DNS and nftables
capture before it can safely preserve endpoint identity.

## Prior art

The current `openshell-supervisor-network` split is the immediate prior step:
it already separates proxy, OPA, L7, inference routing, policy-local routes,
TLS, and token grants from process supervision.

The current `openshell-supervisor-process` netns and bypass monitor are the
packet-enforcement substrate. Transparent TCP should extend that nftables
model rather than creating a second firewall path.

The existing L7 relay is the behavioral prior art for this RFC. It already
proves per-request HTTP evaluation, GraphQL parsing, WebSocket frame handling,
request-body rewrite, and token-grant injection can live behind relay
boundaries.

## Open questions

1. Should overlapping endpoint metadata be rejected at policy load time, or
   should policy name plus endpoint index define precedence?
2. Should direct IP connects to a policy-DNS-resolved TCP endpoint be accepted,
   or should DNS query correlation be required for stricter modes?
3. What TTL cap and stale-generation grace period should policy DNS use?
4. Which process identity source should sidecar mode use when it cannot inspect
   payload process metadata through local `/proc`?
5. Which proxy capabilities should be negotiated with the gateway at startup?
6. Should metadata loopback be modeled as an adapter inside
   `openshell-supervisor-network`, or remain orchestrated by `openshell-sandbox`
   with shared credential/provider helpers?
