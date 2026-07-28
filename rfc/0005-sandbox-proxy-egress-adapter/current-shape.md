# Current Shape Appendix

This appendix records the current proxy shape and the review findings that
motivate the adapter model. The main RFC intentionally keeps these details out
of the direction document.

## Current Runtime Split

The proxy is no longer only a large module inside `openshell-sandbox`.
Current main has three relevant runtime owners:

```mermaid
flowchart TD
    Sandbox["openshell-sandbox<br/>orchestrator"]
    Network["openshell-supervisor-network<br/>proxy, OPA, L7, TLS, inference,<br/>policy.local, token grants"]
    Process["openshell-supervisor-process<br/>process leaf, SSH, netns,<br/>nftables, bypass monitor"]
    Denials["Denial/activity aggregators"]
    Gateway["Gateway policy/provider APIs"]

    Sandbox --> Network
    Sandbox --> Process
    Network --> Denials
    Process --> Denials
    Sandbox --> Gateway
    Network --> Gateway
```

`openshell-sandbox` creates the shared network namespace, owns denial/activity
channels, starts the policy poll loop, starts networking, starts the metadata
loopback server when needed, and then optionally starts the process leaf. If
`process_enabled` is false, the supervisor can run in network-only mode and
keep networking/background tasks alive until shutdown.

`openshell-supervisor-network` owns the explicit proxy listener, OPA engine
integration, L7 enforcement, TLS termination, inference routing, policy-local
routes, identity cache, provider credential injection, and token grants.

`openshell-supervisor-process` owns process execution, SSH, network namespace
helpers, nftables bypass rules, and the bypass monitor that turns nftables LOG
entries into OCSF events.

In embedded supervisor mode, the network leaf normally uses process metadata
resolved by the process/orchestrator side for binary-scoped policy and OCSF
context. Current runtime configuration can instead select endpoint-only policy
evaluation. The adapter model must preserve that intentional mode separately
from an identity lookup failure; the latter continues to deny when binary
identity is required.

## Current Userland-Facing Surfaces

The networking surface currently includes:

- CONNECT proxy traffic for HTTPS and generic TCP tunnels.
- Forward HTTP proxy traffic for absolute-form HTTP requests.
- `inference.local` for local inference routing.
- `policy.local` for current policy, denial summaries, proposal submission,
  and proposal wait routes.
- GCE metadata loopback for SDKs that bypass HTTP proxy variables.
- nftables bypass enforcement for direct TCP/UDP egress that does not enter
  the proxy.
- OPA/Rego policy and endpoint metadata lookups.
- DNS resolution and endpoint validation for CONNECT and forward HTTP egress.
- Static provider credential injection and redaction.
- Endpoint-bound dynamic token grant injection.
- Opt-in REST request-body credential rewrite.
- L7 REST, GraphQL, JSON-RPC, MCP, WebSocket, and
  GraphQL-over-WebSocket enforcement.

The issue is not that these features exist. The issue is that entry mechanisms,
policy evaluation, endpoint metadata lookup, credential injection, and byte
relay decisions are still interleaved.

## Current CONNECT Shape

```mermaid
flowchart TD
    Client["Client CONNECT host:port"] --> Parse["Parse CONNECT target"]
    Parse --> L4["Evaluate network policy"]
    L4 --> Allowed{"Allowed?"}
    Allowed -- No --> Deny["CONNECT denial"]
    Allowed -- Yes --> Meta["Query endpoint metadata"]
    Meta --> Config{"L7, TLS, or credential config?"}
    Config -- No --> Tunnel["Return tunnel-ready response"]
    Config -- Yes --> Tunnel
    Tunnel --> Inspect["Inspect tunneled bytes when possible"]
    Inspect --> Relay["HTTP/WebSocket/TCP relay selection"]
    Relay --> Inject["Middleware, static credentials, and token grants if configured"]
    Inject --> Upstream["Open upstream when relay policy allows"]
```

CONNECT is still the strongest entry shape because the tunnel relay can keep
parsing HTTP requests on long-lived connections and enforce request policy per
request.

## Current Forward HTTP Shape

```mermaid
flowchart TD
    Client["Absolute-form HTTP request"] --> Parse["Parse first request"]
    Parse --> L4["Evaluate network policy"]
    L4 --> Allowed{"Allowed?"}
    Allowed -- No --> Deny["HTTP denial"]
    Allowed -- Yes --> L7{"Matching L7 endpoint?"}
    L7 -- Yes --> Eval["Evaluate REST/GraphQL/JSON-RPC/MCP/WebSocket policy"]
    Eval --> Guard["Reject unsupported h2c upgrade when inspected"]
    Guard --> Rewrite["Rewrite to origin-form + configured credentials"]
    L7 -- No --> Rewrite
    Rewrite --> Token["Apply token grant if endpoint-bound"]
    Token --> Close["Force Connection: close except WebSocket upgrade"]
    Close --> Upstream["Open upstream"]
    Upstream --> Relay["Guarded HTTP relay / upgrade relay"]
```

Latest main no longer has the old raw-copy-after-first-request shape for
ordinary forward HTTP. It rewrites ordinary requests with `Connection: close`,
uses guarded HTTP relay helpers for body handling, rejects inspected h2c
upgrades, injects token grants, and sends allowed WebSocket upgrades through
the upgrade relay. That is a narrower surface than the historical bidirectional
copy, but it is still orchestrated separately from the CONNECT relay path.

## Current Local Service Shape

```mermaid
flowchart TD
    Request["Request to local name"] --> Match{"Known local route?"}
    Match -- "inference.local" --> Inference["Inference route adapter"]
    Match -- "policy.local" --> Policy["Policy local adapter"]
    Match -- "metadata loopback" --> Metadata["Metadata credential server"]
    Match -- No --> External["Normal egress path"]
    Inference --> InferenceResp["Local inference response"]
    Policy --> PolicyResp["Local policy response"]
    Metadata --> MetadataResp["Metadata response"]
```

`inference.local` now covers buffered and streaming inference shapes including
chat/completion routes, model discovery, embeddings, and provider-specific
routes. `policy.local` supports the agentic approval loop: agents can submit
narrow proposals and wait on approval/reload before retrying. Metadata
loopback exists for provider credentials consumed by SDKs that do not honor
HTTP proxy variables.

These are userland-facing network surfaces. They should stay distinct from
external egress while still fitting the adapter model.

## Adjacent In-Flight Supervisor Middleware Shape

PRs #1738 and #2027 propose supervisor middleware as an HTTP request hook in
the proxy relay. That work is adjacent to this RFC rather than a separate entry
adapter.

```mermaid
flowchart TD
    Req["Parsed admitted HTTP request"] --> Policy["Network and request policy already allowed"]
    Policy --> Hook["HTTP_REQUEST / PRE_CREDENTIALS middleware"]
    Hook --> Outcome{"Middleware outcome"}
    Outcome -- "deny" --> Deny["Local deny, no credential injection"]
    Outcome -- "allow / mutate" --> Recheck["Re-parse transformed body and re-evaluate policy"]
    Recheck --> Allowed{"Allowed under endpoint enforcement mode?"}
    Allowed -- "no" --> PolicyDeny["Local policy deny, no credential injection"]
    Allowed -- "yes" --> Creds["Credential injection"]
    Creds --> Upstream["Upstream write"]
```

The proposed middleware chain is selected by admitted destination host, runs in
deterministic order, buffers bounded request bodies, applies `fail_open` or
`fail_closed`, emits audit-safe findings, and runs before OpenShell-managed
credentials are injected. Middleware-transformed GraphQL, JSON-RPC, and MCP
bodies are re-parsed and re-evaluated before credential injection or upstream
write, so a mutation cannot bypass request policy. Policy mismatches retain the
endpoint's audit or enforce behavior, while malformed transformed protocol
bodies fail closed in either mode. Middleware can inspect WebSocket upgrade
requests because they are HTTP requests, but it does not inspect post-upgrade
WebSocket frames in v1.

RFC 0005 should account for this by treating middleware as part of the shared
request processing plan. CONNECT and forward HTTP should not each learn how to
select and invoke middleware independently.

## Current Network Namespace Enforcement

```mermaid
flowchart TD
    Start["Process in sandbox network namespace"] --> Dest{"Destination"}
    Dest -- "Proxy host_ip:port" --> Proxy["Accept to sandbox proxy"]
    Dest -- "Loopback" --> Loopback["Accept loopback"]
    Dest -- "Established/related" --> Established["Accept response packet"]
    Dest -- "Other TCP/UDP" --> Reject["nftables log + reject"]
    Reject --> Monitor["Bypass monitor reads dmesg"]
    Monitor --> OCSF["OCSF network + detection events"]
```

The process leaf installs an `inet` nftables filter table for bypass
enforcement. The table accepts proxy-bound traffic, loopback, and established
flows, then rejects and optionally logs other TCP/UDP traffic. It does not
currently redirect native TCP connections into the proxy.

## Findings To Preserve

### Invariant: forward proxy must not relay unevaluated follow-on HTTP bytes

The historical forward path evaluated at most the first absolute-form request,
rewrote it, then switched to bidirectional copy. Bytes already buffered after
the first header block, or later pipelined requests on the same client/upstream
connection, could reach upstream without the CONNECT L7 relay's per-request
parser/evaluator.

Latest main mitigates this by forcing ordinary forward HTTP to one request per
connection and by using guarded relay helpers. The adapter model should
preserve the invariant either by keeping forward HTTP single-request/close or
by passing the first parsed request into a shared HTTP relay loop.

### Endpoint config is not tied to deterministic matched policy

The policy name used for L4 authorization and logging is the lexicographically
smallest matching policy. L7 candidates are collected independently and later
selected by request-path specificity. TLS and `allowed_ips` use the first
extended endpoint config returned by a separate query. Exact-declared-host is
another independent existential query. With overlapping host, port, and binary
rules, those results can describe different endpoints and policies on the same
connection.

The adapter model requires authorization to return one decision with one
deterministic matched endpoint.

### Policy materialization can span generations

The L4 decision, L7 route, TLS mode, `allowed_ips`, and exact-declared-host
signal are materialized through separate engine calls. The L7 route records a
generation for its tunnel evaluator, but the sibling metadata queries are not
all asserted against the L4 decision generation. A reload during setup can
therefore assemble one logical connection decision from different policy
generations.

The target decision carries one top-level policy generation. Every
policy-derived field must be evaluated from that generation, and relay startup
must reject a stale decision before an upstream request is written.

### Endpoint metadata query failures should not erase enforcement

Failure behavior is not uniform today. L7 configuration failure becomes no L7
configuration, and TLS configuration failure becomes automatic TLS handling;
either can erase intended enforcement. `allowed_ips` and the downstream SSRF
validation path are already more conservative. The migration must test each
query independently instead of describing all metadata failures as equivalent.

The adapter model treats endpoint metadata as part of the authorization result.
Failure to materialize required metadata should deny rather than erase extended
configuration.

### Destination validation must be shared

Private address checks, `allowed_ips`, exact declared private endpoint trust,
trusted gateway aliases, SSRF checks, and control-plane port blocks have grown
over time. They should be centralized so CONNECT and forward HTTP use the same
resolved-destination rules. Existing local services remain outside normal
external destination validation.

## Existing Feature Inventory

The refactor should preserve:

- CONNECT explicit proxy support.
- Forward HTTP explicit proxy support.
- Network-only supervisor mode.
- nftables bypass reject/log enforcement.
- Provider credential injection and redaction.
- Dynamic token grant injection through SPIFFE-backed provider credentials.
- Supervisor middleware `HTTP_REQUEST / PRE_CREDENTIALS` when it lands.
- REST request-body credential rewrite.
- WebSocket text-frame credential rewrite.
- REST endpoint method/path policy.
- GraphQL-over-HTTP policy.
- JSON-RPC-over-HTTP method policy.
- MCP Streamable HTTP method and tool policy.
- WebSocket transport and GraphQL-over-WebSocket policy.
- h2c rejection on inspected HTTP routes.
- Inference routing through `inference.local`, including embeddings.
- Agent-facing policy advisor routes through `policy.local`.
- GCE metadata loopback for supported provider credentials.
- Timeout and resource tracking for client, upstream, and local service work.
- Structured OCSF logging for network and HTTP policy outcomes.
- SSRF and internal address protections.
- Exact declared private endpoint handling.
- Control-plane port protection.
- `allowed_ips` endpoint restrictions.
- TLS auto-detection and termination for inspectable client connections.
