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
- L7 REST, GraphQL, WebSocket, and GraphQL-over-WebSocket enforcement.

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
    Relay --> Inject["Static credentials and token grants if configured"]
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
    L7 -- Yes --> Eval["Evaluate REST/GraphQL/WebSocket policy"]
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

The policy name used for L4 authorization and logging can be selected through a
different precedence rule than endpoint metadata. With overlapping host, port,
and binary rules, allowed IPs, TLS behavior, enforcement, and
`allow_encoded_slash` can come from a different endpoint than the policy name
logged and used for L4 allow.

The adapter model requires authorization to return one decision with one
deterministic matched endpoint.

### Endpoint metadata query failures should not erase enforcement

If endpoint metadata lookup fails, callers can interpret the result as no L7
configuration and downgrade to credential-only or raw L4 relay.

The adapter model treats endpoint metadata as part of the authorization result.
Failure to materialize required metadata should deny rather than erase extended
configuration.

### Destination validation must be shared

Private address checks, `allowed_ips`, exact declared private endpoint trust,
trusted gateway aliases, SSRF checks, and control-plane port blocks have grown
over time. They should be centralized so CONNECT, forward HTTP, future
transparent TCP, and local-service egress use the same resolved-destination
rules.

## Existing Feature Inventory

The refactor should preserve:

- CONNECT explicit proxy support.
- Forward HTTP explicit proxy support.
- Network-only supervisor mode.
- nftables bypass reject/log enforcement.
- Provider credential injection and redaction.
- Dynamic token grant injection through SPIFFE-backed provider credentials.
- REST request-body credential rewrite.
- WebSocket text-frame credential rewrite.
- REST endpoint method/path policy.
- GraphQL-over-HTTP policy.
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
