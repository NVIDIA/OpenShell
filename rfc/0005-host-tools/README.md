---
authors:
  - "@shiju-nv"
state: review
---

# RFC 0005 - Host-Tools

## Summary

Some agent tools need host network reachability or host-local credentials/state instead of sandbox resources. This RFC calls those **host tools**.

V1 gives sandboxed agents one host-tool path: `http://tools.local/mcp`. The Sandbox Proxy intercepts that local origin and forwards accepted JSON-RPC requests to the configured broker.

OpenShell owns the local endpoint, JSON-RPC envelope checks, identity cleanup, and broker authentication. The broker owns tool behavior, host-side backends, authorization, catalogs, execution, and audit. Host-tool payloads do not pass through `openshell-server`.

## Current State in Upstream Main

Written against `main` at `25abc9e3c7dead448cc8d61003e76a905e26b381`.

Main has the boundary pieces needed for this design, but it has no host-tool forwarding path.

- `proto/openshell.proto` defines sandbox lifecycle, provider configuration, `ForwardTcp`, `ConnectSupervisor`, and `RelayStream`. It does not define a host-tool payload RPC, and this RFC does not add one.
- `crates/openshell-sandbox/src/proxy.rs` is the ordinary agent egress path. It evaluates policy, binds process identity, applies SSRF checks, handles L7 rules, and special-cases sandbox-local `policy.local`.
- `crates/openshell-sandbox/src/local_origin/tools.rs` is the first-party `tools.local` HTTP handler. `crates/openshell-sandbox/src/local_origin/host_tools/` contains the broker-client code, profile checks, and JSON-RPC request metadata parsing for OpenShell policy.
- `crates/openshell-sandbox/src/policy_local.rs` shows a sandbox-local hostname with proxy-owned handling. It is policy-specific and must not carry host-tool calls.
- `crates/openshell-sandbox/src/l7/inference.rs` and the `inference.local` route are closer prior art for this RFC: a reserved sandbox-local origin that reaches a credentialed backend while hiding backend URLs and credentials from sandboxed code. Host tools use the same local-origin shape but keep JSON-RPC method behavior and tool behavior in a broker implementation.
- The existing split keeps platform state and callback authorization on the gateway side, while the sandbox handles local process identity, filesystem access, network egress, credential injection, logs, and agent execution. This RFC adds broker-backed host-tool authorization and leaves that split otherwise unchanged.

Main already has sandbox-local origin prior art in `policy.local` and `inference.local`, plus supervisor control streams and relay streams for SSH, exec, and forwarded TCP. RFC 0005 adds a new sandbox-local JSON-RPC forwarding path. It does not add a proto payload RPC, reuse `ConnectSupervisor` or `RelayStream`, route through ordinary egress, or route host-tool payloads through `openshell-server`.

## Why JSON-RPC, Not Just MCP

The sandbox-facing path is `http://tools.local/mcp` because existing agents and clients expect that endpoint. The OpenShell contract is JSON-RPC because that is the stable layer OpenShell needs to inspect and forward.

OpenShell needs to read only a small set of fields before broker I/O: JSON-RPC version, method name, request id, notification shape, selected params, and bounded `_meta`. Those fields are enough for OpenShell to reserve `tools.local`, remove spoofed identity fields, attach sandbox context, ask OpenShell policy whether the JSON-RPC request is allowed, and preserve request/response ids.

OpenShell does not need to implement MCP to do that. MCP defines tool discovery, tool calls, lifecycle behavior, sessions, transport expectations, catalog updates, and result shapes. Those are broker responsibilities. Keeping the OpenShell contract at JSON-RPC prevents the sandbox proxy from becoming an MCP server and lets the selected broker implement MCP or another JSON-RPC method set.

This also avoids binding RFC 0005 to one MCP transport variant. The current profile uses HTTP because agents call `http://tools.local/mcp`, but the reviewable OpenShell boundary is: proxy-intercepted `tools.local`, JSON-RPC metadata parsing, broker JWT forwarding, and the Sandbox Proxy calling the configured broker.

## Problem

The problem is not ordinary sandbox egress. A host tool needs something the sandbox should not receive directly: host network reachability, host-local credentials, or host-local state. Examples are OS keychain lookups, desktop/session APIs, local command wrappers, already-authenticated CLIs, VPN-only internal APIs, or loopback services on the host.

The v1 design is scoped to tools that need one of two host-owned capabilities:

- *Host network reachability*: the tool needs the user's host network context, such as a VPN-only API, corporate egress path, or loopback service.
- *Host-local credentials or state*: the tool needs local OS/session state, such as an OS keychain, already-authenticated CLI, desktop/session API, or local command wrapper.

Neither capability has a path in current main. Ordinary sandbox egress is not the right boundary because it would expose host routes or credentials to sandboxed code. Copying the tool into the sandbox is not a general fallback because it can duplicate the user's installed toolchain, miss native libraries or plugins, lose access to host sockets, keychains, auth caches, VPN state, and desktop/session APIs, or run a different version than the user configured.

OpenShell needs a host-tool path with these constraints:

- The sandbox calls one reserved local origin and never sees backend routes.
- The sandbox proxy forwards accepted host-tool requests only to the configured host-tool broker.
- The OpenShell server does not carry host-tool payloads.
- OpenShell policy can allow or deny a request by JSON-RPC method and selected params before broker I/O.
- The configured broker implements the selected JSON-RPC method set and makes host-tool decisions.
- The broker must not trust identity fields, headers, or `_meta` values that came from sandbox code.
- Broker credentials are mounted only for the sandbox supervisor/proxy process, not for sandboxed agent code.
- Backend addresses, command paths, socket paths, and host-local state never enter the sandbox.

## Goals

V1 must ship only the pieces needed for that boundary:

- `tools.local` is the only sandbox-visible origin for host tools.
- `tools.local/mcp` is the only v1 broker path for agents.
- Root `tools.local/` and unknown paths remain reserved but closed.
- The selected broker connector is a JSON-RPC broker profile, not an OpenShell server session.
- The broker implements the selected JSON-RPC method set, such as MCP-shaped `initialize`, `notifications/initialized`, `tools/list`, and `tools/call`, plus authorization, execution, and broker audit.
- The proxy-side connector handles local request framing, JSON-RPC request policy, the sandbox JWT, bounded transport, response framing checks, and fail-closed error mapping.
- Cross-sandbox broker capacity, tool-specific limits, catalog policy, approvals, retries, idempotency, and audit stay in the broker.

## Non-goals

This RFC does not change filesystem, process, network, or L7 sandbox policy. It does not define the broker's policy language, approval product, storage model, signer trust store, key rotation, backend implementation, or broker audit format.

It rejects:

- a general host network tunnel;
- routing `tools.local/mcp` through ordinary sandbox egress or endpoint-route selection;
- a separate host-tool runtime, generic forwarding subsystem, or second router;
- a root `tools.local` API in v1;
- multiple broker routing in v1;
- direct sandboxed-agent calls to the host-tool broker;
- host execution in the OpenShell server;
- tool authorization in the OpenShell server;
- an OpenShell-server-maintained tool catalog;
- broker credentials readable by sandboxed agent code;
- backend routes or command paths in sandbox-visible tool text.

## Terms

### Host Tool

A tool implemented behind the broker because it needs host network reachability or host-local credentials or state.

### Host-Tool JSON-RPC Payload

The bytes accepted by the sandbox proxy on `http://tools.local/mcp`. In v1 the payload encoding is JSON-RPC 2.0.

### Host-Tool Path

The reserved sandbox-visible route `http://tools.local/mcp`.

### JSON-RPC Request Policy

An OpenShell policy decision made before broker I/O using the parsed JSON-RPC method name and selected bounded params. It decides whether the request may reach the broker. It does not define what the method means, validate broker-specific schemas, or decide whether a specific host tool should run.

### Sandbox Proxy

The in-sandbox supervisor process that already handles proxy traffic. This RFC adds the reserved `tools.local` host. The proxy intercepts requests for that host before DNS or endpoint-route selection, validates local HTTP framing, parses JSON-RPC request metadata for local policy, and forwards accepted `/mcp` traffic to the configured broker.

### Sandbox Proxy Broker Client

The broker-call code inside the Sandbox Proxy. It parses JSON-RPC request metadata, removes untrusted identity fields from `_meta`, applies local HTTP-client limits, authenticates to the selected broker, and forwards accepted traffic. It can live in a separate module for testing and readability, but it is not a separate daemon, router, OpenShell server RPC, or product component.

### Host-Tool Broker

The configured JSON-RPC service for this RFC. It implements or dispatches the selected JSON-RPC method set for forwarded `/mcp` traffic, makes host-tool decisions, routes to execution backends, and hides backend routes from the sandbox.

## Design

Sandbox code sends an HTTP request to `http://tools.local/mcp` through the OpenShell proxy. The proxy reserves the host and routes only one v1 broker endpoint:

```text
http://tools.local/mcp  -> Sandbox Proxy broker client
```

Root `http://tools.local/` and unknown paths are reserved but closed. Adding a root local API or more broker paths requires a separate RFC.

For `/mcp`, the proxy checks path, body size, `Origin`, and JSON-RPC request metadata when a JSON-RPC body is present. Accepted payload bytes are forwarded directly to the configured broker:

```text
sandbox agent
  -> http://tools.local/mcp
  -> sandbox proxy
  -> Sandbox Proxy broker client
  -> configured JSON-RPC broker
  -> private backend adapter
  -> tool-executor
```

The Sandbox Proxy parses JSON-RPC request metadata before broker I/O. It gives OpenShell policy the method name and selected bounded params, then rejects the request if policy denies it. Useful MCP policy inputs include fields such as `tools/call.params.name`, `resources/read.params.uri`, or `prompts/get.params.name`; arbitrary `params.arguments` stay broker-owned unless a future policy explicitly opts into reading them. The proxy removes sandbox-provided identity fields from top-level and `params._meta` while preserving non-identity metadata such as `progressToken`. When the method is `tools/call`, it may add OpenShell context under `openshell.host_tools/*`:

```json
{
  "openshell.host_tools/sandbox_id": "sandbox-id",
  "openshell.host_tools/session_id": "optional-supervisor-session-id",
  "openshell.host_tools/call_id": "uuid"
}
```

`openshell.host_tools/session_id` is copied from the latest `SessionAccepted.session_id` observed on the sandbox supervisor stream. It is omitted before the supervisor stream is accepted, after that session ends, or when the sandbox runs without a gateway supervisor stream. OpenShell does not inject `caller_id` in v1 because the Sandbox Proxy has no trusted sandbox-owner or caller binding.

The Sandbox Proxy then sends accepted broker traffic to the configured broker with `X-OpenShell-Sandbox-Assertion: <broker JWT for this sandbox>`. The broker verifies that JWT to prove the request came through an OpenShell-managed sandbox and derives the sandbox id from the signed claims. The JWT is signed by the OpenShell gateway Ed25519 JWT key and has `aud = openshell-host-tools-broker`, `iss = openshell-gateway:<gateway_id>`, `sub = spiffe://openshell/sandbox/<sandbox_id>`, `sandbox_id`, `iat`, and `exp`. The broker must validate the signature with the matching gateway JWT public key and `kid`, require `alg = EdDSA`, require the broker audience, check issuer and expiry, and reject normal gateway-audience sandbox tokens. `_meta` is request context and must not be treated as proof unless the broker checks it against the verified JWT claims.

The gateway owns broker policy/config distribution. The sandbox supervisor fetches the selected host-tool broker profile through a sandbox-authenticated control-plane RPC. The RPC returns the broker URL/path and the supervisor-local JWT file path, not host-tool payloads and not JWT bytes. If the gateway has no host-tool broker config for the sandbox, `tools.local` remains reserved but disabled.

The gateway can still help the broker through optional control integration: sandbox lifecycle/status, policy/config cache, key discovery, and audit correlation. If the broker calls the gateway, it needs its own gateway-authenticated identity. Broker-to-gateway calls must not become per-tool-call JSON-RPC mediation.

## Protocol Surfaces

V1 has three protocol hops:

- **sandbox -> `tools.local`**: sandbox code sends `http://tools.local/mcp` through the OpenShell HTTP proxy. The proxy intercepts the `tools.local` host before DNS, `.local` resolution, or endpoint-route selection. Root and unknown paths are reserved but closed in v1.
- **Sandbox Proxy -> broker**: the proxy forwards accepted `/mcp` request bytes directly to one configured broker. The current broker profile uses HTTP with `kind = "json_rpc_http"`, `base_url`, `rpc_path`, and `broker_sandbox_assertion_token_path`. The proxy sends `X-OpenShell-Sandbox-Assertion: <broker JWT for this sandbox>`.
- **broker -> host backends**: the broker owns tool authorization, host credentials, backend routing, execution, output shaping, and broker audit.

V1 uses JSON-RPC 2.0 as the common request envelope. `tools.local/mcp` remains the sandbox compatibility endpoint because agents such as Hermes expect that path and use MCP-shaped JSON-RPC methods. The Sandbox Proxy forwards broker-bound JSON-RPC traffic, and the broker implements the selected JSON-RPC method behavior.

The broker JWT is not the gateway-audience JWT used by the sandbox supervisor for OpenShell gRPC. Both token types are signed by the same OpenShell gateway JWT key, but their `aud` values are different. The broker must accept only the broker audience and must reject a normal gateway-audience sandbox token. A broker that talks to the gateway through protobuf needs its own gateway-authenticated identity. Broker-to-gateway calls, if added, are control integration only and must not become per-tool-call JSON-RPC mediation.

## Wire Contract

The Sandbox Proxy enforces this v1 wire contract:

- `tools.local/mcp` is the fixed sandbox-visible host-tool endpoint for JSON-RPC traffic.
- The sandbox-local body cap is 65,536 bytes.
- `/mcp` rejects JSON-RPC batch arrays, non-object JSON, missing or non-`2.0` `jsonrpc`, client-originated JSON-RPC responses, missing or non-string `method`, invalid `id`, and request methods without an `id`.
- JSON-RPC notifications may omit `id`; successful notification forwarding returns `202 Accepted` to the sandbox.
- The Sandbox Proxy parses JSON-RPC request metadata before broker I/O, applies OpenShell JSON-RPC request policy, removes sandbox-provided identity fields from `_meta`, and adds OpenShell `_meta` context only for `tools/call`.
- The current HTTP broker profile forwards accepted traffic to `<base_url><rpc_path>` with the broker JWT and JSON request/response bodies.
- Broker responses are forwarded according to the selected broker profile. The HTTP profile requires bounded, non-retried responses and preserves JSON-RPC ids where the profile validates them.
- The Sandbox Proxy never retries broker requests.
- Sandbox Proxy rejections use local JSON-RPC or closed-route errors. Broker transport or response failures map to broker error classes such as `broker_unavailable`, `broker_timeout`, and `invalid_broker_response`.

## Broker Profile

The gateway stores the host-tool broker profile under `[openshell.gateway.host_tools_broker]` and distributes the selected profile to sandbox supervisors through `GetSandboxHostToolsConfig`. The sandbox supervisor does not read a host-tool TOML file and does not accept `OPENSHELL_HOST_TOOLS_CONFIG`.

```toml
[openshell.gateway.host_tools_broker]
enabled = true
mcp_broker = "local"

[openshell.gateway.host_tools_broker.brokers.local]
kind = "json_rpc_http"
base_url = "http://host.openshell.internal:7901"
rpc_path = "/"
broker_sandbox_assertion_token_path = "/etc/openshell/auth/host-tools-broker.jwt"
```

The profile selects the broker for the fixed sandbox endpoint `http://tools.local/mcp`. V1 activates exactly one broker through `mcp_broker`; root `http://tools.local/` is reserved and closed, and `/mcp` is the only v1 broker path. The current profile shape is `kind = "json_rpc_http"`, `base_url`, optional `rpc_path`, and `broker_sandbox_assertion_token_path`.

`base_url` must be an origin with no path, query, fragment, or embedded credentials. Plain `http` is accepted only for literal loopback origins or trusted host-gateway aliases with an explicit port. Remote brokers must use `https`. `rpc_path` defaults to `/` and is a single validated path segment or `/`.

The supervisor uses built-in HTTP client defaults for local self-protection: short connect and request timeouts, bounded request and response bodies, and bounded inflight requests. These are not gateway-distributed profile fields in v1 because they protect the supervisor process, not broker authorization, quota, or execution policy. Broker-side execution limits, quotas, circuit breakers, provider health, and tool policy stay in the broker.

The gateway creates the broker JWT at sandbox creation and mounts it through the compute driver's supervisor-only secret mechanism. The gateway-distributed profile points the supervisor at that mounted JWT path. The config RPC does not carry JWT bytes. If the profile is absent, disabled, invalid, or has no selected broker, `tools.local` remains reserved but disabled. Rollback is gateway config-only: remove the profile, set `enabled = false`, or remove `mcp_broker`, then restart affected sandbox supervisors.

## Component Responsibilities

V1 has one responsibility boundary:

- The sandbox proxy turns `tools.local` traffic into direct broker traffic.
- The Sandbox Proxy broker client attaches broker auth, sends the sandbox JWT, applies local transport limits, parses JSON-RPC request metadata for OpenShell request policy, calls the selected broker only when policy allows it, and maps failures.
- The broker implementation handles JSON-RPC protocol behavior and host-tool behavior: catalog content, authorization, backend routing, credentials, execution, result shaping, and broker audit.

The Sandbox Proxy may reject bad transport, bad envelopes, JSON-RPC request-policy denial, bad broker context, unavailable brokers, or invalid broker responses. It does not implement the selected JSON-RPC method behavior, tool catalogs, or tool execution authorization, and root `http://tools.local/` is not a second broker endpoint or future API commitment.

V1 broker JWTs are sandbox-bound, not supervisor-session-bound. If the broker needs hard active-session proof, add a short-lived session-bound JWT or a low-QPS gateway introspection/watch path rather than routing host-tool payloads through `openshell-server`.

## Future Direction

Future work may add root local APIs, Unix-socket broker connectors, verified broker identity, or multiple broker routing. None of those are v1 requirements. Each needs a separate RFC because each expands what sandbox code can reach or what brokers can access.

Any future expansion must preserve the core rule: sandbox code sees only `tools.local`; the Sandbox Proxy applies `tools.local` and JSON-RPC request policy; broker implementations keep host-tool method decisions and execution behind the broker boundary. Host-tool payloads must not be routed through `openshell-server`.

## Implementation Plan

1. Add sandbox-local `local_origin::host_tools` modules for profile validation, JSON-RPC helpers, broker-client logic, and normalized error types.
2. Keep `proto/openshell.proto` and `openshell-server` free of host-tool payload RPCs; broker-bound JSON-RPC stays on the Sandbox Proxy-to-broker path.
3. Add a sandbox `tools.local` handler that reserves the host, exposes only `/mcp` in v1, validates local HTTP framing, parses JSON-RPC request metadata, and forwards accepted `/mcp` traffic through the Sandbox Proxy broker client.
4. Add gateway-owned broker profile config and a sandbox-only `GetSandboxHostToolsConfig` RPC. The sandbox supervisor loads host-tool config only from that RPC.
5. Add selected broker profile validation in the sandbox supervisor.
6. Add broker-client handling that parses JSON-RPC request metadata, applies OpenShell JSON-RPC request policy, removes untrusted identity fields from `_meta`, inserts OpenShell `_meta` context for `tools/call`, and forwards to the selected broker only when policy allows it.
7. Add broker client behavior for the current HTTP profile: local plain HTTP or remote HTTPS origin, broker JWT header, connect timeout, request timeout, body caps, response-id validation where applicable, and no retries.
8. Add regression tests for gateway config distribution, config parsing, proxy routing, `_meta` identity handling, broker error handling, and ordinary sandbox behavior.

## Risks

- **OpenShell server scope creep.** `openshell-server` must not become a host-tool runtime or data-plane forwarder. Backend-specific policy, approval logic, credential handling, and command execution belong behind the broker.
- **Protocol scope creep.** `tools.local/mcp` exists so agents can use JSON-RPC tool methods such as MCP-shaped `tools/list` and `tools/call`. It does not make OpenShell a full MCP server or broker-side protocol client.
- **Broker trust.** OpenShell cannot prove broker decisions. Production use requires broker-owner security review and broker audit.
- **Supervisor JWT exposure.** The broker JWT is held by the sandbox supervisor/proxy process. It must be mounted only for that process, not for the sandbox user or agent process.
- **Broker binding.** V1 authenticates Sandbox Proxy-to-broker requests with a broker JWT for the sandbox. Plain HTTP is restricted to loopback or trusted host-gateway aliases; remote brokers must use HTTPS. Stronger broker identity or alternate transports, such as mTLS, Unix sockets, or Unix peer credentials, are future work.
- **Host-gateway plaintext.** Trusted host-gateway aliases use HTTP. They are not equivalent to same-namespace loopback because the broker JWT crosses the container bridge in plaintext.
- **JWT scope.** Broker JWTs should only be created and mounted for sandboxes with host tools enabled. Ordinary sandboxes do not need this credential.
- **Value leakage.** OpenShell cannot detect every route, credential name, or command path embedded in broker-emitted strings. The broker must keep those values out of sandbox-visible catalog and result text.

## Alternatives

### OpenShell Server Runs Host Tools

The OpenShell server validates policy and calls host-side MCP servers or command runners directly. That makes the server responsible for host execution, backend routing, output shaping, and execution audit.

Choose this only if OpenShell intentionally moves host-tool policy, backend routing, approval state, output routing, and execution audit into `openshell-server`.

### Decision Service plus Server Execution

The OpenShell server calls a decision service, then executes. This leaves two brokers, and execution still uses routing and output shaping inside the server.

This is useful only if OpenShell intentionally moves execution into `openshell-server` and needs a separate decision service. That is not this RFC.

### Provider Calls Host Tools Directly

The provider receives a remote MCP or tool-server URL. That exposes host routes outside the OpenShell `tools.local` path, weakens audit, and bypasses the sandbox proxy.

This needs a separate RFC covering provider-facing schema generation, callback authentication, result adaptation, and audit correlation.

### Sandbox Calls Host APIs Directly

The sandbox holds scoped credentials and calls APIs. This puts credentials and route details in the sandbox. User-session OS APIs and command wrappers also do not fit ordinary network policy.

This works only for tools with no hidden host route, no credential to broker, and a clean fit for ordinary network policy. At that point they are not host tools and do not need `tools.local`.

### Use `policy.local` for Host Tools

This combines a policy-advisor API with host execution and makes it harder to keep authorization, audit records, and failure modes separate.

This only works if `policy.local` is restructured to give policy proposals and host execution separate authorization, audit, and failure modes. At that point the result is `tools.local` under a different name.

## Prior Art

- `crates/openshell-sandbox/src/proxy.rs` and `crates/openshell-sandbox/src/policy_local.rs` show the sandbox proxy serving a sandbox-local hostname and using the gateway for operations that read or update gateway state.
- MCP uses JSON-RPC 2.0 method names, request ids, and method-specific params. This RFC focuses on that encoding layer so OpenShell policy can allow or deny requests while MCP method behavior stays in the broker implementation.

## Open Questions

No v1 protocol questions are open in this draft. The remaining work is implementation, verification, and acceptance signoff.
