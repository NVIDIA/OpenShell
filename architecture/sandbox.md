# Sandbox

A sandbox is the runtime boundary where agent code executes. It is created by a
compute runtime and managed inside the workload by `openshell-sandbox`, the
sandbox supervisor.

## Runtime Model

Each sandbox workload has two trust levels:

| Process | Role |
|---|---|
| Supervisor | Starts as root inside the workload, prepares isolation, runs the proxy, fetches config, injects credentials, serves the relay socket, and launches child processes. |
| Agent child | Runs as an unprivileged user with filesystem, process, and network restrictions applied. |

The supervisor keeps enough privilege to manage the sandbox, but the agent child
loses that privilege before user code runs. On Linux, child setup clears the
capability bounding set during privilege drop so later execs cannot regain
container-granted capabilities. This is fail-closed: the supervisor retains
`CAP_SETPCAP` solely to perform the clear, and spawning the workload or SSH shell
aborts unless the bounding set ends up empty. A `setpcap` `EPERM` is tolerated
only when the set is already empty; any other outcome fails the spawn.

## Startup Flow

1. The compute runtime starts the workload with sandbox identity, callback
   endpoint, TLS or secret material, image metadata, and initial command.
2. The supervisor loads policy and runtime settings from local files or the
   gateway, depending on mode.
3. It prepares filesystem access, process restrictions, network namespace
   routing, trust stores, provider credential resolution, and inference routes.
4. It starts the policy proxy and local SSH server.
5. It opens a supervisor session back to the gateway for connect, exec, file
   sync, config polling, and log push.
6. It launches the agent command as the restricted sandbox user.

## Isolation Layers

OpenShell uses overlapping controls rather than a single sandbox primitive:

| Layer | Purpose |
|---|---|
| Filesystem policy | Landlock restricts the paths the agent can read or write. |
| Process policy | The child process runs as a non-root user with reduced privileges. |
| Seccomp | Blocks dangerous syscalls, including raw socket paths that bypass the proxy. |
| Network namespace | Forces ordinary agent egress through the local CONNECT proxy. |
| Policy proxy | Evaluates destination, binary identity, TLS/L7 rules, SSRF checks, and inference interception. |

The supervisor may enrich baseline filesystem allowances for runtime-required
paths, such as proxy support files or GPU device paths when a GPU is present.

## Network and Inference

All ordinary agent egress is routed through the sandbox proxy. The proxy
identifies the calling binary, checks trust-on-first-use binary identity, rejects
unsafe internal destinations, and evaluates the active policy.
For inspected HTTP traffic, the proxy can enforce REST method/path rules,
WebSocket upgrade and text-message rules, GraphQL operation rules, and
MCP method, tool, and supported params rules or generic JSON-RPC method rules
on sandbox-to-server request bodies. MCP and JSON-RPC inspection buffers up to
the endpoint `mcp.max_body_bytes` or `json_rpc.max_body_bytes` limit. MCP
`tools/call` tool names are checked against the spec-recommended syntax by
default before policy evaluation, with a per-endpoint `mcp.strict_tool_names`
compatibility opt-out. Generic JSON-RPC policies do not support `params`
matchers; generic JSON-RPC rules match only the method.
JSON-RPC responses and server-to-client MCP messages on response or SSE streams
are relayed but are not currently parsed for policy enforcement.

`https://inference.local` is special. It bypasses OPA network policy and is
handled by the inference interception path:

1. The proxy terminates the local TLS connection with the sandbox CA.
2. It detects known OpenAI, Anthropic, and compatible inference request shapes.
3. It strips caller-supplied credentials and disallowed headers.
4. It forwards through `openshell-router` using the route bundle fetched from
   the gateway.

External inference endpoints that do not use `inference.local` are treated like
ordinary network traffic and must be allowed by policy.

## Credentials

Provider credentials are stored at the gateway and fetched by the supervisor at
runtime. The supervisor injects resolved environment variables into the initial
agent process and SSH child processes. Driver-controlled environment variables
override template values so sandbox images cannot spoof identity, callback, or
relay settings.

Supervisor bootstrap identity is not inherited by agent child processes. When
provider token grants mount a SPIFFE Workload API socket, the socket path must
live under a dedicated directory. Children also enter a private mount namespace
where that socket directory is hidden before privilege drop.

Credential placeholders in proxied HTTP requests can be resolved by the proxy
when policy allows the target endpoint. For GCP providers, a loopback metadata
server inside the network namespace serves placeholders to SDKs that bypass the
proxy (e.g. Go's `cloud.google.com/go/compute/metadata`). Secrets must not be
logged in OCSF or plain tracing output. The supervisor uses revision-scoped
placeholders for rotating provider credentials; provider environment keys
beginning with `v<digits>_` are reserved for that placeholder namespace.

Provider profiles can also declare dynamic token grants. For matching HTTP
endpoints, the supervisor obtains a SPIFFE JWT-SVID from the local Workload API,
exchanges it for an OAuth2 access token, caches the token, and injects it as an
`Authorization: Bearer` header before forwarding the request. Token grant
endpoints are HTTPS-only except for loopback and Kubernetes service DNS hosts,
and returned access tokens must be bearer-compatible before they are cached or
injected. Token response lifetimes are capped and cached with an expiry margin
unless a profile supplies an explicit cache TTL override.

For AWS endpoints that require request-level signing, the proxy supports SigV4
re-signing. When `credential_signing: sigv4` is set on an L7 endpoint, the proxy
strips the client's placeholder-based AWS auth headers, re-signs with real
credentials from the provider, and forwards the request upstream. The signing
mode is auto-detected from the client SDK's `x-amz-content-sha256` header:

- **Signed body** (hex hash): buffers the request body (up to 10 MiB), computes
  its SHA-256, and includes the hash in the signature. Used by Bedrock and most
  AWS services.
- **Streaming unsigned** (`STREAMING-UNSIGNED-PAYLOAD-TRAILER`): signs headers
  only and streams the body through without buffering. Used by S3 uploads with
  `aws-chunked` encoding.
- **Unsigned payload** (`UNSIGNED-PAYLOAD`): signs headers only with no body
  hash. Used by S3 over HTTPS for non-chunked requests.

Chunk-signed streaming modes (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and other
`STREAMING-*` variants) are rejected — the proxy cannot reproduce per-chunk
signatures. Use `sigv4:no_body` for those clients.

Two explicit overrides are available: `credential_signing: sigv4:body` (always
buffer and hash) and `sigv4:no_body` (always unsigned). The `Expect:
100-continue` header is handled within the SigV4 path so clients like boto3
transmit the body before the proxy forwards to upstream.

The AWS region is extracted from the endpoint hostname. For non-standard
endpoints (VPC endpoints, custom proxies), set `signing_region` in the policy
endpoint to provide an explicit override. The proxy rejects requests when
neither hostname extraction nor `signing_region` yields a region.

`credential_signing` and `request_body_credential_rewrite` are mutually
exclusive on the same endpoint. The policy validator rejects policies that
set both.

## Connect and Logs

The supervisor runs an SSH server on a Unix socket inside the sandbox. The
gateway reaches it through the outbound supervisor relay, not by dialing the
sandbox workload directly. The relay supports:

- Interactive shell sessions.
- Command execution.
- Tar-based file sync.
- Port forwarding where supported by the CLI/TUI surface.

Sandbox logs are emitted locally and can also be pushed back to the gateway.
Security-relevant sandbox behavior uses OCSF structured events; internal
diagnostics use ordinary tracing.

## Policy Proposals

When an L4 CONNECT is denied, the proxy emits a `DenialEvent`. The denial
aggregator batches these events and flushes summaries to the gateway every 10
seconds (configurable via `OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS`). The gateway
runs them through the mechanistic mapper, which generates a pending
`NetworkPolicyRule` proposal visible under `openshell rule get --status pending`.

L7 denials (HTTP 403 from method/path rules) are intentionally excluded from
mechanistic mapping. L4 denials carry only `host:port`, which a deterministic mapper can handle.
L7 denials carry method, path, query, and body context. The agent loop reads
the structured 403 and authors the narrowest rule. Mechanistically mapping L7
would either over-broaden rules or require path-templating logic that rots
quickly.

## Policy Revision Acknowledgement

When the supervisor loads a sandbox-scoped policy from the gateway, it retains
the version, hash, source, and configuration revision returned with that exact
policy snapshot. After the OPA engine is built successfully, the supervisor
reports that revision as `LOADED`, which advances
`SandboxStatus.current_policy_version` and moves the revision out of `Pending`.
If policy construction fails, it reports the captured revision as `FAILED` with
the original construction error. It never infers revision identity by comparing
policy structure.

This holds even when the initial policy is enriched with baseline paths during
startup: the enriched revision the supervisor synced back to the gateway is the
revision it acknowledges, so a successfully constructed initial policy never
remains `Pending`. If the first poll returns a different revision, the supervisor
processes it through the normal reload path instead of treating it as already
loaded.

Policy status delivery uses a FIFO background worker. Retryable delivery
failures retain the ordered update and retry with capped exponential backoff;
terminal errors are logged and discarded. The outbox is nonblocking and does
not discard updates because of a fixed queue capacity, so status endpoint
outages cannot block policy polling, enforcement, settings, or provider
refreshes and cannot permanently lose the initial acknowledgement.

Only sandbox-scoped revisions (`PolicySource::Sandbox`, version greater than
zero) are acknowledged. Global policies and local-file development policies do
not use the sandbox revision API and produce no acknowledgement. When explicit
local Rego and data files are configured, the supervisor continues polling the
gateway for settings and provider refreshes but never replaces the local OPA
engine with a gateway policy revision.

## Failure Behavior

- If gateway config polling fails, the sandbox keeps its last-known-good policy.
- If a live policy update is invalid, the supervisor rejects it and keeps the
  current policy.
- Existing raw byte streams are connection scoped. Dynamic policy changes apply
  to new connections or the next parsed HTTP request where the proxy can safely
  re-evaluate.
- If the supervisor relay drops, the sandbox can keep running, but connect and
  exec operations fail until the supervisor registers again.
