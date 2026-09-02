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
4. It launches the persisted canonical main-process argv and retains its PTY
   or pipes in the main-session multiplexer.
5. It starts the policy proxy and local SSH server.
6. It opens a supervisor session back to the gateway for connect, exec, file
   sync, config polling, and log push.

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

See [Sandbox Limits](sandbox-limits.md) for the current numeric safety ceilings,
their ownership, terminal behavior, and known gaps.

All ordinary agent egress is routed through the sandbox proxy. The proxy
identifies the calling binary, checks trust-on-first-use binary identity, rejects
unsafe internal destinations, and evaluates the active policy. On Linux, it
maps an accepted proxy connection back to the workload socket by matching the
complete local-to-remote TCP tuple before resolving every process that owns the
socket inode.

CONNECT and absolute-form forward HTTP are explicit-proxy adapters over the same
egress pipeline. Each adapter normalizes its request into an egress intent, and
the shared authorization result carries the process evidence and endpoint
metadata used by destination validation and relay selection. Network action,
matched policy, endpoint configuration, and exact-host authorization are
evaluated as one atomic snapshot from one policy generation. Destination validation
returns an unopened connector so adapters retain their existing response and
upstream-dial timing. CONNECT prepares a generation-pinned relay context before
entering shared TLS-terminated or plaintext HTTP relays; non-HTTP traffic uses
the shared raw byte relay after the existing adapter gates. Forward HTTP retains
its guarded single-request relay while sharing authorization, request context,
policy-pinning, and destination boundaries.
Adapter-specific response and OCSF event shapes remain at the protocol boundary.
An explicit `protocol: tcp` endpoint with a valid DNS hostname opts into native
DNS and transparent TCP when the selected runtime advertises that substrate.
Hostless `allowed_ips` and literal-IP selectors remain available only to the
legacy explicit-proxy path when `protocol` is omitted. The shared supervisor
answers only eligible DNS names, returns an epoch-scoped synthetic address, and
publishes the expiring name, endpoint, ports, policy generation, and validated
real addresses as one correlation. A connection to that synthetic address is
captured before the bypass fence, mapped back to its workload process, authorized
through the same egress pipeline, and dialed only through the pinned addresses.
Omitted protocol endpoints retain explicit-proxy behavior.

The DNS store is in-memory and sandbox-local. A combined-supervisor restart also
restarts its workload; before execution, the supervisor advances a persisted
boot epoch and installs only that epoch's synthetic capture ranges. An address
cached from the preceding epoch therefore falls through to the bypass fence
instead of inheriting a new mapping. Policy reload, expiry, wrong ports, direct real-IP access, missing
mappings, or pool exhaustion fail closed. Resolver injection, DNS listeners,
capture rules, and the transparent listener are all ready before workload
execution. A runtime that cannot provide the complete contract rejects a policy
containing explicit TCP endpoints rather than partially activating it. Because
that substrate is startup infrastructure, a sandbox created without explicit
TCP endpoints rejects a hot reload that introduces one and keeps its complete
previous policy active; recreating the sandbox installs the substrate before
the workload starts. A sandbox that started with the substrate may continue to
remove and re-add TCP endpoints through ordinary atomic policy reloads.
Workload DNS targets port 53, while nftables redirects eligible IPv4 DNS traffic
to an unprivileged supervisor listener. The filter admits DNS and transparent
TCP only when the kernel records the traffic as DNATed to the corresponding
supervisor listener, so direct dials to either unprivileged listener port remain
fenced. `SO_ORIGINAL_DST`, synthetic mapping lookup, endpoint correlation, and
generation-pinned authorization form the transparent TCP security boundary.
Docker and Podman do not currently advertise usable IPv6 egress for this
substrate, so AAAA queries return NOERROR/NODATA and IPv6 DNS remains fenced.

Provider credential placeholders are resolved through the live provider state
for each HTTP request, after destination and L7 policy admission. A static
credential resolves only when the request host, port, and path match an endpoint
in that provider's effective profile. CONNECT, absolute-form forward HTTP,
request targets, headers, supported request bodies, SigV4 signing, and opted-in
WebSocket text rewriting use the same scoped resolver. Provider refresh swaps
credential values and endpoint bindings atomically. An invalid or unavailable
refresh revokes the previous static credential state instead of leaving a
partially active or last-known-good static set. Invalid metadata preserves the
supplied dynamic snapshot, while a fetch failure preserves the currently active
dynamic snapshot.

In the Kubernetes sidecar topology, the provider environment revision remains
an opaque content fingerprint and has no numeric ordering semantics. The
network supervisor assigns a separate, connection-local monotonic generation
to each distinct environment it publishes. The process supervisor applies only
newer generations, which accepts descending fingerprint values while rejecting
duplicate or delayed sidecar messages.

Gateway-managed refresh credentials use an opaque workload handle derived from
the sandbox, provider identity, credential key, refresh authorization epoch,
and canonical endpoint boundary. The handle remains stable while the gateway
rotates the short-lived value, so an already-running process keeps one
placeholder and each request resolves against the current token. Explicit
refresh reconfiguration, provider replacement or detachment, and endpoint
boundary changes produce a new handle and revoke the old one. Supervisors do
not retain old values for these handles. Public provider updates cannot replace
or delete the refresh-owned primary credential or co-minted outputs; internal
CAS rotation and explicit refresh lifecycle operations own those values.
Unmanaged static credentials retain the bounded revision-generation behavior.

Route selection and policy evaluation use a syntax-only redacted request target;
they do not materialize real credentials. Cross-endpoint placeholder use returns
HTTP 403. After a WebSocket upgrade it closes the connection with policy
violation code 1008. Both paths emit a denied activity event and a detection
finding without logging the placeholder, environment key, secret, or query.

For inspected HTTP traffic, the proxy can enforce REST method/path rules,
WebSocket upgrade and text-message rules, GraphQL operation rules, and
MCP method, tool, and supported params rules or generic JSON-RPC method rules
on sandbox-to-server request bodies. MCP and JSON-RPC inspection buffers
bounded request bodies. MCP `tools/call` tool names are checked against the
spec-recommended syntax by default before policy evaluation, with a per-endpoint
`mcp.strict_tool_names` compatibility opt-out. Generic JSON-RPC policies do not
support `params` matchers; generic JSON-RPC rules match only the method.
JSON-RPC responses and server-to-client MCP messages on response or SSE streams
are relayed but are not currently parsed for policy enforcement.

For admitted HTTP requests, the proxy can run an ordered supervisor middleware
chain after L7 policy evaluation and before credential injection. Destination
host selectors choose the chain independently of the network rule that admitted
the request. Policy-local map keys identify configs, while built-in names or
operator-owned registration names identify implementations.

Built-ins run in-process against a borrowed view of the chain's current HTTP
request state. Operator services retain the bounded protobuf/gRPC contract, and
the remote adapter materializes an owned HTTP evaluation only when a request
crosses that transport boundary. Both paths support bounded bidirectional
WebSocket sessions, so a manifest advertises capabilities independently of
transport.
When a stage ends, the remote adapter sends its terminal event, half-closes the
request stream, and briefly drains the response stream before releasing the
transport. This keeps a queued terminal event from being canceled with the
bidirectional RPC.
The runtime keeps three states distinct: host selection attaches policy configs,
manifest operation and phase bindings select the active chain, and the parsed
message type determines whether that chain can inspect an individual payload.
An attachment without a WebSocket binding is not a failed WebSocket stage.
Binary messages are outside the V1 text-message binding. Both cases pass through
with informational coverage telemetry rather than applying `on_error`.
The chain runner owns shared sequencing, deadlines, backpressure, and response
validation. `openshell-policy` validates policy-owned structure, and the active
middleware registry validates implementation-owned config. The generic
registry and chain runner live in `openshell-supervisor-middleware`; first-party
implementations live in `openshell-supervisor-middleware-builtins`.

The supervisor installs policy and middleware registry changes as one runtime
generation and preserves the last-known-good generation if preparation fails.
Policy-only updates reuse the connected registry, so an external middleware
outage cannot block unrelated policy changes.

For authenticated operator middleware, the supervisor requests credentials by
registration name through `RefreshSandboxToken`. The gateway resolves names
against the effective policy and mints exact-audience credentials. The
supervisor keeps them in refreshable in-memory slots outside stable middleware
configuration, so rotation neither changes `config_revision` nor reconnects
the registry. Public custom-CA PEM travels with the stable registration.

The slots live in a supervisor-owned `ExtensionCredentialStore` shared by every
gateway connection the supervisor opens, so the registry's clients and the
polling loop that rotates them observe the same credentials. Configuration
polling runs far more frequently than credentials expire, so the loop rotates
only when a credential is missing or has passed four fifths of its lifetime,
and bounds its sleep by the soonest rotation deadline.

Middleware cannot observe injected credentials or mutate supervisor-owned
credential, routing, or framing headers. Body transformations are re-evaluated
against body-aware L7 policy before later stages or the upstream can observe
them. Requests, results, chain length, execution time, and diagnostics are
bounded; external free-form diagnostic text is not exposed in responses or
security logs. See
[Supervisor Middleware](../docs/extensibility/supervisor-middleware.mdx) for
configuration and protocol details.

`https://inference.local` is special. It bypasses OPA network policy and is
handled by the inference interception path:

1. The proxy terminates the local TLS connection with the sandbox CA.
2. It detects known OpenAI, Anthropic, and compatible inference request shapes.
3. It strips caller-supplied credentials and disallowed headers.
4. It forwards through `openshell-router` using the route bundle fetched from
   the gateway.

External inference endpoints that do not use `inference.local` are treated like
ordinary network traffic and must be allowed by policy.

In proxy-required networks, the supervisor chains upstream TLS tunnels through
a corporate forward proxy with HTTP CONNECT instead of connecting directly,
once policy and SSRF checks pass. Only TLS (CONNECT) egress is chained:
plain-HTTP requests always dial the destination directly, because forwarding
plain HTTP through a proxy requires absolute-form request forwarding rather
than CONNECT tunneling and is out of scope. The proxy configuration is an
operator-owned boundary delivered on the supervisor's command line
(`--upstream-proxy` and friends) by the compute driver; sandbox and template
environment — and `ENV` values baked into the sandbox image — cannot
influence it, since none of these can alter the argv the driver sets. The
conventional `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` variables a sandbox
controls are ignored on this path. Operator `NO_PROXY` destinations and
loopback always dial directly; add driver-injected host aliases (e.g.
`host.containers.internal`) to the operator `NO_PROXY` list when the corporate
proxy cannot reach the container host. `NO_PROXY` matching is port-aware and
resolution-aware: an entry with a `:port` qualifier only bypasses that port,
and IP/CIDR entries also match hostnames through their validated resolved
addresses, with the direct dial limited to the addresses the entry contains. `http://` and `https://` proxy URLs in explicit
`scheme://host:port` form are supported — the scheme and port are both
required, and a path, query, or fragment is rejected. For an `https://` proxy
the supervisor wraps the connection to the proxy in TLS before the CONNECT
handshake, verifying the proxy certificate against the built-in and system
roots plus the optional operator CA bundle (see below). Local DNS resolution
and SSRF validation still run before the proxied dial, and the CONNECT
target sent to the corporate proxy is a validated resolved address, so the
proxy performs no DNS resolution of its own and the tunnel stays bound to
the answer that passed SSRF and `allowed_ips` validation. The hostname still
travels inside the tunnel (TLS SNI, application `Host`). In split-horizon
networks, point the gateway host at the corporate resolver so internal names
validate to their internal addresses; the `proxy_connect_by_hostname`
opt-in exists as a
last resort for proxies whose ACLs filter on hostnames and reject IP CONNECT
targets — with it, the proxy resolves the name itself and its ACLs become
the effective egress control for proxied TLS. (Resolving through the proxy's
own DNS view, e.g. DoH tunneled via CONNECT, is a possible future
enhancement and out of scope.) The workload child's proxy variables are
unaffected — they are always rewritten to point at the local policy proxy.

Template environment is treated like user-provided sandbox environment. It can
shape the workload child, but it cannot override driver-controlled identity,
gateway callback, TLS, relay socket, proxy, provider, or supervisor coordination
variables. Drivers and the supervisor rewrite those reserved values after image
and template environment are considered.

The configuration is fail-closed: a setting that is present but invalid — an
empty value, an unsupported or malformed proxy URL, an unreadable auth file or
CA bundle, a malformed credential, or an auth file, `NO_PROXY` list, or CA
bundle set while no proxy URL is configured — is fatal to supervisor startup
instead of being treated as unset, so a misconfiguration can never silently
degrade to direct dialing or unauthenticated proxy access. Only an omitted
argument means "no proxy". The driver validates the same rules at
sandbox-create time through validators shared with the supervisor
(`openshell_core::driver_utils::parse_upstream_proxy_url` and
`parse_upstream_proxy_credential`).

An optional operator CA bundle (`--upstream-proxy-ca-bundle`, a PEM path the
driver bind-mounts read-only into the sandbox) extends the trust boundary for
corporate proxies. A CA certificate is not secret, so unlike the auth file it
travels as a plain read-only bind mount rather than a driver secret. It is
trusted in two places: the TLS handshake with an `https://` proxy, and —
because a TLS-intercepting proxy (mitmproxy, squid `ssl-bump`) re-signs
tunneled server certificates with the same CA — the sandbox combined trust
bundle (`write_ca_files`) and the L7 upstream re-encryption store
(`build_upstream_client_config`). Folding it into both means intercepted
upstream handshakes succeed and sandbox workload processes trust the re-signed
certificates; trusting it only for the proxy-listener handshake would leave
every intercepted upstream connection failing. The bundle is valid with either
an `http://` or `https://` proxy (an intercepting proxy can be reached over
plain HTTP) and is fail-closed: an unreadable or certificate-free file is fatal.

Proxy credentials are never embedded in the URL: an inline `user:pass@` is
rejected because it would be stored in `gateway.toml` and exposed in container
metadata. Operators supply credentials via `proxy_auth_file`; the driver
stages them as a root-only secret mounted at a fixed path and passes only
that path on the supervisor's command line. The supervisor reads the
file and builds the `Proxy-Authorization: Basic` header; a credential that is
empty, contains control characters, or is not in `user:pass` form is fatal on
both sides.

The VM driver has no argv seam of its own: its guest init script runs as PID 1
and execs a fixed supervisor command line, and the libkrun and QEMU launch
backends both reach the supervisor through that script. Driver-owned
supervisor arguments therefore travel in a per-sandbox file the driver writes
into the overlay upperdir at a fixed guest path, one argument per line, which
the guest reads verbatim (no word splitting or globbing) and appends to every
supervisor exec. The file is written on **every** launch, including an empty
file when there is nothing to pass: the upperdir copy always shadows the
read-only image layer, so a sandbox image can neither supply its own
supervisor arguments by baking a file at that path nor disable the operator's
by omitting one. This mirrors the driver-authored `init.d` manifest, which
solves the same trust problem for guest init drop-ins.

A microVM has no bind mounts or container secrets, so the VM driver stages the
credential and the CA bundle into the per-sandbox overlay disk instead — the
credential root-only, the CA world-readable, both at fixed `/opt/openshell`
paths and both removed with the sandbox state directory. The consequence,
which differs from the Podman secret model, is that the credential is at rest
inside that overlay image on the gateway host; the per-sandbox gateway JWT
already travels the same path. Proxy reachability differs by VM backend. libkrun-backed
sandboxes egress through gvproxy, so a proxy on the gateway host's loopback is
reachable through the host alias `host.openshell.internal`, which gvproxy NATs
to the host's `127.0.0.1`. QEMU/TAP sandboxes (GPU) have no equivalent: that
alias resolves to the TAP host address, and the driver's nftables `input`
chain accepts only the gateway port from the guest, so no gateway-host proxy
is reachable. The driver rejects a gateway-host proxy URL on the QEMU path at
launch rather than producing CONNECT timeouts. The guest's gateway callback is
unaffected in both backends and never traverses the proxy.

For Kubernetes sandboxes, the operator configures a Secret name and key rather
than a gateway-host file path. Kubernetes projects that Secret only into the
container that runs network supervision. Proxy credential Secrets require the
sidecar topology, which gives them a separate container boundary from the
workload. Combined topology is rejected because Kubernetes `fsGroup` volume
permission handling can make a shared credential mount readable by the sandbox
group.

The Basic header travels over the plain-TCP connection to the `http://` proxy,
so it is readable on the network path between sandbox host and proxy.
Configuring `proxy_auth_file` therefore requires the explicit opt-in
`proxy_auth_allow_insecure = true`. Both the
driver (at sandbox-create time) and the supervisor (at startup) reject an
auth file without the acknowledgement, and the acknowledgement without an
auth file, so credentials are never sent in cleartext without an explicit
operator decision.

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
placeholders for unmanaged rotating credentials and identity-stable opaque
handles for gateway-managed refresh credentials. Provider environment keys
beginning with `v<digits>_` or `s<64 lowercase hex characters>_` are reserved
for those placeholder namespaces.

Provider profiles can also declare dynamic token grants. For matching HTTP
endpoints, the supervisor obtains or exchanges OAuth2 access tokens, caches
them, and injects them before forwarding the request. `client_credentials`
grants use the supervisor SPIFFE JWT-SVID directly as the client assertion.
`token_exchange` grants ask the gateway to broker an intermediate token using a
stored provider subject credential and the gateway's own SPIFFE JWT-SVID; the
supervisor then exchanges that intermediate token for the final upstream token
using its own JWT-SVID. The gateway validates that its own JWT-SVID has the
requested audience, a SPIFFE subject, and a non-expired `exp` claim when
present. It also validates that the stored subject credential is declared by the
provider profile, and that the supervisor JWT-SVID is a well-formed
three-segment JWT with a SPIFFE subject in the same trust domain as the gateway
SVID. The gateway verifies the supervisor JWT-SVID signature with JWT bundles
fetched from its SPIFFE Workload API. Token grant endpoints are HTTPS-only
except for loopback and Kubernetes service DNS hosts, and returned access tokens
must be bearer-compatible before they are cached or injected. Token response
lifetimes are capped and cached with an expiry margin unless a profile supplies
an explicit cache TTL override. Cache entries are scoped by the sandbox provider
environment revision so provider credential updates miss the old token cache
without changing endpoint matching semantics. Gateway-brokered intermediate
tokens are cached separately by provider resource version, supervisor SPIFFE
subject, and gateway SPIFFE subject, and their cache lifetime is capped by the
intermediate token response, stored subject-token expiry, and supervisor SVID
expiry.

For AWS endpoints that require request-level signing, the proxy supports SigV4
re-signing. When `credential_signing: sigv4` is set on an L7 endpoint, the proxy
strips the client's placeholder-based AWS auth headers, re-signs with real
credentials from the provider, and forwards the request upstream. The signing
endpoint must have a credential source before the policy generation activates:
an attached endpoint-bearing AWS profile whose boundary covers the endpoint, or
an attached endpointless AWS profile explicitly named by the endpoint's
`credential_binding.provider`. Policy activation rejects missing or mismatched
sources atomically. The signing mode is auto-detected from the client SDK's
`x-amz-content-sha256` header:

- **Signed body** (hex hash): buffers the request body, computes its SHA-256,
  and includes the hash in the signature. Used by Bedrock and most AWS services.
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

- Attachment to the canonical main process through the `openshell-main` SSH
  subsystem. The supervisor owns its retained PTY or pipes, a 1 MiB replay
  buffer, and a single stdin lease across client disconnects.
- Independent interactive shell sessions.
- Command execution. Commands run through a login shell (`bash -lc`) by default,
  so the first of the user's `.bash_profile`, `.bash_login`, or `.profile` is
  sourced (and `.bashrc` only if that file sources it). Callers set
  `ExecSandboxRequest.no_login_shell` to skip those files; the gateway signals
  this to the supervisor over the SSH `OPENSHELL_NO_LOGIN_SHELL` env request,
  which selects `bash -c` instead of `bash -lc`. Note `bash -c` still reads
  `BASH_ENV` when the child environment sets it.
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

A newer sandbox-scoped revision can carry the same non-empty effective policy
hash as the currently loaded revision, for example when provenance changes
without changing enforcement content. The supervisor acknowledges that newer
revision without reloading identical policy. If the revision also requires
middleware or policy-runtime reconciliation, acknowledgement waits until that
reconciliation succeeds. Global policies, local overrides, equal or older
versions, and different hashes do not use this shortcut. Success telemetry is
emitted only after the gateway accepts the resulting loaded-status report.

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
- If a live policy or middleware-registry update is invalid, the supervisor
  rejects the combined update and keeps the current runtime pair.
- If an operator-run middleware call fails, the selected config's `on_error`
  behavior decides whether to deny the request or continue without that stage.
- Existing raw byte streams are connection scoped. Dynamic policy changes apply
  to new connections or the next parsed HTTP request where the proxy can safely
  re-evaluate.
- If the supervisor relay drops, the sandbox can keep running, but connect and
  exec operations fail until the supervisor registers again.
- If the canonical main process exits, the supervisor durably reports the
  normalized result immediately. A foreground create declares a one-shot main
  attachment, so the supervisor accepts it even after a fast process exits,
  sends the retained output and SSH exit status, waits for the peer's channel
  close, and then finalizes ephemeral cleanup. With no declared or active
  attachment, it finalizes and exits without a grace period. The gateway waits
  for that finalized supervisor session to disconnect before deleting an
  ephemeral sandbox. Exit code 0 records
  `Completed/MainProcessCompleted`; nonzero and signal-normalized exits record
  `Error/MainProcessFailed`. Infrastructure failures also use `Error`, with a
  distinct condition reason and no fabricated canonical-process result. Runtime
  restart policies must not replace the canonical process.
