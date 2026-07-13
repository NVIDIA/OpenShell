# Security Policy

OpenShell policy defines what a sandboxed agent can access. The policy is
enforced inside each sandbox by kernel controls, process setup, and the local
policy proxy. The gateway stores and delivers policy, but it does not make
per-request egress decisions.

For the field-by-field YAML reference, use
[Policy Schema Reference](../docs/reference/policy-schema.mdx).

## Policy Areas

| Area | Enforcement |
|---|---|
| Filesystem | Landlock restricts read-only and read-write paths. |
| Process | The supervisor launches the agent as an unprivileged user with reduced capabilities. |
| Network | The proxy evaluates destination, port, calling binary, and optional L7 rules. |
| Inference | `inference.local` is configured through gateway inference settings, not OPA network policy. |
| Runtime settings | Typed settings are delivered with policy and can be global or sandbox scoped. |

Filesystem and process policy are startup-time controls. Network policy is
dynamic and can be hot-reloaded when the new policy validates successfully.

Before applying Landlock, the supervisor enriches baseline filesystem paths that
the runtime needs. Missing baseline paths are skipped so one absent runtime path
does not weaken the whole ruleset. When GPU devices are present, GPU baseline
enrichment adds existing GPU device nodes as read-write paths and promotes
`/proc` to read-write because CUDA workloads write thread metadata under
`/proc/<pid>/task/<tid>/comm`.

## Network Decisions

Ordinary network traffic follows this order:

1. Force traffic through the sandbox proxy with namespace and seccomp controls.
2. Identify the calling binary and compare its trusted identity.
3. Reject hard-blocked destinations, including unsafe internal IP ranges unless
   explicitly allowed.
4. Match the destination and binary against network policy blocks.
5. Apply optional HTTP/L7 rules for endpoints that enable protocol inspection.
6. Allow, deny, audit, or log according to the matched policy.

Explicit deny and hardening checks win over allow rules. If no rule matches, the
request is denied.

## Host Wildcards

Network endpoint `host` patterns accept a `*` wildcard inside the first DNS
label only. The OPA runtime matches with a `.` label boundary, so a wildcard
never spans dots. The validator enforces the same boundary so that policy load
fails fast instead of silently mismatching at the proxy.

| Pattern | Accepted | Example match | Notes |
|---|---|---|---|
| `*.example.com` | Yes | `api.example.com` | Single first label of any value. |
| `**.example.com` | Yes | `a.b.example.com` | Recursive wildcard as the entire first label. |
| `*-aiplatform.googleapis.com` | Yes | `us-central1-aiplatform.googleapis.com` | Intra-label wildcard inside the first DNS label. |
| `*` or `**` | No | — | Matches every host. |
| `*.com`, `**.com` | No | — | TLD wildcards (`labels <= 2`). |
| `foo.*.example.com` | No | — | Wildcard outside the first DNS label. |
| `foo**.example.com` | No | — | Recursive `**` mixed inside a label; allowed only as the entire first label. |

Validation rejects the disallowed patterns at policy load time with a message
that names the offending host. Exact hosts and IP addresses do not use this
path.

## TLS and L7 Inspection

For HTTP endpoints that need request-level controls, the proxy can terminate TLS
with the sandbox's ephemeral CA and inspect method/path or protocol-specific
metadata before forwarding. The proxy also supports credential injection on
terminated HTTP streams when policy allows the endpoint.

Raw streams and long-lived response bodies are connection scoped. Policy
reloads affect the next connection or the next parsed HTTP request; they do not
rewrite bytes already being relayed. HTTP upgrades switch to raw relay by
default. A `protocol: rest` endpoint can opt in to
`websocket_credential_rewrite` for client-to-server WebSocket text messages
after an allowed `101` upgrade; server-to-client traffic and all other upgraded
protocols remain raw passthrough.

## Live Updates

The gateway stores sandbox-authored policy revisions separately from derived
effective sandbox configuration. Effective configuration can include
gateway-global policy overrides and provider-profile policy layers. The
supervisor polls for config revisions and attempts to load new dynamic policy
into the in-process OPA engine; CLI reads of the latest sandbox policy use the
same effective configuration path.

If a new policy fails validation or loading, the supervisor reports the failure
and keeps the last-known-good policy. Static controls, such as filesystem
allowlists and process identity, require a new sandbox because they are applied
before the child process starts.

Gateway-global policy can override sandbox-scoped policy. Use it sparingly
because it changes the effective access model for every sandbox on the gateway.

## Managed Maximum

A gateway can own one optional managed maximum policy. The maximum is a ceiling,
not an active sandbox policy: each sandbox starts with a narrower base policy,
and the gateway proves the fully composed base and provider-derived policy before
creation or any authority-changing update. With no maximum configured, policy
creation, updates, and providers keep their existing unmanaged behavior; accepted
agent proposals remain pending for human review.

The maximum extends the normal policy YAML with an ID, version, allowed/default
`ask` or `auto` modes, and optional `review.required` annotations. The same
admission operation protects sandbox creation, provider attachment, direct policy
updates, and proposal merges. The initial implementation checks filesystem paths
plus L4 and REST network authority. Explicit denies take precedence; other
protocols and unsupported authority fields fail closed. Providers without a
resolvable policy profile also fail closed because their credential-bearing
reach cannot be included in the proof. Managed maximums initially require
single-replica SQLite storage; PostgreSQL/HA needs database-backed coordination
before it can preserve the proof-to-commit boundary across gateway replicas.

The sandbox's selected permission mode is fixed at creation. `ask` holds new
agent-proposed authority for review. `auto` applies only the requested delta that
fits the maximum's auto-eligible region; review-marked authority remains pending.
Authenticated direct edits are approval of that exact edit but remain bounded.
Every merge recomputes the candidate from live policy and provider state before
persistence, so a stored proposal or approval is evidence rather than authority.

## Policy Advisor

The policy advisor pipeline turns observed denials into draft policy
recommendations. There are two proposers (sandbox-side mechanistic mapper,
agent-authored via `policy.local`); the gateway is the single referee.
When enabled, L7 `policy_denied` responses include both structured
`next_steps` and a short `agent_guidance` string so generic agents can continue
through the proposal loop instead of treating the denial as terminal.

1. **Submit.** Both proposers POST through the same `SubmitPolicyAnalysis`
   path. Each chunk is persisted with its `analysis_mode` for audit provenance.
2. **Validate.** The gateway rejects always-blocked targets and merges each
   chunk into the live base policy. If a managed maximum exists, the same
   managed-admission operation used by creation, provider attachment, and
   direct policy updates returns `apply`, `ask`, or `reject`.
3. **Decide.** Without a managed maximum, every accepted proposal remains
   pending. Managed `ask` also holds all in-boundary proposals. Managed `auto`
   applies only the requested delta inside the maximum's auto-eligible view;
   review-marked authority remains pending and outside or unsupported authority
   is rejected. Automatic application emits `CONFIG:APPROVED` with
   `auto=true`, `source=<mode>`, and `approval_basis=managed_maximum`.
4. **Implicit supersede.** On any successful submission, the gateway scans
   the sandbox's pending chunks for matches on `(host, port, binary)` and
   auto-rejects the older ones with reason `"superseded by chunk X"`. This
   gives the agent a refinement path (broad mechanistic L4 → narrow agent
   L7) without an explicit `supersedes_chunk_id` field.
5. **Revalidate and merge.** Automatic and human-approved proposals are
   checked again against live policy and provider state before persistence.
   Stored decisions are audit evidence, not reusable authority.

## Credentialed Raw-L4 Advisory

For each proposal, the gateway checks whether a raw L4 endpoint overlaps a
host targeted by an attached provider credential. Host overlap includes
first-label wildcard coverage such as `*.github.com` covering
`api.github.com`. A match adds a deterministic advisory containing the binary,
host, and port. The warning states that raw stream authority cannot be bounded
by an HTTP method or path.

The advisory is deliberately non-gating. It does not return `apply`, `ask`, or
`reject`, and it cannot override managed admission. This keeps the security
contract singular: the managed maximum decides authority, while the advisory
helps the policy author prefer L7 or consciously accept opaque L4 access.

Loopback, link-local, unspecified, and known metadata targets are enforced as
always-blocked network invariants and are rejected during proposal validation.
Capability and credential-reach expansion are represented by the candidate
policy and therefore bounded by managed-maximum containment rather than a
second proposal-specific finding model.

Proposals intentionally omit `allowed_ips`. If a proposed rule targets a host
that resolves to a private IP, the proxy's runtime SSRF classification blocks
the connection. The operator must then add an explicit `allowed_ips` entry to
permit it — a two-step flow that keeps SSRF protection on by default.

The advisor proposes narrow additions and preserves explicit-deny behavior.
Managed containment remains deterministic; contextual review can be added as
an advisory layer without becoming another authority boundary.

## Security Logging

Sandbox events that represent observable behavior use OCSF structured logs:

| Event | OCSF class |
|---|---|
| Network and proxy decisions | Network or HTTP activity |
| SSH authentication and relay activity | SSH activity |
| Process lifecycle | Process activity |
| Policy and settings changes | Configuration state change |
| Security findings | Detection finding |

Use plain tracing for internal plumbing such as retries, debug state, and
intermediate steps where the final observable event is logged separately.

Never log secrets, credentials, bearer tokens, or query parameters in OCSF
messages. OCSF JSONL output may be shipped to external systems.
