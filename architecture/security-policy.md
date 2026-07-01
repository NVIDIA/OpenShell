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
label and as an entire middle DNS label. The OPA runtime matches with a `.`
label boundary, so a wildcard never spans dots. The validator enforces the same
boundary so that policy load fails fast instead of silently mismatching at the
proxy.

| Pattern | Accepted | Example match | Notes |
|---|---|---|---|
| `*.example.com` | Yes | `api.example.com` | Single first label of any value. |
| `**.example.com` | Yes | `a.b.example.com` | Recursive wildcard as the entire first label. |
| `*-aiplatform.googleapis.com` | Yes | `us-central1-aiplatform.googleapis.com` | Intra-label wildcard inside the first DNS label. |
| `*.s3.*.amazonaws.com` | Yes | `bucket.s3.us-east-1.amazonaws.com` | Middle-label `*` matches exactly one DNS label. |
| `*` or `**` | No | — | Matches every host. |
| `*.com`, `**.com` | No | — | TLD wildcards (`labels <= 2`). |
| `foo.us-*.example.com` | No | — | Partial middle-label wildcards are not allowed. |
| `foo.**.example.com` | No | — | Recursive wildcard outside the first label is not allowed. |
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

## Policy Advisor

The policy advisor pipeline turns observed denials into draft policy
recommendations. There are two proposers (sandbox-side mechanistic mapper,
agent-authored via `policy.local`); the gateway is the single referee.
When enabled, L7 `policy_denied` responses include both structured
`next_steps` and a short `agent_guidance` string so generic agents can continue
through the proposal loop instead of treating the denial as terminal.

1. **Submit.** Both proposers POST through the same `SubmitPolicyAnalysis`
   path. Each chunk is persisted with its `analysis_mode` for audit provenance.
2. **Validate.** The gateway runs the prover (`openshell-prover`) on every
   chunk regardless of mode. The prover builds a Z3 model from the merged
   policy plus the sandbox's attached-provider credential set, then computes
   the delta of findings between the current baseline and the merged policy.
3. **Auto-approval gate (proposer-agnostic, opt-in).** Auto-approval fires
   when *both* (a) the prover delta is empty (`prover: no new findings`) AND
   (b) the `proposal_approval_mode` setting resolves to `"auto"` — gateway
   scope wins, sandbox scope is the per-sandbox override, default is
   `"manual"`. When both hold, the gateway internally invokes the approve
   path with actor identity `system:auto`. The audit event uses
   `CONFIG:APPROVED` and carries `auto=true`, `source=<mode>`,
   `prover_delta=empty`, and `resolved_from=<gateway|sandbox>` as unmapped
   fields, with message text `"auto-approved: no new prover findings"` —
   never `safe`. The opt-in gate preserves OpenShell's default-deny
   posture: with no setting at either scope, every proposal lands in
   `pending` for human review, even when the prover sees no findings.
4. **Implicit supersede.** On any successful submission, the gateway scans
   the sandbox's pending chunks for matches on `(host, port, binary)` and
   auto-rejects the older ones with reason `"superseded by chunk X"`. This
   gives the agent a refinement path (broad mechanistic L4 → narrow agent
   L7) without an explicit `supersedes_chunk_id` field.
5. **Escalation.** Anything else lands in `pending` for human review.

## What the prover decides

The prover answers four formal questions about each proposed policy
change. Each "yes" answer becomes its own categorical finding — there is
no severity grade. Any finding (of any category) blocks auto-approval.
The categories are intended to be (mostly) mutually exclusive per
underlying change: the gateway suppresses `capability_expansion` paths
whose `(binary, host, port)` is also in the `credential_reach_expansion`
delta, so a brand-new credentialed reach surfaces as one finding rather
than one reach + N method findings.

| Category | The prover detects… |
|---|---|
| `link_local_reach` | The proposal grants reach to a host in `169.254.0.0/16`, `fe80::/10`, or a known metadata hostname such as `metadata.google.internal`. Unconditional — cloud-metadata endpoints serve credentials regardless of sandbox state. |
| `l7_bypass_credentialed` | The proposal lets a binary using a non-HTTP wire protocol (`git-remote-https`, `ssh`, `nc`) reach a host where a sandbox credential is in scope. The L7 proxy cannot inspect the wire protocol; the reviewer decides whether to trust the binary with the credential. |
| `credential_reach_expansion` | A binary gained credentialed reach to a (host, port) it could not reach before. New authenticated reach is a stated intent change; the reviewer confirms the binary should authenticate to the host at all. |
| `capability_expansion` | On a (binary, host, port) that already had credentialed reach, the policy adds a new HTTP method. The reviewer sees exactly which method was added (e.g., PUT) and decides if it's part of the agent's task. |

"Credential in scope" is sandbox-coarse, not binary-fine: a credential is
considered in scope if the sandbox has a provider attached whose
`target_hosts` include the proposed endpoint's host, including runtime-like
first-label wildcard coverage such as `*.github.com` covering
`api.github.com`. v1 does not model credential scopes (read-only vs write);
presence is enough.

Proposals intentionally omit `allowed_ips`. If a proposed rule targets a host
that resolves to a private IP, the proxy's runtime SSRF classification blocks
the connection. The operator must then add an explicit `allowed_ips` entry to
permit it — a two-step flow that keeps SSRF protection on by default.

The advisor proposes narrow additions and preserves explicit-deny behavior.
Auto-approval is gated on prover determinism, not human judgment; an LLM-based
contextual reviewer is a deliberate future addition layered on top of the
deterministic prover gate.

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
