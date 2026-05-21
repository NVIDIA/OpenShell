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

The gateway stores policy revisions and exposes effective sandbox configuration.
The supervisor polls for config revisions and attempts to load new dynamic
policy into the in-process OPA engine.

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

1. **Submit.** Both proposers POST through the same `SubmitPolicyAnalysis`
   path. Each chunk is persisted with its `analysis_mode` for audit provenance.
2. **Validate.** The gateway runs the prover (`openshell-prover`) on every
   chunk regardless of mode. The prover builds a Z3 model from the merged
   policy plus the sandbox's attached-provider credential set, then computes
   the delta of findings between the current baseline and the merged policy.
3. **Auto-approval gate (proposer-agnostic).** If the delta is empty
   (`prover: no new findings`), the gateway internally invokes the approve
   path with actor identity `system:auto`. The audit event uses
   `CONFIG:APPROVED` and carries `auto=true`, `source=<mode>`,
   `prover_delta=empty` as unmapped fields, with message text
   `"auto-approved: no new prover findings"` — never `safe`.
4. **Implicit supersede.** On any successful submission, the gateway scans
   the sandbox's pending chunks for matches on `(host, port, binary)` and
   auto-rejects the older ones with reason `"superseded by chunk X"`. This
   gives the agent a refinement path (broad mechanistic L4 → narrow agent
   L7) without an explicit `supersedes_chunk_id` field.
5. **Escalation.** Anything else lands in `pending` for human review.

The v1 prover calibration emits `HIGH` findings (the only severity used) on:

- **Link-local endpoints** (`169.254.0.0/16`, `fe80::/10`), unconditionally
  — covers cloud metadata endpoints (AWS IMDS, GCP metadata) which serve
  credentials and so are dangerous even with no sandbox credential present.
- **L4 grants** to a host where a sandbox credential is in scope.
- **Bypass-L7 binaries** (`git-remote-http`, `ssh`, `nc`) bound to a host
  where a sandbox credential is in scope.

"Credential in scope" is sandbox-coarse, not binary-fine: a credential is
considered in scope if the sandbox has a provider attached whose
`target_hosts` include the proposed endpoint's host. v1 does not model
credential scopes (read-only vs write); presence is enough.

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
