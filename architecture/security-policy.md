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

## TLS and L7 Inspection

For HTTP endpoints that need request-level controls, the proxy can terminate TLS
with the sandbox's ephemeral CA and inspect method/path or protocol-specific
metadata before forwarding. The proxy also supports credential injection on
terminated HTTP streams when policy allows the endpoint.

Raw streams, HTTP upgrades, and long-lived response bodies are connection
scoped. Policy reloads affect the next connection or the next parsed HTTP
request; they do not rewrite bytes already being relayed.

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
recommendations:

1. The sandbox aggregates denied network events.
2. A mechanistic mapper proposes minimal endpoint, binary, or rule additions.
3. The gateway validates and stores draft recommendations.
4. A human or admin workflow approves or rejects drafts.
5. Approved drafts merge into the target sandbox policy.

The advisor should propose narrow additions and preserve explicit-deny behavior.
It is a workflow aid, not an automatic permission grant.

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
