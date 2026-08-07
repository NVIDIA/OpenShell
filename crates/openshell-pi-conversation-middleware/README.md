# Pi conversation middleware prototype

This crate is a standalone operator gRPC middleware server for the narrow Pi
prototype in `examples/pi-conversation-middleware`.

It implements both `EvaluateAgentConversation` and `EvaluateHttpRequest`. The
agent operation replaces every exact, case-sensitive `sandbox` substring with
`REDACTED` and signs the resulting model/message array. The HTTP operation
denies requests with missing, invalid, expired, or mismatched attestations and
removes the internal attestation header from allowed requests.

Run the service on an address reachable from the gateway and sandbox
supervisors:

```shell
cargo run -p openshell-pi-conversation-middleware -- --listen 0.0.0.0:50061
```

Register it in the gateway TOML before starting the gateway:

```toml
[[openshell.supervisor.middleware]]
name = "pi-conversation-prototype"
grpc_endpoint = "http://host.openshell.internal:50061"
max_body_bytes = 262144
timeout = "5s"
```

The same registered service must be selected as fail-closed network middleware
for the protected provider host. The supervisor prototype bridge is enabled by
setting these variables in the sandbox supervisor environment:

```shell
OPENSHELL_PI_CONVERSATION_MIDDLEWARE=pi-conversation-prototype
OPENSHELL_PI_CONVERSATION_PROVIDER_HOST=api.openai.com
```

The bridge reuses the selected network middleware's validated `config` for hook
evaluation, so signing and egress verification use the same policy revision.

When enabled, the supervisor injects the stable
`OPENSHELL_PI_CONVERSATION_URL=http://127.0.0.1:8193/v1/agent/conversation`
address into the workload environment. Load
`examples/pi-conversation-middleware/pi-extension.ts` as a Pi extension.

## Prototype limitations

- Only OpenAI Chat Completions requests whose messages contain exactly string
  `role` and `content` fields are supported. Images, tool calls, tool results,
  multipart content, and other provider message shapes fail closed. Other
  top-level request options are forwarded but are not attested.
- The Pi adapter requires a non-reasoning `openai-completions` model so Pi emits
  the effective system prompt with the `system` role used by this prototype.
  It checks the serialized provider messages against the signed context and
  fails before dispatch if Pi changes their roles or string content.
- The extension persists sanitized user text through `input` and sanitized
  plain-text assistant output through `message_end`. Pi rebuilds and sanitizes
  the system prompt on each turn. The prototype has not been validated against
  every Pi compaction, retry, steering, or session-fork path.
- `context` replacement is ephemeral in Pi. The persistent hooks are therefore
  part of the prototype, while egress verification remains the final security
  boundary.
- The attestation uses a reserved HTTP header. The supervisor strips it before
  forwarding, but the transport has not been integrated into a native Pi or
  provider API.
- Only the combined supervisor topology is implemented. Kubernetes sidecar
  topology fails startup when this bridge is enabled.
- The deterministic Ed25519 seed is public and forgeable. It exists only to
  make tests reproducible. Production must use operator-controlled secret
  storage, separated signing/verifying material, key rotation, and key IDs.
- Attestations are stateless and short-lived. There is no transcript hash chain,
  server-side conversation state, or replay cache.
- The bridge captures one policy configuration and middleware registry at
  sandbox startup. Hot policy or registration changes can make later requests
  fail closed until the sandbox restarts.
