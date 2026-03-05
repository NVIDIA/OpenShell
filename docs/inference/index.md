<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Inference Routing

The inference routing system keeps your AI inference traffic private by transparently intercepting API calls from sandboxed agents and rerouting them to policy-controlled backends. This enables organizations to keep sensitive prompts and model responses on private infrastructure — redirecting traffic to local or self-hosted models without modifying the agent's code.

## How It Works

When an agent inside a sandbox makes an API call (e.g., using the OpenAI or Anthropic SDK), the request flows through the sandbox proxy. If the destination does not match any explicit network policy but the sandbox has inference routes configured, the proxy:

1. **TLS-terminates** the connection using the sandbox's ephemeral CA.
2. **Detects the inference API pattern** (e.g., `POST /v1/chat/completions` for OpenAI, `POST /v1/messages` for Anthropic).
3. **Strips authorization headers** and forwards the request to a matching backend.
4. **Rewrites the authorization** with the route's API key and injects the correct model ID.
5. **Returns the response** to the agent — the agent sees a normal HTTP response as if it came from the original API.

Agents need zero code changes. Standard OpenAI/Anthropic SDK calls work transparently.

```{mermaid}
sequenceDiagram
    participant Agent as Sandboxed Agent
    participant Proxy as Sandbox Proxy
    participant OPA as OPA Engine
    participant Router as Local Router
    participant Backend as Backend (e.g., LM Studio)

    Agent->>Proxy: CONNECT api.openai.com:443
    Proxy->>OPA: evaluate_network_action(input)
    OPA-->>Proxy: InspectForInference
    Proxy-->>Agent: 200 Connection Established
    Proxy->>Proxy: TLS terminate (ephemeral CA)
    Agent->>Proxy: POST /v1/chat/completions
    Proxy->>Proxy: detect_inference_pattern()
    Proxy->>Router: route to matching backend
    Router->>Backend: POST /v1/chat/completions
    Backend-->>Router: 200 OK
    Router-->>Proxy: response
    Proxy-->>Agent: HTTP 200 OK (re-encrypted)
```

## Working with Inference Routes

- {doc}`create-routes` --- register a new inference backend with `nemoclaw inference create`.
- {doc}`manage-routes` --- list, update, and delete inference routes.
- {doc}`connect-sandboxes` --- connect a sandbox to inference routes via policy.

## Key Design Properties

- **Zero agent code changes** — standard SDK calls work transparently.
- **Inference privacy** — prompts and responses stay on your infrastructure when routed to local backends.
- **Credential isolation** — the sandbox never sees the real API key for the backend, protecting your credentials.
- **Policy-controlled** — `inference.allowed_routes` determines which routes a sandbox can use.
- **Hot-reloadable** — the `inference` policy field is dynamic and can be updated on a running sandbox.
- **Automatic cache refresh** — in cluster mode, the sandbox refreshes its route cache from the gateway every 30 seconds.

## Supported API Patterns

The proxy detects these inference API patterns:

| Pattern | Method | Path |
|---------|--------|------|
| `openai_chat_completions` | POST | `/v1/chat/completions` |
| `openai_completions` | POST | `/v1/completions` |
| `anthropic_messages` | POST | `/v1/messages` |

If an intercepted request does not match any known pattern, it is denied with a descriptive error.
