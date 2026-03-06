<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Inference Routing

The inference routing system keeps your AI inference traffic private by
transparently intercepting API calls from sandboxed agents and rerouting them
to backends you control.

:::{note}
Inference routing applies to userland traffic: code that the agent writes
or runs, not the agent itself. The agent's own API calls (e.g., Claude calling
`api.anthropic.com`) go direct via network policy. See
{doc}`/safety-and-privacy/network-access-rules` for the distinction.
:::

## How It Works

When userland code inside a sandbox makes an API call (e.g., using the OpenAI
or Anthropic SDK), the request flows through the sandbox proxy. If the
destination does not match any explicit network policy but the sandbox has
inference routes configured, the proxy:

1. TLS-terminates the connection using the sandbox's ephemeral CA.
2. Detects the inference API pattern (e.g., `POST /v1/chat/completions`).
3. Strips authorization headers and forwards to a matching backend.
4. Rewrites the authorization with the route's API key and model ID.
5. Returns the response to the agent's code. The agent sees a normal HTTP
   response as if it came from the original API.

The agent's code needs zero changes. Standard OpenAI/Anthropic SDK calls work
transparently.

```{mermaid}
sequenceDiagram
    participant Code as Userland Code
    participant Proxy as Sandbox Proxy
    participant OPA as Policy Engine
    participant Router as Privacy Router
    participant Backend as Your Backend

    Code->>Proxy: CONNECT api.openai.com:443
    Proxy->>OPA: evaluate policy
    OPA-->>Proxy: InspectForInference
    Proxy-->>Code: 200 Connection Established
    Proxy->>Proxy: TLS terminate
    Code->>Proxy: POST /v1/chat/completions
    Proxy->>Router: route to matching backend
    Router->>Backend: forwarded request
    Backend-->>Router: response
    Router-->>Proxy: response
    Proxy-->>Code: HTTP 200 OK
```

## Supported API Patterns

The proxy detects these inference patterns:

| Pattern | Method | Path |
|---|---|---|
| OpenAI Chat Completions | POST | `/v1/chat/completions` |
| OpenAI Completions | POST | `/v1/completions` |
| Anthropic Messages | POST | `/v1/messages` |

If an intercepted request does not match any known pattern, it is denied.

## Key Properties

- Zero code changes: standard SDK calls work transparently.
- Inference privacy: prompts and responses stay on your infrastructure.
- Credential isolation: the agent's code never sees your backend API key.
- Policy-controlled: `inference.allowed_routes` determines which routes a
  sandbox can use.
- Hot-reloadable: update `allowed_routes` on a running sandbox without
  restarting.

## Next Steps

- {doc}`configure-routes`: create and manage inference routes.
- {doc}`/safety-and-privacy/network-access-rules`: understand agent traffic vs.
  userland traffic.
