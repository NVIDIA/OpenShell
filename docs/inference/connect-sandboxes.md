<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Connect Sandboxes to Inference Routes

Inference routes take effect only when a sandbox policy references the route's `routing_hint` in its `inference.allowed_routes` list. This page shows how to wire them together.

## Step 1: Add the Routing Hint to Your Policy

In your policy YAML, include the routing hint that matches the route you created:

```yaml
inference:
  allowed_routes:
    - local
```

## Step 2: Create or Update the Sandbox with That Policy

When creating a new sandbox:

```console
$ nemoclaw sandbox create --policy ./my-policy.yaml --keep -- claude
```

Or, if the sandbox is already running, push an updated policy:

```console
$ nemoclaw sandbox policy set <name> --policy ./my-policy.yaml --wait
```

The `inference` section is a dynamic field, so you can add or remove routing hints on a running sandbox without recreating it.

## How It Works

Once a sandbox has `allowed_routes` configured, the proxy intercepts outbound connections that do not match any explicit `network_policies` entry. If the request matches a known inference API pattern (e.g., `POST /v1/chat/completions`), the proxy:

1. TLS-terminates the connection.
2. Strips the original authorization header.
3. Selects a route whose `routing_hint` appears in the sandbox's `allowed_routes`.
4. Injects the route's API key and model ID.
5. Forwards the request to the route's backend.

The agent's code sees a normal HTTP response as if it came from the original API.

:::{tip}
To avoid passing `--policy` every time, set a default policy via environment variable:

```console
$ export NEMOCLAW_SANDBOX_POLICY=./my-policy.yaml
$ nemoclaw sandbox create --keep -- claude
```
:::

## Next Steps

- {doc}`create-routes` --- register new inference backends.
- {doc}`manage-routes` --- list, update, and delete routes.
- [Policies](../safety-and-privacy/policies.md) --- the full policy iteration workflow.
- [Network Access Control](../safety-and-privacy/network-access-rules.md) --- how agent traffic differs from userland inference traffic.
