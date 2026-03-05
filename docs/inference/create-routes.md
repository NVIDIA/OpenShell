<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Create Inference Routes

Use `nemoclaw inference create` to register a new inference backend that sandboxes can route AI API calls to.

:::{note}
Inference routes are for **userland code** --- scripts and programs that the agent writes and executes inside the sandbox. The agent's own API traffic flows directly through network policies, not through inference routing. See {doc}`../safety-and-privacy/network-access-rules` for the distinction between agent traffic and userland traffic.
:::

## Create a Route

```console
$ nemoclaw inference create \
    --routing-hint local \
    --base-url https://my-llm.example.com \
    --model-id my-model-v1 \
    --api-key sk-abc123
```

This creates a route named after the routing hint. Any sandbox whose policy includes `local` in its `inference.allowed_routes` list can use this route. If you omit `--protocol`, the CLI probes the endpoint and auto-detects the supported protocol (see [Supported API Patterns](index.md#supported-api-patterns)).

## Flags

| Flag | Description |
|------|-------------|
| `--routing-hint` (required) | Name used in sandbox policy to reference this route. |
| `--base-url` (required) | Backend inference endpoint URL. |
| `--model-id` (required) | Model identifier sent to the backend. |
| `--api-key` | API key for the backend endpoint. |
| `--protocol` | Supported protocol(s): `openai_chat_completions`, `openai_completions`, `anthropic_messages` (repeatable, auto-detected if omitted). |
| `--disabled` | Create the route in a disabled state. |

See the [CLI Reference](../reference/cli.md#inference-commands) for the full command specification.

## Good to Know

- **Cluster-level** --- routes are shared across all sandboxes in the cluster, not scoped to one sandbox.
- **Per-model** --- each route maps to one model. Create multiple routes with the same `--routing-hint` but different `--model-id` values to expose multiple models.
- **Hot-reloadable** --- routes can be created, updated, or deleted at any time without restarting sandboxes.

## Next Steps

- {doc}`manage-routes` --- list, update, and delete inference routes.
- {doc}`connect-sandboxes` --- connect a sandbox to inference routes via policy.
- {doc}`index` --- understand the inference routing architecture and interception sequence.
