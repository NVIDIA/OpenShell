<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Configure Inference Routes

This guide covers how to create and manage inference routes so that sandboxes can route AI API calls from userland code to policy-controlled backends. You will learn to create routes, connect them to sandboxes via policy, and manage routes across a cluster.

:::{note}
Inference routes are for *userland code*, which are scripts and programs that the agent writes and executes inside the sandbox. The agent's own API traffic flows directly through network policies, not through inference routing. See {doc}`../safety-and-privacy/network-access-rules` for the distinction between agent traffic and userland traffic.
:::

## Create a Route

Use `nemoclaw inference create` to register a new inference backend:

```console
$ nemoclaw inference create \
    --routing-hint local \
    --base-url https://my-llm.example.com \
    --model-id my-model-v1 \
    --api-key sk-abc123
```

This creates a route named after the routing hint. Any sandbox whose policy includes `local` in its `inference.allowed_routes` list can use this route. If you omit `--protocol`, the CLI probes the endpoint and auto-detects the supported protocol (see [Supported API Patterns](index.md#supported-api-patterns)). See the [CLI Reference](../reference/cli.md#inference-create-flags) for all flags.

## Manage Routes

### List all routes

```console
$ nemoclaw inference list
```

### Update a route

Change any field on an existing route:

```console
$ nemoclaw inference update <name> --base-url https://new-backend.example.com
```

```console
$ nemoclaw inference update <name> --model-id updated-model-v2 --api-key sk-new-key
```

### Delete a route

```console
$ nemoclaw inference delete <name>
```

Deleting a route that is referenced by running sandboxes does not interrupt those sandboxes immediately. Future inference requests that would have matched the deleted route will be denied.

## Connect a Sandbox to Routes

Inference routes take effect only when a sandbox policy references the route's `routing_hint` in its `inference.allowed_routes` list.

### Step 1: Add the routing hint to your policy

```yaml
inference:
  allowed_routes:
    - local
```

### Step 2: Create or update the sandbox with that policy

```console
$ nemoclaw sandbox create --policy ./my-policy.yaml --keep -- claude
```

Or, if the sandbox is already running, push an updated policy:

```console
$ nemoclaw sandbox policy set <name> --policy ./my-policy.yaml --wait
```

The `inference` section is a dynamic field, so you can add or remove routing hints on a running sandbox without recreating it.

## Good to Know

- Cluster-level: routes are shared across all sandboxes in the cluster, not scoped to one sandbox.
- Per-model: each route maps to one model. Create multiple routes with the same `--routing-hint` but different `--model-id` values to expose multiple models.
- Hot-reloadable: routes can be created, updated, or deleted at any time without restarting sandboxes.

## Next Steps

- {doc}`index`: understand the inference routing architecture, interception sequence, and routing hints.
- {doc}`../safety-and-privacy/network-access-rules`: configure the network policies that control agent traffic (as opposed to userland inference traffic).
- {doc}`../safety-and-privacy/policies`: the full policy iteration workflow.
