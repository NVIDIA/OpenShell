<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Manage Inference Routes

List, update, and delete inference routes across your cluster.

## List All Routes

```console
$ nemoclaw inference list
```

## Update a Route

Change any field on an existing route:

```console
$ nemoclaw inference update <name> --base-url https://new-backend.example.com
```

```console
$ nemoclaw inference update <name> --model-id updated-model-v2 --api-key sk-new-key
```

## Delete a Route

```console
$ nemoclaw inference delete <name>
```

Deleting a route that is referenced by running sandboxes does not interrupt those sandboxes immediately. Future inference requests that would have matched the deleted route will be denied.

## Behavior Notes

- Routes are **cluster-level** --- they are shared across all sandboxes in the cluster, not scoped to one sandbox.
- Each route maps to **one model**. Create multiple routes with the same `--routing-hint` but different `--model-id` values to expose multiple models.
- Route changes are **hot-reloadable** --- sandboxes pick up new, updated, or deleted routes without restarting.

## Next Steps

- {doc}`create-routes` --- register a new inference backend.
- {doc}`connect-sandboxes` --- connect a sandbox to inference routes via policy.
- [CLI Reference](../reference/cli.md#inference-commands) --- full command specification for all inference commands.
