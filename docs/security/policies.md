<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Policies

Sandbox policies are YAML documents that define what an agent can do. Every sandbox has a policy — either the built-in default or a custom one provided at creation time.

## Using Policies

### Create a Sandbox with a Custom Policy

```console
$ nemoclaw sandbox create --policy ./my-policy.yaml --keep -- claude
```

### Set a Default Policy via Environment Variable

```console
$ export NEMOCLAW_SANDBOX_POLICY=./my-policy.yaml
$ nemoclaw sandbox create -- claude
```

## Policy Structure

A policy has four top-level sections:

```yaml
filesystem_policy:
  read_only:
    - /usr
    - /etc
  read_write:
    - /sandbox
    - /tmp

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  github:
    endpoints:
      - host: github.com
        port: 443
      - host: api.github.com
        port: 443
    binaries:
      - path_patterns: ["**/git"]
      - path_patterns: ["**/ssh"]

inference:
  allowed_routes:
    - local
```

### `filesystem_policy` (Static)

Controls which directories the agent can access. Enforced by the Linux Landlock LSM.

| Field | Description |
|-------|-------------|
| `read_only` | List of paths the agent can read but not write. |
| `read_write` | List of paths the agent can read and write. Directories are created and chowned automatically. |

### `landlock` (Static)

| Field | Description |
|-------|-------------|
| `compatibility` | `best_effort` (default) — use the best available Landlock ABI. `hard_requirement` — fail if the required ABI is not available. |

### `process` (Static)

| Field | Description |
|-------|-------------|
| `run_as_user` | Username or UID the agent runs as. |
| `run_as_group` | Group name or GID the agent runs as. |

### `network_policies` (Dynamic)

A map of named network policy entries. Each entry defines which endpoints a set of binaries can reach. See [Network Access Control](network-access.md) for the full specification.

### `inference` (Dynamic)

| Field | Description |
|-------|-------------|
| `allowed_routes` | List of routing hint names that this sandbox can use for inference. Routes are created separately via `nemoclaw inference create`. |

## Live Policy Updates

Dynamic fields (`network_policies` and `inference`) can be updated on a running sandbox without restarting it.

### The Policy Iteration Loop

```
Create sandbox with initial policy
        │
        ▼
   Monitor logs ◄──────────────────┐
        │                          │
        ▼                          │
  Observe denied actions           │
        │                          │
        ▼                          │
  Pull current policy              │
        │                          │
        ▼                          │
  Modify policy YAML               │
        │                          │
        ▼                          │
  Push updated policy              │
        │                          │
        ▼                          │
  Verify reload succeeded ─────────┘
```

### Step 1: Monitor logs for denied actions

```console
$ nemoclaw sandbox logs my-sandbox --tail --source sandbox
```

Look for `action: deny` log lines — these show the destination host/port, the binary that attempted the connection, and the denial reason.

### Step 2: Pull the current policy

```console
$ nemoclaw sandbox policy get my-sandbox --full > current-policy.yaml
```

The `--full` flag outputs valid YAML that can be directly re-submitted.

### Step 3: Modify and push the updated policy

Edit `current-policy.yaml`, then:

```console
$ nemoclaw sandbox policy set my-sandbox --policy current-policy.yaml --wait
```

The `--wait` flag blocks until the sandbox confirms the policy is loaded. Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Policy loaded successfully. |
| 1 | Policy load failed. |
| 124 | Timeout (default: 60 seconds). |

### Step 4: Verify

```console
$ nemoclaw sandbox policy list my-sandbox
```

Check that the latest revision shows status `loaded`.

## Policy Revision History

Each policy update creates a new revision. View the history:

```console
$ nemoclaw sandbox policy list my-sandbox --limit 50
```

Fetch a specific historical revision:

```console
$ nemoclaw sandbox policy get my-sandbox --rev 3 --full
```

### Revision Statuses

| Status | Meaning |
|--------|---------|
| `pending` | Accepted by the server; not yet loaded by the sandbox. |
| `loaded` | Successfully applied by the sandbox. |
| `failed` | Sandbox attempted to load but validation failed; previous policy remains active. |
| `superseded` | A newer revision was submitted before the sandbox loaded this one. |

## Last-Known-Good Behavior

If a new policy version fails validation, the sandbox keeps the previous (last-known-good) policy active. This provides safe rollback semantics — a bad policy push does not break a running sandbox.

## Idempotent Updates

Submitting the same policy content again does not create a new revision. The CLI detects this and prints "Policy unchanged."
