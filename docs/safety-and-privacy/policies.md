<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Write Sandbox Policies

This guide covers how to author, iterate, and manage sandbox policies that control what an agent can do inside a NemoClaw sandbox. You will learn to create sandboxes with custom policies, monitor denied traffic to discover missing rules, and push policy updates without restarting the sandbox.

## Policy Structure

A policy is a YAML document with five sections. Static fields (`filesystem_policy`, `landlock`, `process`) are locked at sandbox creation and require recreation to change. Dynamic fields (`network_policies`, `inference`) are hot-reloadable on a running sandbox.

```yaml
version: 1

# --- STATIC FIELDS (require sandbox recreation to change) ---

filesystem_policy:
  # Directories the agent can read but not modify.
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /etc
    - /var/log
  # Directories the agent can read and write.
  read_write:
    - /sandbox       # the agent's working directory
    - /tmp
    - /dev/null

landlock:
  # How NemoClaw applies Landlock LSM enforcement.
  # "best_effort" uses the highest Landlock ABI the host kernel supports.
  # "strict" requires a specific ABI version and fails if unavailable.
  compatibility: best_effort

process:
  # The OS user and group the agent process runs as inside the sandbox.
  # "sandbox" is a non-root user created in the container image.
  run_as_user: sandbox
  run_as_group: sandbox

# --- DYNAMIC FIELDS (hot-reloadable on a running sandbox) ---

network_policies:
  # Each key is a logical name for a set of allowed connections.
  claude_api:
    endpoints:
      - host: api.anthropic.com
        port: 443
        protocol: rest       # enables L7 (HTTP) inspection
        tls: terminate        # proxy decrypts TLS to inspect traffic
        enforcement: enforce  # actively enforce access rules
        access: full          # allow all HTTP methods and paths
    binaries:
      # Only these binaries may connect to the endpoints above.
      - path: /usr/local/bin/claude
      - path: /usr/bin/node

inference:
  # Which inference route types userland code is allowed to use.
  allowed_routes:
    - local
```

Refer to the [Policy Schema Reference](../reference/policy-schema.md) for every field, type, and default value.

## Default Policy

NemoClaw ships a built-in default policy designed for Claude Code. It covers Claude's API endpoints, telemetry hosts, GitHub access, and VS Code marketplace traffic out of the box.

| Agent | Default policy coverage | What you need to do |
|---|---|---|
| Claude Code | Full | Nothing: works out of the box |
| opencode | Partial | Add `opencode.ai` endpoint and opencode binary paths. |
| Codex | None | Provide a complete custom policy with OpenAI endpoints and Codex binary paths. |

:::{important}
If you run a non-Claude agent without a custom policy, the agent's API calls will be denied by the proxy. You must provide a policy that declares the agent's endpoints and binaries.
:::

## Create a Sandbox with a Custom Policy

Pass a policy YAML file when creating the sandbox:

```console
$ nemoclaw sandbox create --policy ./my-policy.yaml --keep -- claude
```

The `--keep` flag keeps the sandbox running after the initial command exits, which is useful when you plan to iterate on the policy.

To avoid passing `--policy` every time, set a default policy by using environment variable:

```console
$ export NEMOCLAW_SANDBOX_POLICY=./my-policy.yaml
$ nemoclaw sandbox create --keep -- claude
```

The CLI uses the policy from `NEMOCLAW_SANDBOX_POLICY` whenever `--policy` is not explicitly provided.

## The Policy Iteration Loop

Policy authoring is an iterative process. You start with a minimal policy, observe what the agent needs, and refine the rules until everything works. This is the core workflow:

```{mermaid}
flowchart TD
    A["1. Create sandbox with initial policy"] --> B["2. Monitor logs for denied actions"]
    B --> C["3. Pull current policy"]
    C --> D["4. Modify the policy YAML"]
    D --> E["5. Push updated policy"]
    E --> F["6. Verify the new revision loaded"]
    F --> B
```

### Step 1: Create the Sandbox with Your Initial Policy

```console
$ nemoclaw sandbox create --policy ./my-policy.yaml --keep -- claude
```

### Step 2: Monitor Logs for Denied Actions

In a second terminal, tail the sandbox logs and look for `action: deny` entries:

```console
$ nemoclaw sandbox logs <name> --tail --source sandbox
```

Each deny entry shows the blocked host, port, calling binary, and reason. This tells you exactly what the agent tried to reach and why it was blocked.

Alternatively, run `nemoclaw term` for the NemoClaw Terminal, a live dashboard
that shows status and logs in a single view. See {doc}`/sandboxes/terminal` for
how to read log entries and diagnose what's being blocked.

:::{tip}
The NemoClaw Terminal is especially useful during policy iteration. You can
watch deny entries appear in real time as the agent hits blocked endpoints, then
push an updated policy without leaving the terminal.
:::

### Step 3: Pull the Current Policy

Export the running policy to a file:

```console
$ nemoclaw sandbox policy get <name> --full > current-policy.yaml
```

:::{warning}
The `--full` output includes a metadata header with `Version`, `Hash`, and `Status` lines that are not valid YAML. Strip these lines before re-submitting the file as a policy update, or the push will fail.
:::

### Step 4: Modify the Policy YAML

Edit `current-policy.yaml` to address the denied actions you observed. Common changes include:

- Adding endpoints to `network_policies` entries
- Adding binary paths to existing endpoint rules
- Creating new named policy entries for new destinations
- Adjusting `access` levels or adding custom `rules`
- Updating `inference.allowed_routes`

### Step 5: Push the Updated Policy

```console
$ nemoclaw sandbox policy set <name> --policy current-policy.yaml --wait
```

The `--wait` flag blocks until the policy engine processes the update. Exit codes:

| Exit code | Meaning |
|-----------|---------|
| `0`       | Policy loaded successfully |
| `1`       | Policy failed validation |
| `124`     | Timed out waiting for the policy engine |

### Step 6: Verify the New Revision Loaded

```console
$ nemoclaw sandbox policy list <name>
```

Check that the latest revision shows status `loaded`. If it shows `failed`, review the error message and go back to Step 4.

### Step 7: Repeat

Return to Step 2. Monitor logs, observe new denied actions (or confirm everything works), and refine the policy until the agent operates correctly within the rules you have set.

## Policy Revision History

Every `policy set` creates a new revision. You can inspect the full revision history:

```console
$ nemoclaw sandbox policy list <name> --limit 50
```

To retrieve a specific revision:

```console
$ nemoclaw sandbox policy get <name> --rev 3 --full
```

### Revision Statuses

| Status       | Meaning |
|--------------|---------|
| `pending`    | The revision has been submitted and is awaiting processing by the policy engine. |
| `loaded`     | The revision passed validation and is the active policy for the sandbox. |
| `failed`     | The revision failed validation. The previous good revision remains active. |
| `superseded` | A newer revision has been loaded, replacing this one. |

## Policy Validation

The server validates every policy at creation and update time. Policies that violate any of the following rules are rejected with exit code `1` (`INVALID_ARGUMENT`):

| Rule | Description |
|---|---|
| No root identity | `run_as_user` and `run_as_group` cannot be `root` or `0`. |
| Absolute paths only | All filesystem paths must start with `/`. |
| No path traversal | Filesystem paths must not contain `..` components. |
| No overly broad writes | Read-write paths like `/` alone are rejected. |
| Path length limit | Each path must not exceed 4096 characters. |
| Path count limit | The combined total of `read_only` and `read_write` paths must not exceed 256. |

When a disk-loaded YAML policy (via `--policy` or `NEMOCLAW_SANDBOX_POLICY`) fails validation, the sandbox falls back to a restrictive default policy rather than starting with an unsafe configuration.

Refer to the [Policy Schema Reference](../reference/policy-schema.md) for the constraints documented alongside each field.

## Safety Properties

**Last-known-good.**
If a new policy revision fails validation, the previous successfully loaded policy stays active. A bad push does not break a running sandbox. The agent continues operating under the last good policy.

**Idempotent.**
Submitting the same policy content again does not create a new revision. The CLI detects that the content has not changed and returns without modifying the revision history.

## Next Steps

- [Network Access Rules](network-access-rules.md): How the proxy evaluates connections, endpoint allowlists, binary matching, and enforcement modes.
- {doc}`../reference/policy-schema`: Complete field reference for the policy YAML.
