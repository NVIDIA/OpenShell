<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Environment Variables

Environment variables that configure the NemoClaw CLI and control credential injection into sandboxes.

## CLI Configuration

These variables affect CLI behavior across all commands.

| Variable | Description | Used By |
|---|---|---|
| `NEMOCLAW_CLUSTER` | Name of the cluster to operate on. Overrides the active cluster set by `nemoclaw cluster use`. | All commands that interact with a cluster. |
| `NEMOCLAW_SANDBOX_POLICY` | Default path to a policy YAML file. When set, `nemoclaw sandbox create` uses this policy if no `--policy` flag is provided. | `nemoclaw sandbox create` |

Set these in your shell profile to avoid repeating flags:

```console
$ export NEMOCLAW_CLUSTER=my-remote-cluster
$ export NEMOCLAW_SANDBOX_POLICY=~/policies/default.yaml
```

## Provider Credential Variables

When you create a provider with `--from-existing`, the CLI reads credentials from your shell environment. See {doc}`../sandboxes/providers` for the full list of provider types and the environment variables each one discovers.

### How Discovery Works

The CLI checks each variable in the order listed. If any variable in the set is defined in your shell, its value is captured and stored in the provider. Variables that are unset or empty are skipped.

To verify that a variable is set before creating a provider:

```console
$ echo $ANTHROPIC_API_KEY
```

If the output is empty, export the variable first:

```console
$ export ANTHROPIC_API_KEY=sk-ant-...
$ nemoclaw provider create --name my-claude --type claude --from-existing
```

### What Gets Injected

When a sandbox starts with a provider attached, the supervisor fetches credentials from the gateway and injects them as environment variables into the agent process. For example, a `claude` provider injects both `ANTHROPIC_API_KEY` and `CLAUDE_API_KEY` into the sandbox. See {doc}`../sandboxes/providers` for the full list of variable names per provider type.

These variables are also available in SSH sessions opened with `nemoclaw sandbox connect`.
