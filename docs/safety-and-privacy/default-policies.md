<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Built-in Default Policy

NVIDIA OpenShell ships a built-in policy that covers common agent workflows out of the box. When you create a sandbox without `--policy`, this policy is applied automatically.

## Agent Compatibility

| Agent | Coverage | Action Required |
|---|---|---|
| Claude Code | Full | None. Works out of the box. |
| OpenCode | Partial | Add `opencode.ai` endpoint and OpenCode binary paths. See [Run OpenCode with NVIDIA Inference](../get-started/run-opencode.md). |
| Codex | None | Provide a complete custom policy with OpenAI endpoints and Codex binary paths. |

:::{important}
If you run a non-Claude agent without a custom policy, the agent's API calls are denied by the proxy. You must provide a policy that declares the agent's endpoints and binaries.
:::

## What the Default Policy Allows

The default policy defines six network policy blocks, filesystem isolation, Landlock enforcement, and process identity. To view the default policy, check the [`deploy/docker/sandbox/dev-sandbox-policy.yaml`](https://github.com/NVIDIA/NemoClaw/blob/main/deploy/docker/sandbox/dev-sandbox-policy.yaml) file.

<!-- On hold until devs confirm this is the correct policy 

The tables below are generated from [`deploy/docker/sandbox/dev-sandbox-policy.yaml`](https://github.com/NVIDIA/NemoClaw/blob/main/deploy/docker/sandbox/dev-sandbox-policy.yaml).

```{policy-table} deploy/docker/sandbox/dev-sandbox-policy.yaml
```
-->

## Next Steps

- {doc}`policies`: Write custom policies, configure network rules, and iterate on a running sandbox.
- [Policy Schema Reference](../reference/policy-schema.md): Complete field reference for the policy YAML.
