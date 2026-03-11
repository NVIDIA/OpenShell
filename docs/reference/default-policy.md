---
title:
  page: "Default Policy Reference"
  nav: "Default Policy"
description: "Breakdown of the built-in default policy applied when you create an OpenShell sandbox without a custom policy."
keywords: ["openshell default policy", "sandbox policy", "agent compatibility"]
topics: ["generative_ai", "cybersecurity"]
tags: ["ai_agents", "sandboxing", "security", "policy"]
content:
  type: reference
  difficulty: technical_beginner
  audience: [engineer, data_scientist]
---

# Default Policy Reference

The default policy is the policy applied when you create an OpenShell sandbox without `--policy`. It is defined in the [`deploy/docker/sandbox/dev-sandbox-policy.yaml`](https://github.com/NVIDIA/OpenShell/blob/main/deploy/docker/sandbox/dev-sandbox-policy.yaml) file.

## Agent Compatibility

The following table shows the coverage of the default policy for common agents.

| Agent | Coverage | Action Required |
|---|---|---|
| Claude Code | Full | None. Works out of the box. |
| OpenCode | Partial | Add `opencode.ai` endpoint and OpenCode binary paths. |
| Codex | None | Provide a complete custom policy with OpenAI endpoints and Codex binary paths. |

:::{important}
If you run a non-Claude agent without a custom policy, the agent's API calls are denied by the proxy. You must provide a policy that declares the agent's endpoints and binaries.
:::

## Default Policy Blocks

The following tables show the default policy blocks pre-configured in the file.

```{policy-table} deploy/docker/sandbox/dev-sandbox-policy.yaml
```
