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

The default policy is the policy applied when you create an OpenShell sandbox without `--policy`. It is baked into the community base image ([`ghcr.io/nvidia/openshell-community/sandboxes/base`](https://github.com/nvidia/openshell-community)) and defined in the community repo's `dev-sandbox-policy.yaml`.

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

The default policy blocks are defined in the community base image. See the [openshell-community repository](https://github.com/nvidia/openshell-community) for the full `dev-sandbox-policy.yaml` source.
