---
title:
  page: "Overview of NVIDIA OpenShell"
  nav: "Overview"
description: "OpenShell is the safe, private runtime for autonomous AI agents. Run agents in sandboxed environments that protect your data, credentials, and infrastructure."
keywords: ["openshell", "ai agent sandbox", "agent security", "agent isolation", "inference routing"]
topics: ["generative_ai", "cybersecurity"]
tags: ["ai_agents", "sandboxing", "security", "privacy", "inference_routing"]
content:
  type: concept
  difficulty: technical_beginner
  audience: [engineer, data_scientist]
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Overview of NVIDIA OpenShell

NVIDIA OpenShell is an open-source runtime for executing autonomous AI agents in sandboxed environments with kernel-level isolation. It combines sandbox runtime controls and a declarative YAML policy so teams can run agents without giving them unrestricted access to local files, credentials, and external networks.

## Why OpenShell Exists

AI agents are most useful when they can read files, install packages, call APIs, and use credentials. That same access can create material risk. OpenShell is designed for this tradeoff: preserve agent capability while enforcing explicit controls over what the agent can access.

## Common Risks and Controls

The table below summarizes common failure modes and how OpenShell mitigates them.

| Threat | Without controls | With OpenShell |
|---|---|---|
| Data exfiltration | Agent uploads source code or internal files to unauthorized endpoints. | Network policies allow only approved destinations; other outbound traffic is denied. |
| Credential theft | Agent reads local secrets such as SSH keys or cloud credentials. | Filesystem restrictions (Landlock) confine access to declared paths only. |
| Unauthorized API usage | Agent sends prompts or data to unapproved model providers. | Privacy routing and network policies control where inference traffic can go. |
| Privilege escalation | Agent attempts `sudo`, setuid paths, or dangerous syscall behavior. | Unprivileged process identity and seccomp restrictions block escalation paths. |

## Protection Layers at a Glance

OpenShell applies defense in depth across four policy domains:

| Layer | What it protects | When it applies |
|---|---|---|
| Filesystem | Prevents reads/writes outside allowed paths. | Locked at sandbox creation. |
| Network | Blocks unauthorized outbound connections. | Hot-reloadable at runtime. |
| Process | Blocks privilege escalation and dangerous syscalls. | Locked at sandbox creation. |
| Inference | Reroutes model API calls to controlled backends. | Hot-reloadable at runtime. |

For details, refer to [Built-in Default Policy](../sandboxes/index.md#built-in-default-policy) and [Customize Sandbox Policies](../sandboxes/policies.md).

## Common Use Cases

- **Secure coding agents**: Run Claude Code, OpenCode, or OpenClaw with constrained file and network access.
- **Private enterprise development**: Route inference to self-hosted or private backends while keeping sensitive context under your control.
- **Compliance and audit**: Treat policy YAML as version-controlled security controls that can be reviewed and audited.
- **Reusable environments**: Use community sandbox images or bring your own containerized runtime.

---

## Next Steps

- [Architecture Overview](architecture.md): Understand the components that make up the OpenShell runtime.
- [Quickstart](get-started.md): Install the CLI and create your first sandbox.
- [Sandboxes](../sandboxes/index.md): Learn how OpenShell enforces isolation across all protection layers.
