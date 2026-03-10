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

NVIDIA OpenShell is an open-source runtime that executes autonomous AI agents inside sandboxed environments with kernel-level isolation. It prevents agents from accessing unauthorized files, exfiltrating data, leaking credentials, or making uncontrolled network requests. A single declarative YAML policy governs filesystem, network, process, and inference protections across all sandboxes and is hot-reloadable without restarting running agents.

## Common Challenges with AI Agents

AI agents are most useful when they have broad access to reading files, installing packages, calling APIs, and using credentials. However, this same access makes them dangerous. An unrestricted agent can leak your API keys, send proprietary code to unauthorized endpoints, or reach infrastructure it was never meant to touch.

Conventional containers do not solve this. They isolate processes from the host, but they do not control what an agent does *inside* the container — which files it reads, which hosts it contacts, or where it sends your prompts.

## Benefits of Using OpenShell

OpenShell addresses these risks through defense-in-depth enforcement across four policy domains: filesystem, network, process, and inference.

:::{dropdown} 🛡️ Kernel-Level Isolation
OpenShell enforces isolation at the Linux kernel level using Landlock for filesystem restrictions, seccomp for system call filtering, and network namespaces for traffic control. These mechanisms operate below the application layer, so agents cannot bypass them regardless of the tools or languages they use.
:::

:::{dropdown} 📜 Declarative Policy Enforcement
A single YAML policy file defines all security boundaries for a sandbox: allowed filesystem paths, permitted network destinations, restricted processes, and inference routing rules. Policies are hot-reloadable, so you can tighten or relax rules on a running sandbox without restarting the agent.
:::

:::{dropdown} 🔐 Credential Containment
Credentials are injected into sandboxes as environment variables at startup and are scoped to the sandbox's isolated namespace. They cannot be read by processes outside the sandbox, and network policies prevent agents from transmitting them to unauthorized endpoints.
:::

:::{dropdown} 🔀 Private Inference Routing
The built-in inference router intercepts LLM API calls and redirects them to local or self-hosted backends based on your routing policy. Sensitive prompts and completions stay on infrastructure you control. Routes are configurable per sandbox and can be updated without restarting agents.
:::

:::{dropdown} 🔍 Full L7 Traffic Inspection
Every outbound TCP connection from a sandbox passes through an L7 proxy that resolves the calling process, evaluates the destination against the active policy, and either allows, denies, or reroutes the request. For REST endpoints, the proxy decrypts TLS, inspects HTTP method and path, and applies fine-grained access rules.
:::

## Use Cases

The following are common use cases for OpenShell.

:::{dropdown} 💻 Secure Coding Agents
Run AI coding assistants such as Claude Code, OpenCode, or OpenClaw inside a sandbox where they can read and modify project files but cannot access SSH keys, cloud credentials, or files outside the project directory. Network policies restrict which package registries and APIs the agent can reach.
:::

:::{dropdown} 🏢 Private Enterprise Development
Route all LLM inference through self-hosted NVIDIA NIM endpoints or private API backends. Proprietary source code and internal documentation stay on your infrastructure and are never sent to third-party LLM providers.
:::

:::{dropdown} ✅ Compliance and Audit
Declarative policies serve as auditable security controls. Each sandbox runs under a well-defined policy that specifies exactly what the agent can access. Policy files can be version-controlled and reviewed as part of your security and compliance processes.
:::

:::{dropdown} 📦 Community and Custom Sandbox Images
Use pre-built sandbox images from the [OpenShell Community](https://github.com/NVIDIA/OpenShell-Community) catalog or bring your own container. Community sandboxes bundle domain-specific tools, policies, and skills, while custom containers let you package any environment your agents need.
:::

---

## Next Steps

- [Architecture Overview](architecture.md): Understand the components that make up the OpenShell runtime.
- [Get Started](../index.md): Install the CLI and create your first sandbox.
- [Safety and Privacy](../safety-and-privacy/index.md): Learn how OpenShell enforces isolation across all protection layers.
