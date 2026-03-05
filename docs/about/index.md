---
title:
  page: "NVIDIA NemoClaw Overview"
  nav: "Overview"
description: "Learn about NemoClaw, the safe and private runtime for autonomous AI agents. Run agents in sandboxed environments that protect your data, credentials, and infrastructure."
keywords: ["nemoclaw", "ai agent sandbox", "agent safety", "agent privacy", "sandboxed execution"]
topics: ["generative_ai", "cybersecurity"]
tags: ["ai_agents", "sandboxing", "security", "privacy", "inference_routing"]
content:
  type: concept
  difficulty: technical_beginner
  audience: [engineer, data_scientist, devops]
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# NVIDIA NemoClaw Overview

NVIDIA NemoClaw is a safe, private runtime for autonomous AI agents. It provides sandboxed execution environments that protect your data, credentials, and infrastructure while giving agents the system access they need to be useful. Each sandbox enforces declarative YAML policies through Linux kernel-level isolation, a policy-enforcing network proxy, and a credential management pipeline — agents run with exactly the permissions you grant and nothing more.

You do not modify agent code to use NemoClaw. Instead, the CLI bootstraps a local Kubernetes cluster packaged in a single Docker container, creates sandboxes with the safety policies you define, and connects you to the running agent through an SSH tunnel.

## How NemoClaw Works

```{mermaid}
flowchart LR
    CLI["CLI"] -->|gRPC| GW["Gateway"]
    GW --> SBX["Sandbox"]

    subgraph SBX["Sandbox"]
        direction TB
        AGENT["Agent Process"] -->|All traffic| PROXY["Network Proxy"]
        PROXY -->|Evaluate| OPA["Policy Engine"]
    end

    PROXY -->|Allowed traffic| EXT["External Services"]

    style CLI fill:#ffffff,stroke:#000000,color:#000000
    style GW fill:#76b900,stroke:#000000,color:#000000
    style SBX fill:#f5f5f5,stroke:#000000,color:#000000
    style AGENT fill:#ffffff,stroke:#000000,color:#000000
    style PROXY fill:#76b900,stroke:#000000,color:#000000
    style OPA fill:#76b900,stroke:#000000,color:#000000
    style EXT fill:#ffffff,stroke:#000000,color:#000000

    linkStyle default stroke:#76b900,stroke-width:2px
```

The CLI bootstraps a cluster, creates sandboxes, and connects you via SSH. Inside each sandbox, an agent process runs with kernel-level filesystem restrictions while all network traffic passes through a policy-enforcing proxy. The proxy evaluates every request against an OPA policy engine before allowing or denying access. For the full architecture and end-to-end flow, refer to [How It Works](how-it-works.md).

## Key Capabilities

:::{dropdown} Data Safety

Filesystem restrictions prevent agents from reading sensitive files or writing outside designated directories. The Linux Landlock LSM controls which paths the agent can access, and seccomp filters block raw network socket creation. Restrictions are enforced at the kernel level — they cannot be bypassed by the agent process.
:::

:::{dropdown} Network Privacy

All outbound traffic passes through an HTTP CONNECT proxy that inspects every connection. The proxy identifies which program is making the request, verifies binary integrity through SHA256 hashing, and evaluates requests against per-host, per-binary policies. DNS results that resolve to private IP ranges are blocked automatically to prevent SSRF attacks.
:::

:::{dropdown} Credential Privacy

API keys and tokens are stored separately from sandbox definitions, never appear in container or pod specifications, and are fetched only at runtime over mTLS. The CLI auto-discovers local credentials for supported providers (Anthropic, OpenAI, GitHub, GitLab, NVIDIA) and uploads them through a privacy-preserving pipeline. Refer to [Providers](../sandboxes/providers.md) for the full list.
:::

:::{dropdown} Inference Privacy

AI API calls (OpenAI, Anthropic) are transparently intercepted by the proxy and rerouted to local or self-hosted backends such as LM Studio or vLLM. The agent calls its SDK as normal — NemoClaw swaps the destination and injects the backend's API key without the sandbox ever seeing it. Prompts and responses stay on your infrastructure. Refer to [Inference Routing](../inference/index.md) for configuration details.
:::

:::{dropdown} Declarative Policies

YAML policies define what each sandbox can access — filesystems, network endpoints, inference routes, and credential bindings. Policies can be updated on running sandboxes without restart: push a new policy revision and the OPA engine reloads atomically within 30 seconds. Refer to [Policies](../safety-and-privacy/policies.md) for the schema and examples.
:::

:::{dropdown} Zero-Config Deployment

The entire platform packages into a single Docker container running k3s. Docker is the only dependency. Two commands go from zero to a running sandbox:

```bash
nemoclaw cluster admin deploy
nemoclaw sandbox create -- claude
```

No Kubernetes expertise is required. Refer to [Get Started](../get-started/installation.md) for full installation steps.
:::

## Use Cases

| Use Case | Description |
| --- | --- |
| Autonomous coding agents | Run Claude, Codex, or OpenCode with full shell access while preventing unauthorized file reads, credential leaks, and network exfiltration. |
| Secure CI/CD agent execution | Execute AI-assisted build, test, and deploy workflows in sandboxes that restrict what the agent can reach on your network. |
| Private inference | Route all LLM API calls to self-hosted backends, keeping prompts, code, and responses off third-party servers. |
| Multi-tenant agent hosting | Run sandboxes for multiple users or teams on a shared cluster with isolated policies, credentials, and network access. |
| Compliance-sensitive environments | Enforce auditable, declarative policies that prove agents operate within defined boundaries for regulatory or security review. |
| Custom toolchain sandboxing | Bring your own container image with custom tools and dependencies while NemoClaw enforces the same safety guarantees. Refer to [Custom Containers](../sandboxes/custom-containers.md). |

## Next Steps

- [How It Works](how-it-works.md): Explore the architecture, major subsystems, and the end-to-end flow from cluster bootstrap to running sandbox.
- [Support Matrix](support-matrix.md): Find platform requirements, supported providers, agent tools, and compatibility details.
- [Release Notes](release-notes.md): Track what changed in each version.
- [Get Started](../get-started/installation.md): Install the CLI and launch your first sandbox.
