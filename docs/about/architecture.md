---
title:
  page: "Architecture Overview"
  nav: "Architecture"
description: "High-level overview of the OpenShell architecture: gateway, sandboxes, policy engine, and privacy router."
keywords: ["openshell architecture", "sandbox architecture", "agent isolation", "k3s", "policy engine"]
topics: ["generative_ai", "cybersecurity"]
tags: ["ai_agents", "sandboxing", "security", "architecture"]
content:
  type: concept
  difficulty: technical_beginner
  audience: [engineer, data_scientist]
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# How OpenShell Works

OpenShell runs as a [k3s](https://k3s.io/) Kubernetes cluster inside a Docker container.
Each sandbox is an isolated Kubernetes pod managed by the OpenShell control plane.
Four components work together to keep agents secure.

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

## Components

OpenShell consists of the following components.

Gateway
: The control-plane API that manages sandbox lifecycle, stores encrypted credentials, distributes policies, and terminates SSH tunnels. The CLI communicates exclusively with the gateway—it never talks to sandbox pods directly.

Sandbox
: An isolated pod that runs your agent. Each sandbox contains a **supervisor** (sets up isolation and starts the agent), an **L7 proxy** (intercepts and evaluates every outbound connection), and the agent process itself.

Policy Engine
: Evaluates declarative YAML policies that define filesystem, network, and process constraints. The proxy queries the engine on every outbound connection. Policies can be hot-reloaded without restarting the agent.

Privacy Router
: Intercepts LLM API calls and routes them to local or self-hosted backends based on your routing policy. Sensitive prompts and completions stay on infrastructure you control.

## How a Request Flows

OpenShell works in the following way:

1. The agent makes an outbound connection (for example, an API call).
2. The L7 proxy intercepts the connection and identifies the calling process.
3. The proxy queries the policy engine with the destination and process identity.
4. Based on the policy decision, the proxy either allows the connection, routes it through the privacy router for inference, or denies it.

## Remote Deployment

OpenShell can also run on a remote host. Deploy with `openshell gateway start --remote user@host`, then set up a tunnel with `openshell gateway tunnel`. The architecture is identical—only the Docker container location changes.

---

For detailed component internals, refer to the [Architecture Reference](../reference/architecture.md).
