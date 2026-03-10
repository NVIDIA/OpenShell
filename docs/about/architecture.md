---
title:
  page: "How OpenShell Works"
  nav: "How It Works"
description: "OpenShell architecture: gateway, sandbox, policy engine, and privacy router."
keywords: ["nemoclaw architecture", "sandbox architecture", "agent isolation", "k3s", "policy engine"]
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

OpenShell runs as a [k3s](https://k3s.io/) Kubernetes cluster inside a Docker container. Each sandbox is an isolated Kubernetes pod managed through the gateway. Four components work together to keep agents secure.

```{mermaid}
graph TB
    subgraph docker["Docker Container"]
        subgraph k3s["k3s Cluster"]
            gw["Gateway"]
            pr["Privacy Router"]

            subgraph pod1["Sandbox"]
                sup1["Supervisor"]
                proxy1["Proxy"]
                pe1["Policy Engine"]
                agent1["Agent"]

                sup1 --> proxy1
                sup1 --> agent1
                proxy1 --> pe1
            end

            subgraph pod2["Sandbox"]
                sup2["Supervisor"]
                proxy2["Proxy"]
                pe2["Policy Engine"]
                agent2["Agent"]

                sup2 --> proxy2
                sup2 --> agent2
                proxy2 --> pe2
            end

            gw -- "credentials,<br/>policies" --> sup1
            gw -- "credentials,<br/>policies" --> sup2
        end
    end

    cli["nemoclaw CLI"] -- "gRPC" --> gw
    agent1 -- "all outbound<br/>traffic" --> proxy1
    agent2 -- "all outbound<br/>traffic" --> proxy2
    proxy1 -- "policy-approved<br/>traffic" --> internet["External Services"]
    proxy2 -- "policy-approved<br/>traffic" --> internet
    proxy1 -- "inference traffic" --> pr
    proxy2 -- "inference traffic" --> pr
    pr -- "routed requests" --> backend["LLM Backend"]

    style cli fill:#ffffff,stroke:#000000,color:#000000
    style gw fill:#76b900,stroke:#000000,color:#000000
    style pr fill:#76b900,stroke:#000000,color:#000000
    style sup1 fill:#76b900,stroke:#000000,color:#000000
    style proxy1 fill:#76b900,stroke:#000000,color:#000000
    style pe1 fill:#76b900,stroke:#000000,color:#000000
    style agent1 fill:#ffffff,stroke:#000000,color:#000000
    style sup2 fill:#76b900,stroke:#000000,color:#000000
    style proxy2 fill:#76b900,stroke:#000000,color:#000000
    style pe2 fill:#76b900,stroke:#000000,color:#000000
    style agent2 fill:#ffffff,stroke:#000000,color:#000000
    style internet fill:#ffffff,stroke:#000000,color:#000000
    style backend fill:#ffffff,stroke:#000000,color:#000000
    style docker fill:#f5f5f5,stroke:#000000,color:#000000
    style k3s fill:#e8e8e8,stroke:#000000,color:#000000
    style pod1 fill:#f5f5f5,stroke:#000000,color:#000000
    style pod2 fill:#f5f5f5,stroke:#000000,color:#000000

    linkStyle default stroke:#76b900,stroke-width:2px
```

## Components

| Component | Role |
|---|---|
| **Gateway** | Control-plane API that coordinates sandbox lifecycle and state, acts as the auth boundary, and brokers requests across the platform. |
| **Sandbox** | Isolated runtime that includes container supervision and policy-enforced egress routing. |
| **Policy Engine** | Policy definition and enforcement layer for filesystem, network, and process constraints. Defense in depth enforces policies from the application layer down to infrastructure and kernel layers. |
| **Privacy Router** | Privacy-aware LLM routing layer that keeps sensitive context on sandbox compute and routes based on cost and privacy policy. |

## How a Request Flows

Every outbound connection from agent code passes through the same decision path:

1. The agent process opens an outbound connection (API call, package install, git clone, etc.).
2. The proxy inside the sandbox intercepts the connection and identifies which binary opened it.
3. The proxy queries the policy engine with the destination, port, and calling binary.
4. The policy engine returns one of three decisions:
   - **Allow** — the destination and binary match a policy block. Traffic flows directly to the external service.
   - **Route for inference** — no policy block matched, but inference routing is configured. The privacy router intercepts the request, strips the original credentials, injects the configured backend credentials, and forwards to the managed model endpoint.
   - **Deny** — no match and no inference route. The connection is blocked and logged.

For REST endpoints with TLS termination enabled, the proxy also decrypts TLS and checks each HTTP request against per-method, per-path rules before allowing it through.

## Deployment Modes

OpenShell can run locally or on a remote host. The architecture is identical in both cases — only the Docker container location changes.

- **Local**: the k3s cluster runs inside Docker on your workstation. The CLI provisions it automatically on first use.
- **Remote**: the cluster runs on a remote host. Deploy with `nemoclaw gateway start --remote user@host`, then connect with `nemoclaw gateway tunnel`. All CLI commands route through the SSH tunnel transparently.

## Next Steps

- [Sandbox Policies](../sandboxes/policies.md): Policy structure, network rules, and update workflow.
