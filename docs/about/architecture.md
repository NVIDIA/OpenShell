---
title:
  page: "How OpenShell Works"
  nav: "How It Works"
description: "OpenShell architecture: gateway, sandbox, policy engine, and privacy router."
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

OpenShell runs as a [k3s](https://k3s.io/) Kubernetes cluster inside a Docker container. Each sandbox is an isolated Kubernetes pod managed through the gateway. Four components work together to keep agents secure.

```{image} architecture.svg
:alt: OpenShell architecture diagram showing the OpenShell component layout
:align: center
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
- **Remote**: the cluster runs on a remote host. Deploy with `openshell gateway start --remote user@host`. For example, connect to your DGX Spark
  ```console
  $ openshell gateway start --remote <username>@<spark-SSID>.local
  $ openshell status
  ```

## Next Steps

- [Quickstart](get-started.md): Create your first sandbox.
- [Sandboxes](../sandboxes/index.md): Learn how OpenShell enforces isolation across all protection layers.
