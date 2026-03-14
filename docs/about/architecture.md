---
title:
  page: How OpenShell Works
  nav: How It Works
description: OpenShell architecture overview covering the gateway, sandbox, policy engine, and privacy router.
topics:
- Generative AI
- Cybersecurity
tags:
- AI Agents
- Sandboxing
- Security
- Architecture
content:
  type: concept
  difficulty: technical_beginner
  audience:
  - engineer
  - data_scientist
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# How OpenShell Works

OpenShell runs inside a Docker container. Each sandbox is an isolated environment managed through the gateway. Four components work together to keep agents secure.

```{figure} architecture.svg
:alt: OpenShell architecture diagram showing the component layout
:align: center
:target: ../_images/architecture.svg
```

## Components

The following table describes each component  and its role in the system:

| Component | Role |
|---|---|
| **Gateway** | Control-plane API that coordinates sandbox lifecycle and state, acts as the auth boundary, and brokers requests across the platform. |
| **Sandbox** | Isolated runtime that includes container supervision and policy-enforced egress routing. |
| **Policy Engine** | Policy definition and enforcement layer for filesystem, network, and process constraints. Defense in depth enforces policies from the application layer down to infrastructure and kernel layers. |
| **Privacy Router** | Privacy-aware LLM routing layer that keeps sensitive context on sandbox compute and routes based on cost and privacy policy. |

## How a Request Flows

Every outbound connection from agent code passes through the same decision path:

1. The agent process opens an outbound connection (API call, package install, git clone, and so on).
2. The proxy inside the sandbox intercepts the connection and identifies which binary opened it.
3. The proxy queries the policy engine with the destination, port, and calling binary.
4. The policy engine returns one of three decisions:
   - **Allow** — the destination and binary match a policy block. Traffic flows directly to the external service.
   - **Route for inference** — no policy block matched, but inference routing is configured. The privacy router intercepts the request, strips the original credentials, injects the configured backend credentials, and forwards to the managed model endpoint.
   - **Deny** — no match and no inference route. The connection is blocked and logged.

For REST endpoints with TLS termination enabled, the proxy also decrypts TLS and checks each HTTP request against per-method, per-path rules before allowing it through.

## Deployment Modes

OpenShell can run locally, on a remote host, or behind a cloud proxy. The architecture is identical in all cases — only the Docker container location and authentication mode change.

| Mode | Description | Command |
|---|---|---|
| **Local** | The gateway runs inside Docker on your workstation. The CLI provisions it automatically on first use. | `openshell gateway start` |
| **Remote** | The gateway runs on a remote host via SSH. Only Docker is required on the remote machine. | `openshell gateway start --remote user@host` |
| **Cloud** | A gateway already running behind a reverse proxy (e.g. Cloudflare Access). Register and authenticate via browser. | `openshell gateway add https://gateway.example.com` |

You can register multiple gateways and switch between them with `openshell gateway select`. For the full deployment and management workflow, refer to the [Gateways](../sandboxes/manage-gateways.md) section.

## Next Steps

Continue with one of the following:

- To deploy or register a gateway, refer to [Gateways](../sandboxes/manage-gateways.md).
- To create your first sandbox, refer to the [Quickstart](../get-started/quickstart.md).
- To learn how OpenShell enforces isolation across all protection layers, refer to [Sandboxes](../sandboxes/index.md).
