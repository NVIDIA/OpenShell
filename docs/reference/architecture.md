---
title:
  page: "Architecture Reference"
  nav: "Architecture"
description: "Detailed reference for OpenShell architecture: gateway, sandbox internals, policy engine, privacy router, and remote deployment."
keywords: ["openshell architecture", "sandbox architecture", "agent isolation", "k3s", "policy engine"]
topics: ["generative_ai", "cybersecurity"]
tags: ["ai_agents", "sandboxing", "security", "architecture"]
content:
  type: reference
  difficulty: technical_advanced
  audience: [engineer, data_scientist]
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Architecture Reference

This page provides detailed technical information about each OpenShell component.
For a high-level summary, refer to the [Architecture Overview](../about/architecture.md).

## Component Diagram

```{mermaid}
graph TB
    subgraph docker["Docker Container"]
        subgraph k3s["k3s Cluster"]
            gw["Gateway"]
            pr["Privacy Router"]

            subgraph pod1["Sandbox"]
                sup1["Supervisor"]
                proxy1["L7 Proxy"]
                pe1["Policy Engine"]
                agent1["Agent"]

                sup1 --> proxy1
                sup1 --> agent1
                proxy1 --> pe1
            end

            subgraph pod2["Sandbox"]
                sup2["Supervisor"]
                proxy2["L7 Proxy"]
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

    cli["openshell CLI"] -- "gRPC" --> gw
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

## Gateway

The gateway is the central control-plane API. It coordinates sandbox lifecycle
and state, acts as the auth boundary, and brokers all requests across the
platform. It exposes a gRPC API consumed by the CLI and handles:

- Sandbox lifecycle: creates, monitors, and deletes sandbox pods.
- Provider storage: stores encrypted provider credentials.
- Policy distribution: delivers policy YAML to sandboxes at startup and on
  hot-reload.
- SSH termination: terminates SSH tunnels from the CLI and routes them to
  the correct sandbox.

The CLI never talks to sandbox pods directly. All commands go through the
gateway.

## Sandbox

Each sandbox is an isolated runtime that includes container supervision and
general L7 egress routing. It runs as a Kubernetes pod containing a supervisor
process, an L7 proxy, and the agent.

### Supervisor

The supervisor is the sandbox's init process. It establishes all isolation
boundaries before starting the agent:

1. Fetch credentials from the gateway for all attached providers.
2. Set up the network namespace. The sandbox gets its own network stack
   with no default route. All outbound traffic is redirected through the proxy.
3. Apply Landlock filesystem restrictions based on the policy.
4. Apply seccomp filters to restrict available system calls.
5. Start the L7 proxy in the sandbox's network namespace.
6. Start the SSH server for interactive access.
7. Start the agent as a child process with credentials injected as
   environment variables.

### L7 Proxy

Every outbound TCP connection from any process in the sandbox is routed through
the proxy. For each connection, the proxy:

1. Resolves the calling binary through `/proc/<pid>/exe`, ancestor process
   walking, and `/proc/<pid>/cmdline`.
2. Queries the policy engine with the destination host, port, and resolved
   binary path.
3. Acts on the decision: allow the connection directly, hand it to the
   privacy router for inference routing, or deny it. Refer to
   {doc}`../safety-and-privacy/policies` for the full decision model.

For endpoints configured with `protocol: rest` and `tls: terminate`, the proxy
performs full L7 inspection: it decrypts TLS, reads the HTTP method and path,
evaluates access rules, then re-encrypts and forwards the request.

## Policy Engine

The policy engine is the definition and enforcement layer for filesystem,
network, and process constraints. Defense in depth enforces policies from the
application layer down to infrastructure and kernel layers.

The engine evaluates policies compiled from the sandbox's policy YAML. It is
queried synchronously by the proxy on every outbound connection. Policy updates
delivered through hot-reload are compiled and loaded without restarting the proxy.

## Privacy Router

The privacy router is a privacy-aware LLM routing layer that keeps sensitive
context on sandbox compute and routes based on cost/privacy policy.

When the policy engine determines that a connection should be inspected for
inference, the privacy router:

1. Reads the intercepted HTTP request.
2. Checks whether the method and path match a recognized inference API pattern
   (`/v1/chat/completions`, `/v1/completions`, `/v1/messages`).
3. Selects a route whose `routing_hint` appears in the sandbox policy's
   `allowed_routes`.
4. Strips the original authorization header.
5. Injects the route's API key and model ID.
6. Forwards the request to the route's backend URL.

The router refreshes its route list periodically from the gateway, so routes
created with `openshell inference create` become available without restarting
sandboxes.

## Remote Deployment

OpenShell can deploy the cluster to a remote host via SSH. This is useful for
shared team environments or running sandboxes on machines with more resources.

### Deploy

```console
$ openshell gateway start --remote user@host --ssh-key ~/.ssh/id_rsa
```

The CLI connects to the remote machine over SSH, installs k3s, deploys the
OpenShell control plane, and registers the cluster locally. The remote machine
needs Docker installed.

### Tunnel

After deploying to a remote host, set up a tunnel for CLI access:

```console
$ openshell gateway tunnel
```

This establishes an SSH tunnel from your local machine to the remote cluster's
API server. All subsequent CLI commands route through this tunnel transparently.

### Remote Architecture

The architecture is identical to a local deployment. The only difference is
that the Docker container runs on the remote host instead of your workstation.
The CLI communicates with the gateway over the SSH tunnel. Sandbox SSH
connections are also tunneled through the gateway.
