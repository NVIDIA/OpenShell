<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Architecture

System architecture and component internals for the NemoClaw runtime. This page is for advanced users who need to understand what runs where, how components interact, and how to deploy to remote hosts.

## System Overview

NemoClaw runs as a [k3s](https://k3s.io/) Kubernetes cluster inside a Docker container. All components run within this container. Sandboxes are Kubernetes pods managed by the NemoClaw control plane.

The system has five core components:

| Component | Role |
|---|---|
| **Gateway** | gRPC control plane. Manages sandbox lifecycle, stores provider credentials, distributes policies, and terminates SSH tunnels. |
| **Sandbox Supervisor** | Per-sandbox process that sets up isolation (Landlock, seccomp, network namespace), runs the proxy and SSH server, and fetches credentials from the gateway at startup. |
| **HTTP CONNECT Proxy** | Per-sandbox proxy in the sandbox's network namespace. Evaluates OPA policy for every outbound connection. Supports L4 passthrough and L7 inspection with TLS termination. |
| **OPA Engine** | Embedded [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policy evaluator. The proxy queries it on each connection to determine allow, deny, or inspect-for-inference. |
| **Inference Router** | Intercepts outbound LLM API calls that do not match any network policy, strips credentials, and reroutes them to operator-configured backends. |

## Component Diagram

```{mermaid}
graph TB
    subgraph docker["Docker Container"]
        subgraph k3s["k3s Cluster"]
            gw["Gateway<br/>(gRPC + DB)"]

            subgraph pod1["Sandbox Pod"]
                sup1["Supervisor"]
                proxy1["Proxy + OPA"]
                ssh1["SSH Server"]
                agent1["Agent Process"]

                sup1 --> proxy1
                sup1 --> ssh1
                sup1 --> agent1
            end

            subgraph pod2["Sandbox Pod"]
                sup2["Supervisor"]
                proxy2["Proxy + OPA"]
                ssh2["SSH Server"]
                agent2["Agent Process"]

                sup2 --> proxy2
                sup2 --> ssh2
                sup2 --> agent2
            end

            gw -- "credentials,<br/>policies" --> sup1
            gw -- "credentials,<br/>policies" --> sup2
        end
    end

    cli["nemoclaw CLI"] -- "gRPC" --> gw
    user["User"] -- "SSH" --> ssh1
    user -- "SSH" --> ssh2
    agent1 -- "all outbound<br/>traffic" --> proxy1
    agent2 -- "all outbound<br/>traffic" --> proxy2
    proxy1 -- "allowed / routed<br/>traffic" --> internet["External Services"]
    proxy2 -- "allowed / routed<br/>traffic" --> internet
```

## Gateway

The gateway is the central control plane. It exposes a gRPC API consumed by the CLI and handles:

| Responsibility | Detail |
|---|---|
| Sandbox lifecycle | Creates, monitors, and deletes sandbox pods in the k3s cluster. |
| Provider storage | Stores encrypted provider credentials in its embedded database. |
| Policy distribution | Delivers policy YAML to sandbox supervisors at startup and on hot-reload. |
| SSH termination | Terminates SSH tunnels from the CLI and routes them to the correct sandbox pod. |

The CLI never talks to sandbox pods directly. All commands go through the gateway.

## Sandbox Supervisor

Each sandbox pod runs a supervisor process as its init process. The supervisor is responsible for establishing all isolation boundaries before starting the agent.

Startup sequence:

1. **Fetch credentials** from the gateway for all attached providers.
2. **Set up the network namespace.** The sandbox gets its own network stack with no default route to the outside world. All outbound traffic is redirected through the proxy via iptables rules.
3. **Apply Landlock** filesystem restrictions based on the policy's `filesystem_policy`.
4. **Apply seccomp** filters to restrict available system calls.
5. **Start the proxy** in the sandbox's network namespace.
6. **Start the SSH server** for interactive access.
7. **Start the agent** as a child process running as the configured user and group, with credentials injected as environment variables.

The supervisor continues running for the lifetime of the sandbox. It monitors the agent process, handles policy hot-reloads from the gateway, and manages the proxy and SSH server.

## Proxy

The proxy runs inside each sandbox's network namespace. Every outbound TCP connection from any process in the sandbox is routed through the proxy via iptables redirection.

For each connection, the proxy:

1. **Resolves the calling binary** by reading `/proc/<pid>/exe` for the socket owner, walking ancestor processes, and checking `/proc/<pid>/cmdline` for interpreted languages.
2. **Queries the OPA engine** with the destination host, port, and resolved binary path.
3. **Acts on the policy decision:**

| Decision | Action |
|---|---|
| **Allow** | Forward the connection directly to the destination. |
| **InspectForInference** | TLS-terminate the connection, inspect the HTTP request, and hand it to the inference router if it matches a known API pattern. Deny if it does not match. |
| **Deny** | Block the connection. Return HTTP 403 or reset the TCP connection. |

For endpoints configured with `protocol: rest` and `tls: terminate`, the proxy performs full L7 inspection: it decrypts TLS, reads the HTTP method and path, evaluates `access` or `rules`, then re-encrypts and forwards the request.

## OPA Engine

The OPA engine is embedded in the proxy process. It evaluates [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies compiled from the sandbox's policy YAML. The engine is queried synchronously on every outbound connection.

Policy updates delivered via hot-reload are compiled into Rego and loaded into the engine without restarting the proxy.

## Inference Router

The inference router handles connections that the OPA engine marks as `InspectForInference`. It:

1. Reads the intercepted HTTP request.
2. Checks whether the method and path match a recognized inference API pattern (`/v1/chat/completions`, `/v1/completions`, `/v1/messages`).
3. Selects a route whose `routing_hint` appears in the sandbox policy's `allowed_routes`.
4. Strips the original authorization header.
5. Injects the route's API key and model ID.
6. Forwards the request to the route's backend URL.

The router refreshes its route list periodically from the gateway, so routes created with `nemoclaw inference create` become available without restarting sandboxes.

## Remote Deployment

NemoClaw can deploy the cluster to a remote host via SSH. This is useful for shared team environments or running sandboxes on machines with more resources.

### Deploy

```console
$ nemoclaw cluster admin deploy --remote user@host --ssh-key ~/.ssh/id_rsa
```

The CLI connects to the remote machine over SSH, installs k3s, deploys the NemoClaw control plane, and registers the cluster locally. The remote machine needs Docker installed.

### Tunnel

After deploying to a remote host, set up a tunnel for kubectl access:

```console
$ nemoclaw cluster admin tunnel
```

This establishes an SSH tunnel from your local machine to the remote cluster's API server. All subsequent CLI commands route through this tunnel transparently.

### Remote Architecture

The architecture is identical to a local deployment. The only difference is that the Docker container runs on the remote host instead of your workstation. The CLI communicates with the gateway over the SSH tunnel. Sandbox SSH connections are also tunneled through the gateway.
