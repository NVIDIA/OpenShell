<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# System Architecture

This page provides a high-level view of NemoClaw's system architecture and component interactions.

## Architecture Diagram

```{mermaid}
flowchart TB
    subgraph USER["User's Machine"]
        CLI["Command-Line Interface"]
    end

    subgraph CLUSTER["Kubernetes Cluster (single Docker container)"]
        SERVER["Gateway / Control Plane"]
        DB["Database (SQLite or Postgres)"]

        subgraph SBX["Sandbox Pod"]
            SUPERVISOR["Sandbox Supervisor"]
            PROXY["Network Proxy"]
            CHILD["Agent Process (restricted)"]
            OPA["Policy Engine (OPA)"]
        end
    end

    subgraph EXT["External Services"]
        HOSTS["Allowed Hosts"]
        BACKEND["Inference Backends"]
    end

    CLI -- "gRPC / HTTPS" --> SERVER
    CLI -- "SSH over HTTP CONNECT" --> SERVER
    SERVER -- "CRUD + Watch" --> DB
    SERVER -- "Create / Delete Pods" --> SBX
    SUPERVISOR -- "Fetch Policy + Credentials" --> SERVER
    SUPERVISOR -- "Spawn + Restrict" --> CHILD
    CHILD -- "All network traffic" --> PROXY
    PROXY -- "Evaluate request" --> OPA
    PROXY -- "Allowed traffic only" --> HOSTS
    PROXY -- "Inference reroute" --> SERVER
    SERVER -- "Proxied inference" --> BACKEND
```

## Component Summary

| Component | Description |
|-----------|-------------|
| **CLI** (`nemoclaw`) | Primary user interface. Manages clusters, sandboxes, providers, and inference routes. |
| **Gateway** | Central control plane. Provides gRPC and HTTP APIs, manages sandbox lifecycle in Kubernetes, stores data in SQLite/Postgres. |
| **Sandbox Supervisor** | Runs inside each sandbox pod. Sets up isolation (Landlock, seccomp, netns), runs the proxy, spawns the agent. |
| **Network Proxy** | HTTP CONNECT proxy inside the sandbox. Evaluates every outbound connection against the OPA policy. |
| **OPA Engine** | Embedded Rego policy evaluator (regorus crate). No external OPA daemon. |
| **Gator TUI** | Terminal dashboard for real-time cluster and sandbox monitoring. |

## Container Images

NemoClaw produces three container images:

| Image | Purpose |
|-------|---------|
| **Sandbox** | Runs inside each sandbox pod. Contains the supervisor binary, Python runtime, and agent tooling. |
| **Gateway** | Runs the control plane. Contains the gateway binary, database migrations, and SSH client. |
| **Cluster** | Airgapped Kubernetes image with k3s, pre-loaded sandbox/gateway images, Helm charts, and API gateway. This is the single container users deploy. |

## Communication Protocols

| Path | Protocol | Description |
|------|----------|-------------|
| CLI to Gateway | gRPC over mTLS | Sandbox CRUD, provider management, inference routes, session creation. |
| CLI to Sandbox | SSH over HTTP CONNECT | Interactive shells, command execution, file sync. Tunneled through the gateway. |
| Sandbox to Gateway | gRPC over mTLS | Policy fetching, credential retrieval, inference bundle delivery, log push, policy status reporting. |
| Proxy to External | HTTPS | Outbound connections from the sandbox, filtered by policy. |
| Proxy to Backend | HTTP/HTTPS | Inference requests rerouted to configured backends. |

## Project Structure

| Path | Purpose |
|------|---------|
| `crates/` | Rust crates (CLI, gateway, sandbox, TUI, bootstrap, router, core, providers). |
| `python/` | Python SDK and bindings. |
| `proto/` | Protocol buffer definitions. |
| `deploy/` | Dockerfiles, Helm chart, Kubernetes manifests. |
| `architecture/` | Internal architecture documentation. |
| `tasks/` | `mise` task definitions. |
