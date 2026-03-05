<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# How It Works

This page covers the NemoClaw architecture, its major subsystems, and the end-to-end flow from bootstrapping a cluster to running a safety-enforced sandbox.

## Architecture

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
        HOSTS["Allowed Hosts (github.com, api.anthropic.com, ...)"]
        CREDS["Provider APIs (Claude, GitHub, GitLab, ...)"]
        BACKEND["Inference Backends (LM Studio, vLLM, ...)"]
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
    SERVER -. "Store / retrieve credentials" .-> CREDS
```

Users interact through the CLI, which communicates with a central gateway. The gateway manages sandbox lifecycle in Kubernetes, and each sandbox enforces its own policy locally.

## Major Subsystems

### Sandbox Execution Environment

Each sandbox runs inside a container as two processes: a privileged **supervisor** and a restricted **child process** (the agent). Safety and privacy are enforced through four independent layers:

- **Filesystem restrictions** — the Linux Landlock LSM controls which directories the agent can read and write. Attempts to access files outside the allowed set are blocked by the kernel.
- **System call filtering** — seccomp prevents the agent from creating raw network sockets, eliminating proxy bypass.
- **Network namespace isolation** — the agent is placed in a separate network where the only reachable destination is the proxy, preventing data exfiltration.
- **Process privilege separation** — the agent runs as an unprivileged user, protecting against privilege escalation.

All restrictions are driven by a YAML **policy** evaluated by an embedded OPA/Rego engine. See [Safety & Privacy](../safety-and-privacy/index.md).

### Network Proxy

Every sandbox forces all outbound traffic through an HTTP CONNECT proxy — no data leaves without inspection. The proxy:

1. **Identifies the requesting program** via the process table.
2. **Verifies binary integrity** with trust-on-first-use SHA256 hashing.
3. **Evaluates requests against policy** with per-binary, per-host granularity.
4. **Protects private infrastructure** by blocking DNS results that resolve to internal IP ranges.
5. **Performs L7 inspection** for configured endpoints, examining HTTP requests within TLS tunnels.
6. **Keeps inference traffic private** by intercepting AI API calls and rerouting them to policy-controlled backends.

### Gateway

The central orchestration service providing gRPC and HTTP APIs, sandbox lifecycle management, data persistence, TLS termination, SSH tunnel gateway, and real-time status streaming.

### Providers

Credentials are managed with a privacy-first design. API keys and tokens are stored separately from sandbox definitions, never appear in pod specs, and are fetched only at runtime. See [Providers](../sandboxes/providers.md).

### Inference Routing

AI inference API calls are transparently intercepted and rerouted to policy-controlled backends, keeping sensitive prompts and responses on private infrastructure. See [Inference Routing](../inference/index.md).

### Cluster Infrastructure

The entire platform packages into a single Docker container running k3s. Docker is the only dependency. See [Clusters](../clusters/index.md).

## End-to-End Flow

```{mermaid}
sequenceDiagram
    participant User as User
    participant CLI as CLI
    participant Docker as Docker
    participant GW as Gateway
    participant K8s as Kubernetes
    participant SBX as Sandbox

    User->>CLI: nemoclaw sandbox create -- claude
    CLI->>CLI: Check for running cluster
    alt No cluster found
        CLI->>Docker: Bootstrap k3s cluster
        Docker-->>CLI: Cluster ready
    end
    CLI->>CLI: Discover local credentials (ANTHROPIC_API_KEY, ~/.claude.json)
    CLI->>GW: Upload credentials as provider
    CLI->>GW: CreateSandbox(policy, providers)
    GW->>K8s: Create sandbox pod
    K8s-->>GW: Pod scheduled
    GW-->>CLI: Sandbox provisioning
    loop Wait for Ready
        CLI->>GW: GetSandbox(name)
        GW-->>CLI: Status update
    end
    CLI->>GW: CreateSshSession(sandbox_id)
    GW-->>CLI: Session token
    CLI->>SBX: SSH tunnel through gateway
    User->>SBX: Interactive shell session
```

## What Happens Inside a Sandbox

When a sandbox starts, the supervisor executes this sequence:

1. **Load policy** — fetches the YAML policy from the gateway. The policy defines all filesystem, network, and process restrictions.
2. **Fetch credentials** — retrieves provider credentials via gRPC for injection into child processes.
3. **Set up filesystem isolation** — configures Landlock rules. Writable directories are created and ownership is set automatically.
4. **Generate ephemeral TLS certificates** — creates a per-sandbox CA for transparent TLS inspection.
5. **Create network namespace** — isolates the agent's network so the only reachable destination is the proxy.
6. **Start the proxy** — launches the HTTP CONNECT proxy with OPA policy evaluation.
7. **Start the SSH server** — launches the embedded SSH daemon for interactive access.
8. **Spawn the agent** — launches the child process with reduced privileges: seccomp filters, network namespace, Landlock rules, and credentials injected as environment variables.
9. **Begin policy polling** — checks for policy updates every 30 seconds, enabling live changes without restart.

## How Network Safety Works

```{mermaid}
flowchart TD
    A[Agent makes HTTPS request] --> B[Request routed to proxy via network namespace]
    B --> C{OPA policy evaluation}
    C -->|Endpoint + binary match| D[Allow: forward to destination]
    C -->|No match, inference routes exist| E[Inspect for inference patterns]
    C -->|No match, no routes| F[Deny: connection rejected]
    E --> G{Known inference API?}
    G -->|Yes| H[Route to configured backend]
    G -->|No| F
    D --> I{DNS resolves to private IP?}
    I -->|Yes| F
    I -->|No| J[Connection established]
```

Every connection is evaluated with three pieces of context:
- **Which program** is making the request (identified via `/proc`).
- **Which host and port** the program is trying to reach.
- **Whether the binary has been tampered with** since its first request.

## How Credential Privacy Works

Credentials flow through a privacy-preserving pipeline:

1. **Discovery** — the CLI scans local environment variables and config files for credentials.
2. **Upload** — credentials are sent to the gateway over mTLS and stored separately from sandbox definitions.
3. **Injection** — the supervisor fetches credentials via gRPC and injects them as environment variables. They never appear in Kubernetes pod specs.
4. **Isolation** — the sandbox policy controls which endpoints the agent can reach, so credentials cannot be exfiltrated.

## How Inference Privacy Works

When inference routing is configured, the proxy intercepts AI API calls and keeps them private:

1. The agent calls the OpenAI/Anthropic SDK as normal.
2. The proxy TLS-terminates the connection and detects the inference API pattern.
3. The proxy strips the original authorization header and routes the request to a configured backend.
4. The backend's API key is injected by the router — the sandbox never sees it.
5. The response flows back to the agent transparently.

This keeps prompts and responses on your private infrastructure while the agent operates as if it were calling the original API.

## How Live Policy Updates Work

Policies can be updated on running sandboxes without restarts:

1. Push the updated policy: `nemoclaw sandbox policy set <name> --policy updated.yaml --wait`.
2. The gateway stores the new revision as `pending`.
3. The sandbox detects the new version within 30 seconds.
4. The OPA engine atomically reloads with the new rules.
5. If the reload fails, the previous policy stays active (last-known-good behavior).
