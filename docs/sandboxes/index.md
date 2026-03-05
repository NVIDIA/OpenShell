<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Sandboxes

A sandbox is a safe, private execution environment for an AI agent. Each sandbox runs inside a Kubernetes pod with multiple layers of protection that prevent unauthorized data access, credential exposure, and network exfiltration: filesystem restrictions (Landlock), system call filtering (seccomp), network namespace isolation, and a privacy-enforcing HTTP CONNECT proxy.

## Concepts

### Lifecycle

A sandbox goes through these phases:

| Phase | Description |
|-------|-------------|
| **Provisioning** | The pod is being created and the supervisor is starting up. |
| **Ready** | The sandbox is running and accessible via SSH. |
| **Error** | Something went wrong during startup or execution. |
| **Deleting** | The sandbox is being torn down. |

### Supervisor and Child Process

Each sandbox runs two processes:

- The **supervisor** (`navigator-sandbox`) is a privileged process that sets up isolation, starts the proxy, runs the SSH server, and manages the child process.
- The **child process** is the agent (e.g., Claude, Codex) running with restricted privileges — reduced filesystem access, filtered system calls, and all network traffic routed through the proxy.

### Policy

Every sandbox is governed by a policy that defines what the agent can do, ensuring your data and credentials stay safe. Policies are written in YAML and control:

- **Filesystem access** — which directories are readable and writable, protecting sensitive data.
- **Network access** — which hosts each program can connect to, preventing data exfiltration.
- **Inference routing** — which AI model backends are available, keeping inference traffic private.
- **Process privileges** — the user and group the agent runs as, limiting blast radius.

See [Safety & Privacy](../safety-and-privacy/index.md) for details.

## Quick Reference

| Task | Command |
|------|---------|
| Create sandbox (interactive) | `nemoclaw sandbox create` |
| Create sandbox with tool | `nemoclaw sandbox create -- claude` |
| Create with custom policy | `nemoclaw sandbox create --policy ./p.yaml --keep` |
| List sandboxes | `nemoclaw sandbox list` |
| Connect to sandbox | `nemoclaw sandbox connect <name>` |
| Stream live logs | `nemoclaw sandbox logs <name> --tail` |
| Sync files to sandbox | `nemoclaw sandbox sync <name> --up ./src /sandbox/src` |
| Forward a port | `nemoclaw sandbox forward start <port> <name> -d` |
| Delete sandbox | `nemoclaw sandbox delete <name>` |

## In This Section

- [Create and Manage](create-and-manage.md): About creating, listing, inspecting, and connecting to sandboxes.
- [Providers](providers.md): About managing external credentials privately.
- [Custom Containers](custom-containers.md): About bringing your own container images.
- [Community Sandboxes](community-sandboxes.md): About using pre-built sandboxes from the NemoClaw Community catalog.
- [Port Forwarding](port-forwarding.md): About forwarding local ports into sandboxes.
- [Terminal](terminal.md): About using NemoClaw Terminal to monitor sandbox activity and diagnose blocked connections.
