<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Resources

## Links

- [NemoClaw on GitHub](https://github.com/NVIDIA/NemoClaw) — source code, issues, and pull requests.
- [Contributing Guide](https://github.com/NVIDIA/NemoClaw/blob/main/CONTRIBUTING.md) — how to build from source and contribute.

## Related Technologies

| Technology | How NemoClaw Uses It |
|------------|---------------------|
| [k3s](https://k3s.io/) | Lightweight Kubernetes distribution used for the cluster runtime. |
| [OPA / Rego](https://www.openpolicyagent.org/) | Policy language for sandbox network access control. NemoClaw uses the `regorus` pure-Rust evaluator. |
| [Landlock](https://landlock.io/) | Linux security module for filesystem access control. |
| [seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) | Linux kernel system call filtering. |
| [ratatui](https://ratatui.rs/) | Rust TUI framework powering the Gator terminal dashboard. |
| [russh](https://github.com/warp-tech/russh) | Rust SSH library used for the sandbox embedded SSH server. |
| [Helm](https://helm.sh/) | Kubernetes package manager used for deploying NemoClaw components. |

## Glossary

| Term | Definition |
|------|-----------|
| **Sandbox** | An isolated execution environment for an AI agent, enforcing filesystem, network, and syscall restrictions. |
| **Supervisor** | The privileged process inside a sandbox that manages isolation and spawns the agent. |
| **Provider** | A credential store for external services (API keys, tokens). Injected as environment variables at runtime. |
| **Policy** | A YAML document defining what a sandbox can access (filesystem, network, inference). |
| **Gateway** | The central control plane service that manages sandboxes, providers, and routes. |
| **Inference Route** | A mapping from a routing hint to a backend AI model endpoint. |
| **BYOC** | Bring Your Own Container — running custom images as sandboxes. |
| **Gator** | The NemoClaw terminal user interface (TUI). |
| **L7 Inspection** | HTTP-level traffic inspection inside TLS tunnels. |
| **TOFU** | Trust-On-First-Use — the binary integrity verification model used by the proxy. |
| **mTLS** | Mutual TLS — both client and server present certificates. Used for all gateway communication. |
