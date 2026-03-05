<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Release Notes

## 0.1.0 (Initial Release)

### Features

- **Sandbox execution environment** — isolated AI agent runtime with Landlock filesystem restrictions, seccomp system call filtering, network namespace isolation, and process privilege separation.
- **HTTP CONNECT proxy** — policy-enforcing network proxy with per-binary access control, binary integrity verification (TOFU), SSRF protection, and L7 HTTP inspection.
- **OPA/Rego policy engine** — embedded policy evaluation using the `regorus` pure-Rust Rego evaluator. No external OPA daemon required.
- **Live policy updates** — hot-reload `network_policies` and `inference` fields on running sandboxes without restart.
- **Provider system** — first-class credential management with auto-discovery from local machine, secure gateway storage, and runtime injection.
- **Inference routing** — transparent interception and rerouting of OpenAI/Anthropic API calls to policy-controlled backends for inference privacy.
- **Cluster bootstrap** — single-container k3s deployment with Docker as the only dependency. Supports local and remote (SSH) targets.
- **CLI** (`nemoclaw` / `ncl`) — full command-line interface for cluster, sandbox, provider, and inference route management.
- **Gator TUI** — terminal dashboard for real-time cluster monitoring and sandbox management.
- **BYOC (Bring Your Own Container)** — run custom container images as sandboxes with supervisor bootstrap.
- **SSH tunneling** — secure access to sandboxes through the gateway with session tokens and mTLS.
- **File sync** — push and pull files to/from sandboxes via tar-over-SSH.
- **Port forwarding** — forward local ports into sandboxes via SSH tunnels.
- **mTLS** — automatic PKI bootstrap and mutual TLS for all gateway communication.

### Supported Providers

Claude, Codex, OpenCode, GitHub, GitLab, NVIDIA, Generic, Outlook.

### Supported Inference Protocols

`openai_chat_completions`, `openai_completions`, `anthropic_messages`.
