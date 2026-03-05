<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Release Notes

This page tracks changes, new features, and fixes for each NemoClaw release.

## 0.1.0

The first release of NVIDIA NemoClaw, introducing sandboxed AI agent execution with kernel-level isolation, policy enforcement, and credential management.

### Key Features

The following table summarizes the key features included in this release.

| Feature | Description |
|---------|-------------|
| Sandbox execution environment | Isolated AI agent runtime with Landlock filesystem restrictions, seccomp system call filtering, network namespace isolation, and process privilege separation. |
| HTTP CONNECT proxy | Policy-enforcing network proxy with per-binary access control, binary integrity verification (TOFU), SSRF protection, and L7 HTTP inspection. |
| OPA/Rego policy engine | Embedded policy evaluation using the `regorus` pure-Rust Rego evaluator. No external OPA daemon required. |
| Live policy updates | Hot-reload `network_policies` and `inference` fields on running sandboxes without restart. |
| Provider system | First-class credential management with auto-discovery from local machine, secure gateway storage, and runtime injection. |
| Inference routing | Transparent interception and rerouting of OpenAI/Anthropic API calls to policy-controlled backends for inference privacy. |
| Cluster bootstrap | Single-container k3s deployment with Docker as the only dependency. Supports local and remote (SSH) targets. |
| CLI (`nemoclaw` / `ncl`) | Full command-line interface for cluster, sandbox, provider, and inference route management. |
| Gator TUI | Terminal dashboard for real-time cluster monitoring and sandbox management. |
| BYOC | Run custom container images as sandboxes with supervisor bootstrap. |
| SSH tunneling | Secure access to sandboxes through the gateway with session tokens and mTLS. |
| File sync | Push and pull files to/from sandboxes via tar-over-SSH. |
| Port forwarding | Forward local ports into sandboxes via SSH tunnels. |
| mTLS | Automatic PKI bootstrap and mutual TLS for all gateway communication. |

For supported providers, inference protocols, and platform requirements, refer to the [Support Matrix](support-matrix.md).
