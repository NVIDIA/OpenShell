<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Support Matrix

This page lists the platforms, kernel features, providers, protocols, and tools that NVIDIA NemoClaw supports.

## Platform Requirements

The following software and runtime dependencies are required to install and run NemoClaw.

| Requirement | Supported |
|-------------|-----------|
| **Operating System** | Linux (sandbox runtime). macOS and Linux (CLI). |
| **Docker** | Required for cluster bootstrap. |
| **Python** | 3.12+ (for CLI installation with `pip`). |
| **Rust** | 1.88+ (for building from source). |
| **Kubernetes** | k3s (bundled, no external cluster needed). |

## Linux Kernel Features

The sandbox isolation mechanisms require the following Linux kernel features:

| Feature | Minimum Kernel | Purpose |
|---------|---------------|---------|
| **Landlock** | 5.13+ (ABI V1) | Filesystem access restriction. |
| **seccomp-BPF** | 3.5+ | System call filtering. |
| **Network namespaces** | 2.6.29+ | Network isolation for sandbox processes. |
| **`/proc` filesystem** | — | Process identity resolution for proxy. |

:::{note}
When `landlock.compatibility` is set to `best_effort` (the default), the sandbox runs with the best available Landlock ABI. Set to `hard_requirement` to fail startup if the required ABI is not available.
:::

## Supported Provider Types

Providers supply credentials to sandboxes. NemoClaw can auto-discover credentials from environment variables and config files on your local machine.

| Type | Environment Variables Injected | Typical Use |
|---|---|---|
| `claude` | `ANTHROPIC_API_KEY`, `CLAUDE_API_KEY` | Claude Code, Anthropic API |
| `codex` | `OPENAI_API_KEY` | OpenAI Codex |
| `opencode` | `OPENCODE_API_KEY`, `OPENROUTER_API_KEY`, `OPENAI_API_KEY` | opencode tool |
| `github` | `GITHUB_TOKEN`, `GH_TOKEN` | GitHub API, `gh` CLI |
| `gitlab` | `GITLAB_TOKEN`, `GLAB_TOKEN`, `CI_JOB_TOKEN` | GitLab API, `glab` CLI |
| `nvidia` | `NVIDIA_API_KEY` | NVIDIA API Catalog |
| `generic` | User-defined | Any service with custom credentials |
| `outlook` | *(none, no auto-discovery)* | Microsoft Outlook integration |

:::{tip}
Use the `generic` type for any service not listed above. You define the
environment variable names and values yourself with `--credential`.
:::

## Supported Inference Protocols

Inference routing intercepts AI API calls and reroutes them to policy-controlled backends. The following protocols are recognized for interception.

| Protocol | API Pattern | Method | Path |
|----------|-------------|--------|------|
| `openai_chat_completions` | OpenAI Chat | POST | `/v1/chat/completions` |
| `openai_completions` | OpenAI Completions | POST | `/v1/completions` |
| `anthropic_messages` | Anthropic Messages | POST | `/v1/messages` |

## Supported Agent Tools

The following tools are recognized by `nemoclaw sandbox create -- <tool>` for auto-provider discovery:

| Tool | Provider Type | Notes |
|------|--------------|-------|
| `claude` | `claude` | Auto-discovers Anthropic credentials. |
| `codex` | `codex` | Auto-discovers OpenAI credentials. |
| `opencode` | `opencode` | Auto-discovers OpenCode/OpenRouter credentials. |

## Network Policy Features

The network proxy enforces policies at layers 4 and 7. The following table summarizes the available policy capabilities.

| Feature | Support |
|---------|---------|
| L4 allow/deny (host + port) | Supported |
| Per-binary access control | Supported (glob patterns) |
| Binary integrity (TOFU) | Supported (SHA256) |
| SSRF protection (private IP blocking) | Supported |
| L7 HTTP inspection | Supported (TLS termination) |
| L7 enforcement modes | `enforce`, `audit` |
| L7 access presets | `read-only`, `read-write`, `full` |
| Inference interception | Supported |

## Container Image Compatibility (BYOC)

Bring Your Own Container lets you run custom images as sandboxes. Image compatibility depends on the libraries and tools available in the image.

| Image Type | Supported | Notes |
|------------|-----------|-------|
| Standard Linux images | Yes | Must have glibc and `/proc`. |
| Alpine / musl-based | Yes | Requires `iproute2` for proxy mode. |
| Distroless / `FROM scratch` | No | Supervisor needs glibc, `/proc`, and a shell. |
| Images without `iproute2` | Partial | Works in Block mode; fails in Proxy mode. |

## Database Backends

The gateway server stores cluster state in a database. SQLite is the default and requires no configuration.

| Backend | Support |
|---------|---------|
| SQLite | Default. No configuration needed. |
| PostgreSQL | Supported as an alternative. |
