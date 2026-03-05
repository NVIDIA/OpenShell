<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Support Matrix

## Platform Requirements

| Requirement | Supported |
|-------------|-----------|
| **Operating System** | Linux (sandbox runtime). macOS and Linux (CLI). |
| **Docker** | Required for cluster bootstrap. |
| **Python** | 3.12+ (for CLI installation via `pip`). |
| **Rust** | 1.88+ (for building from source). |
| **Kubernetes** | k3s (bundled — no external cluster needed). |

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

| Provider | Type Slug | Auto-Discovery |
|----------|-----------|----------------|
| Anthropic Claude | `claude` | `ANTHROPIC_API_KEY`, `CLAUDE_API_KEY`, `~/.claude.json` |
| OpenAI Codex | `codex` | `OPENAI_API_KEY`, `~/.config/codex/config.json` |
| OpenCode | `opencode` | `OPENCODE_API_KEY`, `OPENROUTER_API_KEY`, `OPENAI_API_KEY` |
| GitHub | `github` | `GITHUB_TOKEN`, `GH_TOKEN`, `~/.config/gh/hosts.yml` |
| GitLab | `gitlab` | `GITLAB_TOKEN`, `GLAB_TOKEN`, `~/.config/glab-cli/config.yml` |
| NVIDIA | `nvidia` | `NVIDIA_API_KEY` |
| Generic | `generic` | Manual only (`--credential KEY=VALUE`) |
| Outlook | `outlook` | Manual only |

## Supported Inference Protocols

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

| Image Type | Supported | Notes |
|------------|-----------|-------|
| Standard Linux images | Yes | Must have glibc and `/proc`. |
| Alpine / musl-based | Yes | Requires `iproute2` for proxy mode. |
| Distroless / `FROM scratch` | No | Supervisor needs glibc, `/proc`, and a shell. |
| Images without `iproute2` | Partial | Works in Block mode; fails in Proxy mode. |

## Database Backends

| Backend | Support |
|---------|---------|
| SQLite | Default. No configuration needed. |
| PostgreSQL | Supported as an alternative. |
