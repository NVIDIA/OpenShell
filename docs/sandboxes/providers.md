<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Providers

AI agents typically need credentials to access external services — an API key for the AI model provider, a token for GitHub or GitLab, and so on. NemoClaw manages these credentials as first-class entities called **providers**.

## How Providers Work

1. **You configure a provider once** — either by letting the CLI discover credentials from your local machine, or by providing them explicitly.
2. **Credentials are stored on the gateway** — separate from sandbox definitions. They never appear in Kubernetes pod specifications.
3. **Sandboxes receive credentials at runtime** — when a sandbox starts, the supervisor fetches credentials from the gateway and injects them as environment variables into every process it spawns.

This means you configure credentials once, and every sandbox that needs them receives them automatically.

## Supported Provider Types

| Type | Discovered Environment Variables | Discovered Config Paths |
|------|----------------------------------|------------------------|
| `claude` | `ANTHROPIC_API_KEY`, `CLAUDE_API_KEY` | `~/.claude.json`, `~/.claude/credentials.json`, `~/.config/claude/config.json` |
| `codex` | `OPENAI_API_KEY` | `~/.config/codex/config.json`, `~/.codex/config.json` |
| `opencode` | `OPENCODE_API_KEY`, `OPENROUTER_API_KEY`, `OPENAI_API_KEY` | `~/.config/opencode/config.json` |
| `github` | `GITHUB_TOKEN`, `GH_TOKEN` | `~/.config/gh/hosts.yml` |
| `gitlab` | `GITLAB_TOKEN`, `GLAB_TOKEN`, `CI_JOB_TOKEN` | `~/.config/glab-cli/config.yml` |
| `nvidia` | `NVIDIA_API_KEY` | — |
| `generic` | — | — |
| `outlook` | — | — |

## Creating Providers

### From Local Credentials (Auto-Discovery)

The easiest way to create a provider — the CLI scans your machine for existing credentials:

```console
$ nemoclaw provider create --name my-claude --type claude --from-existing
```

### With Explicit Credentials

```console
$ nemoclaw provider create --name my-api --type generic \
  --credential API_KEY=sk-abc123 \
  --config base_url=https://api.example.com
```

A bare key (without `=VALUE`) reads the value from the environment variable of that name:

```console
$ nemoclaw provider create --name my-api --type generic --credential API_KEY
```

## Managing Providers

```console
$ nemoclaw provider list
$ nemoclaw provider get my-claude
$ nemoclaw provider update my-claude --type claude --from-existing
$ nemoclaw provider delete my-claude
```

## Attaching Providers to Sandboxes

Specify providers at sandbox creation time:

```console
$ nemoclaw sandbox create --provider my-claude --provider my-github -- claude
```

Each attached provider's credentials are injected as environment variables into the sandbox. If multiple providers define the same environment variable, the first provider's value wins.

:::{warning}
Providers cannot be added to a running sandbox. If you need to attach an
additional provider, delete the sandbox and recreate it with all required
providers specified.
:::

## Privacy & Safety

NemoClaw manages credentials with a privacy-first design:

- **Credentials stay private** — stored separately from sandbox definitions, never in Kubernetes pod specs or container configurations.
- **Runtime-only injection** — credentials are fetched at runtime by the sandbox supervisor, minimizing exposure surface.
- **No credential leakage** — the CLI never displays credential values in its output.
- **Strict key validation** — only credential keys that are valid environment variable names (`^[A-Za-z_][A-Za-z0-9_]*$`) are injected; invalid keys are silently skipped.

### Auto-Discovery Shortcut

When the trailing command in `nemoclaw sandbox create` is a recognized tool name
--- `claude`, `codex`, or `opencode` --- the CLI auto-creates the required
provider from your local credentials if one does not already exist. You do not
need to create the provider separately:

```console
$ nemoclaw sandbox create -- claude
```

This detects `claude` as a known tool, finds your `ANTHROPIC_API_KEY`, creates
a provider, attaches it to the sandbox, and launches Claude Code.

## How Credentials Flow

Credentials follow a secure path from your machine into the agent process.

```{mermaid}
flowchart LR
    A["You create a provider"] --> B["Attach provider\nto sandbox at creation"]
    B --> C["Sandbox starts"]
    C --> D["Supervisor fetches\ncredentials from gateway"]
    D --> E["Credentials injected into\nagent process + SSH sessions"]
```

1. **You create a provider** with credentials from your environment or
   specified explicitly.
2. **You attach the provider to a sandbox** at creation time using the
   `--provider` flag (one or more providers can be attached).
3. **The sandbox starts.** The supervisor process initializes.
4. **The supervisor fetches credentials** from the NemoClaw gateway at runtime.
   Credentials are not stored in the sandbox specification --- they are
   retrieved on demand.
5. **Credentials are injected** into the agent process as environment variables.
   They are also available in SSH sessions when you connect to the sandbox.

:::{warning}
Credentials are never stored in the sandbox container specification. They are
fetched at runtime by the supervisor and held only in process memory. This
means credentials are not visible in container inspection, image layers, or
environment dumps of the container spec.
:::

## Supported Types

| Type | Environment Variables Injected | Typical Use |
|---|---|---|
| `claude` | `ANTHROPIC_API_KEY`, `CLAUDE_API_KEY` | Claude Code, Anthropic API |
| `codex` | `OPENAI_API_KEY` | OpenAI Codex |
| `opencode` | `OPENCODE_API_KEY`, `OPENROUTER_API_KEY`, `OPENAI_API_KEY` | opencode tool |
| `github` | `GITHUB_TOKEN`, `GH_TOKEN` | GitHub API, `gh` CLI |
| `gitlab` | `GITLAB_TOKEN`, `GLAB_TOKEN`, `CI_JOB_TOKEN` | GitLab API, `glab` CLI |
| `nvidia` | `NVIDIA_API_KEY` | NVIDIA API Catalog |
| `generic` | User-defined | Any service with custom credentials |
| `outlook` | *(none --- no auto-discovery)* | Microsoft Outlook integration |

:::{tip}
Use the `generic` type for any service not listed above. You define the
environment variable names and values yourself with `--credential`.
:::

## Next Steps

- {doc}`create-and-manage` --- full sandbox lifecycle management
- {doc}`custom-containers` --- use providers with custom container images
- {doc}`/safety-and-privacy/security-model` --- why credential isolation matters