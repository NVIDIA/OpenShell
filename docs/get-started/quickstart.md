---
title:
  page: "Quickstart"
  nav: "Quickstart"
description: "Install the NemoClaw CLI and create your first sandboxed AI agent in two commands."
keywords: ["nemoclaw install", "quickstart", "sandbox create", "getting started"]
topics: ["generative_ai", "cybersecurity"]
tags: ["ai_agents", "sandboxing", "installation", "quickstart"]
content:
  type: get_started
  difficulty: technical_beginner
  audience: [engineer, data_scientist]
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Quickstart

This page gets you from zero to a running, policy-enforced sandbox in two commands.

## Prerequisites

Before you begin, make sure you have:

- Docker installed and running. <!--Need to specify the Docker version-->
- Python 3.12 or later.

## Install the NemoClaw CLI

Install the NemoClaw CLI from PyPI.

```console
$ pip install nemoclaw
```

## Create Your First NemoClaw Sandbox

Choose the tab that matches your agent:

::::{tab-set}

:::{tab-item} Claude Code
```console
$ nemoclaw sandbox create -- claude
```

```text
✓ Runtime ready
✓ Discovered Claude credentials (ANTHROPIC_API_KEY)
✓ Created sandbox: keen-fox
✓ Policy loaded (4 protection layers active)

Connecting to keen-fox...
```

The CLI detects your `ANTHROPIC_API_KEY`, creates a provider, builds the sandbox, applies a default policy, and drops you into an interactive session. No additional configuration is required.
:::

:::{tab-item} Community Sandbox
```console
$ nemoclaw sandbox create --from openclaw
```

The `--from` flag pulls a pre-built sandbox definition from the [NemoClaw Community](https://github.com/NVIDIA/NemoClaw-Community) catalog. Each definition bundles a container image, a tailored policy, and optional skills into a single package.
:::

::::

## What Happens Behind the Scenes

When you create a sandbox, NemoClaw activates four protection layers:

- **Filesystem isolation.** The agent can only read and write paths that the policy explicitly permits.
- **Network enforcement.** Outbound connections are denied by default. The policy allowlists specific hosts, ports, and binaries.
- **Process restrictions.** The agent runs as a non-root user inside the container.
- **Inference privacy.** LLM API traffic is routed through a privacy-aware proxy. Credentials never leak outside the sandbox.

A single YAML policy file controls all four layers. You can hot-reload network and inference rules on a running sandbox without restarting it.

:::{note}
For OpenCode or Codex, the default policy does not cover the required endpoints. Follow the [Run OpenCode with NVIDIA Inference](run-opencode.md) tutorial for agent-specific setup.
:::

## Next Steps

You now have a working sandbox. From here, you can:

- Follow the [Tutorials](tutorials.md) for step-by-step walkthroughs with Claude Code, OpenClaw, and OpenCode.
- Learn how sandboxes work in [Sandboxes](../sandboxes/create-and-manage.md).
- Write your own policies in [Safety and Privacy](../safety-and-privacy/index.md).
