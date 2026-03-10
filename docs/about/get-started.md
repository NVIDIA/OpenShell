---
title:
  page: "Quickstart"
  nav: "Quickstart"
description: "Install the OpenShell CLI and create your first sandboxed AI agent in two commands."
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

- Python 3.12 or later
- [uv](https://docs.astral.sh/uv/) installed
- Docker Desktop running on your machine <!-- TODO: add compatible version -->

## Install the OpenShell CLI

Activate your virtual environment:

```bash
uv venv && source .venv/bin/activate
```

Install the CLI:

```bash
uv pip install nemoclaw
```

## Connect to a Remote Gateway (Optional)

If you're running locally, skip this step — the CLI creates a gateway automatically when you create your first sandbox.

:::::{tab-set}

::::{tab-item} Brev

:::{note}
Deploy an OpenShell gateway on Brev by hitting **Deploy** on the [OpenShell Launchable](https://brev.nvidia.com/launchable/deploy/now?launchableID=env-3AaK9NmCzWp3pVyUDNNFBt805FT).
:::

Once the instance is running, find the gateway URL in the Brev console under **Using Secure Links**. Copy the shareable URL for **port 8080** — this is the gateway endpoint.

```console
$ nemoclaw gateway add https://<your-port-8080-url>.brevlab.com
$ nemoclaw status
```

::::

::::{tab-item} DGX Spark

:::{note}
Set up your Spark with NVIDIA Sync first, or make sure SSH access is configured (e.g., SSH keys added to the host).
:::

Deploy to a DGX Spark machine over SSH:

```console
$ nemoclaw gateway start --remote <username>@<spark-ssid>.local
$ nemoclaw status
```

Once `nemoclaw status` shows the gateway as healthy, all subsequent commands route through the SSH tunnel.

::::

:::::

## Create Your First OpenShell Sandbox

Choose the tab that matches your agent:

::::{tab-set}

:::{tab-item} Claude Code
```console
$ nemoclaw sandbox create -- claude
```

The CLI prompts you to create a provider from local credentials — type `yes` to continue. If `ANTHROPIC_API_KEY` is set in your environment, it is picked up automatically. If not, you can configure it from inside the sandbox after it launches.
:::

:::{tab-item} OpenCode
```console
$ nemoclaw sandbox create -- opencode
```

The CLI prompts you to create a provider from local credentials — type `yes` to continue. If `OPENAI_API_KEY` or `OPENROUTER_API_KEY` is set in your environment, it is picked up automatically. If not, you can configure it from inside the sandbox after it launches.
:::

:::{tab-item} Codex
```console
$ nemoclaw sandbox create -- codex
```

The CLI prompts you to create a provider from local credentials — type `yes` to continue. If `OPENAI_API_KEY` is set in your environment, it is picked up automatically. If not, you can configure it from inside the sandbox after it launches.
:::

:::{tab-item} Community Sandbox
```console
$ nemoclaw sandbox create --from openclaw
```

The `--from` flag pulls a pre-built sandbox definition from the [NemoClaw Community](https://github.com/NVIDIA/NemoClaw-Community) catalog. Each definition bundles a container image, a tailored policy, and optional skills into a single package.
:::

::::

## Next Steps

You now have a working sandbox! From here, you can:

- **Follow a guided tutorial** — set up scoped GitHub repo access in {doc}`/tutorials/github-sandbox`.
- **Learn how sandboxes work** — see {doc}`/sandboxes/create-and-manage` for the full lifecycle.
- **Write your own policies** — see {doc}`/sandboxes/policies` for custom access rules.
