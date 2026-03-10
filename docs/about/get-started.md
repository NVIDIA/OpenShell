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
- Docker Desktop running on your machine <!-- TODO: add compatible version -->

## Install the OpenShell CLI

```bash
pip install nemoclaw
```

## Create Your First OpenShell Sandbox

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

## Next Steps

You now have a working sandbox! From here, you can:

- **Follow a guided tutorial** — set up scoped GitHub repo access in {doc}`/tutorials/github-sandbox`.
- **Learn how sandboxes work** — see {doc}`/sandboxes/create-and-manage` for the full lifecycle.
- **Write your own policies** — see {doc}`/sandboxes/policies` for custom access rules.
