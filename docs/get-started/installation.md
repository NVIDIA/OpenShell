---
title:
  page: "About Getting Started with NemoClaw"
  nav: "About Getting Started"
  card: "About Getting Started"
description: "Install the CLI, bootstrap a cluster, and launch your first sandbox in minutes."
topics:
- Get Started
tags:
- Installation
- Quickstart
- Sandbox
- CLI
content:
  type: get_started
  difficulty: technical_beginner
  audience:
  - engineer
  - ai_engineer
  - devops
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Install and Create a Sandbox

NemoClaw is designed for minimal setup with safety and privacy built in from the start. Two commands take you from zero to a running, policy-enforced sandbox.

## Prerequisites

The following are the prerequisites for the NemoClaw CLI.

- Docker must be running.
- Python 3.12+ is required.

## Install the CLI

```console
$ pip install nemoclaw
```

## Create a Sandbox

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

Claude Code works out of the box with the default policy.
:::

:::{tab-item} Community Sandbox
```console
$ nemoclaw sandbox create --from openclaw
```

The `--from` flag pulls from the [NemoClaw Community](https://github.com/NVIDIA/NemoClaw-Community) catalog --- a collection of domain-specific sandbox images bundled with their own containers, policies, and skills.
:::

::::

The agent runs with filesystem, network, process, and inference protection active. Credentials stay inside the sandbox, network access follows your policy, and inference traffic remains private. A single YAML policy controls all four protection layers and is hot-reloadable on a running sandbox.

For opencode or Codex, see the [Tutorials](tutorials/index.md) for agent-specific setup.
