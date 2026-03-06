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

NemoClaw is designed for minimal setup with safety and privacy built in from the start. Two commands take you from zero to a running, policy-enforced sandbox.

## Prerequisites

The following are the prerequisites for the NemoClaw CLI.

- Docker must be running.
- Python 3.12+ is required.

## Install the NemoClaw CLI

```console
$ pip install nemoclaw
```

## Create Your First NemoClaw Sandbox

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

The `--from` flag pulls from the [NemoClaw Community](https://github.com/NVIDIA/NemoClaw-Community) catalog, which contains a collection of domain-specific sandbox images bundled with their own containers, policies, and skills.
:::

::::

The agent runs with filesystem, network, process, and inference protection active. Credentials stay inside the sandbox, network access follows your policy, and inference traffic remains private. A single YAML policy controls all four protection layers and is hot-reloadable on a running sandbox.

For OpenCode or Codex, refer to the [Run OpenCode with NVIDIA Inference](run-opencode.md) tutorial for agent-specific setup.

## Next Steps

- [Tutorials](tutorials.md): Step-by-step walkthroughs for Claude Code, OpenClaw, and OpenCode.
- [Sandboxes](../sandboxes/create-and-manage.md): Understand the isolation model and sandbox lifecycle.
- [Safety and Privacy](../safety-and-privacy/index.md): Write policies that control what agents can access.
