---
title:
  page: "OpenShell Tutorials"
  nav: "Tutorials"
description: "Step-by-step tutorials for running AI agents inside OpenShell sandboxes."
keywords: ["openshell tutorials", "claude code sandbox", "opencode sandbox", "openclaw sandbox"]
topics: ["generative_ai", "cybersecurity"]
tags: ["ai_agents", "sandboxing", "tutorial"]
content:
  type: tutorial
  difficulty: technical_beginner
  audience: [engineer, data_scientist]
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Tutorials

Each tutorial below walks you through running a specific AI agent inside a OpenShell sandbox. Choose the tutorial that matches your agent.

::::{grid} 1 1 2 2
:gutter: 3

:::{grid-item-card} Run Claude Code Safely
:link: run-claude
:link-type: doc

Create a sandbox with Claude Code.

+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Run OpenClaw Safely
:link: run-openclaw
:link-type: doc

Launch a sandbox with OpenClaw from the OpenShell Community catalog using the `--from` flag.

+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Run OpenCode with NVIDIA Inference
:link: run-opencode
:link-type: doc

Launch a sandbox with OpenCode with NVIDIA inference routed to NVIDIA API endpoints.

+++
{bdg-secondary}`Tutorial`
:::

::::

```{toctree}
:hidden:
:maxdepth: 2

Run Claude Code Safely <run-claude>
Run OpenClaw Safely <run-openclaw>
Run OpenCode with NVIDIA Inference <run-opencode>
```
