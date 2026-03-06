---
title:
  page: "NemoClaw Tutorials"
  nav: "Tutorials"
description: "Step-by-step tutorials for running AI agents inside NemoClaw sandboxes."
keywords: ["nemoclaw tutorials", "claude code sandbox", "opencode sandbox", "openclaw sandbox"]
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

This section contains tutorials that help you run AI agents inside NemoClaw sandboxes. Each tutorial covers a different agent and setup, from a single-command quickstart to full policy iteration with inference routing.

::::{grid} 1 1 2 2
:gutter: 3

:::{grid-item-card} Run Claude Code Safely
:link: run-claude
:link-type: doc

Create a sandbox with a single command, auto-discover credentials, and work inside an isolated environment with the default policy.

+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Run OpenClaw Safely
:link: run-openclaw
:link-type: doc

Launch a community sandbox using the `--from` flag. Explore pre-built configurations bundled with tailored policies and container images.

+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Run OpenCode with NVIDIA Inference
:link: run-opencode
:link-type: doc

Write a custom policy, diagnose denied actions from logs, and configure inference routing to NVIDIA API endpoints.

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
