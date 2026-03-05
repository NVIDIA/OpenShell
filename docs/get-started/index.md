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

# About Getting Started with NemoClaw

NemoClaw is designed for minimal setup with safety and privacy built in from the start. Docker is the only prerequisite. Three commands take you from zero to a running, policy-enforced sandbox.

::::{grid} 1 1 2 2
:gutter: 3

:::{grid-item-card} Installation
:link: installation
:link-type: doc

Prerequisites, install methods, shell completions, and verification steps for the NemoClaw CLI.
+++
{bdg-secondary}`Get Started`
:::

:::{grid-item-card} Tutorials
:link: tutorials/index
:link-type: doc

Step-by-step walkthrough from cluster bootstrap to an interactive sandbox session with policy enforcement.
+++
{bdg-secondary}`Tutorial`
:::

::::

---

## Next Steps

After you have a sandbox running, explore the following areas.

::::{grid} 1 1 2 2
:gutter: 3

:::{grid-item-card} Sandboxes
:link: ../sandboxes/index
:link-type: doc

Create, connect to, and manage sandboxes. Configure providers, sync files, forward ports, and bring your own containers.
+++
{bdg-secondary}`How To`
:::

:::{grid-item-card} Safety and Privacy
:link: ../security/index
:link-type: doc

Understand how NemoClaw keeps your data safe and private — and write policies that control filesystem, network, and inference access.
+++
{bdg-secondary}`Concept`
:::

:::{grid-item-card} Inference Routing
:link: ../inference/index
:link-type: doc

Route AI API calls to local or self-hosted backends without modifying agent code.
+++
{bdg-secondary}`How To`
:::

:::{grid-item-card} Reference
:link: ../reference/index
:link-type: doc

CLI command reference, policy schema, environment variables, and system architecture diagrams.
+++
{bdg-secondary}`Reference`
:::

::::
