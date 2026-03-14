---
title:
  page: Tutorials
  nav: Tutorials
description: Step-by-step walkthroughs for OpenShell, from first sandbox to production-ready policies.
topics:
- Generative AI
- Cybersecurity
tags:
- Tutorial
- Sandbox
- Policy
content:
  type: index
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Tutorials

Hands-on walkthroughs that teach OpenShell concepts by building real configurations. Each tutorial builds on the previous one, starting with core sandbox mechanics and progressing to production workflows.

::::{grid} 1 1 2 2
:gutter: 3

:::{grid-item-card} First Network Policy
:link: first-network-policy
:link-type: doc

Create a sandbox, observe default-deny networking, apply a read-only L7 policy, and inspect audit logs. No AI agent required.
+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} GitHub Push Access
:link: github-sandbox
:link-type: doc

Launch Claude Code in a sandbox, diagnose a policy denial, and iterate on a custom GitHub policy from outside the sandbox.
+++
{bdg-secondary}`Tutorial`
:::
::::

```{toctree}
:hidden:

First Network Policy <first-network-policy>
GitHub Push Access <github-sandbox>
```
