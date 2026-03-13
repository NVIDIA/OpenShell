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

- **{doc}`sandbox-policy-quickstart`**: Create a sandbox, observe default-deny networking, apply a read-only L7 policy, and inspect audit logs. No AI agent required.
- **{doc}`github-sandbox`**: Launch Claude Code in a sandbox, diagnose a policy denial, and iterate on a custom GitHub policy from outside the sandbox.

```{toctree}
:hidden:

Basic Walkthrough <sandbox-policy-quickstart>
GitHub Sandbox <github-sandbox>
```
