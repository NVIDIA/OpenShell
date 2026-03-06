---
title:
  page: "NVIDIA NemoClaw Developer Guide"
  nav: "Get Started"
  card: "NVIDIA NemoClaw"
description: "NemoClaw is the safe, private runtime for autonomous AI agents. Run agents in sandboxed environments that protect your data, credentials, and infrastructure."
topics:
- Generative AI
- Cybersecurity
tags:
- AI Agents
- Sandboxing
- Security
- Privacy
- Inference Routing
content:
  type: index
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# NVIDIA NemoClaw

[![GitHub](https://img.shields.io/badge/github-repo-green?logo=github)](https://github.com/NVIDIA/NemoClaw)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](https://github.com/NVIDIA/NemoClaw/blob/main/LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-nemoclaw-orange?logo=pypi)](https://pypi.org/project/nemoclaw/)

NemoClaw is the safe, private runtime for autonomous AI agents. It provides sandboxed execution environments
that protect your data, credentials, and infrastructure. Agents run with exactly the permissions they need and
nothing more, governed by declarative policies that prevent unauthorized file access, data exfiltration, and
uncontrolled network activity.

## Get Started

Install the CLI and create your first sandbox in two commands. Refer to the [Quickstart](get-started/quickstart.md) to get up and running.

```console
$ pip install nemoclaw
$ nemoclaw sandbox create -- claude
```

---

## Explore

::::{grid} 2 2 3 3
:gutter: 3

:::{grid-item-card} Tutorials
:link: get-started/tutorials
:link-type: doc

Step-by-step walkthroughs for Claude Code, OpenClaw, and OpenCode with NVIDIA inference.

+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Sandboxes
:link: sandboxes/index
:link-type: doc

Create, manage, and customize sandboxes. Use community images or bring your own container.

+++
{bdg-secondary}`Concept`
:::

:::{grid-item-card} Safety and Privacy
:link: safety-and-privacy/index
:link-type: doc

Write policies that control what agents can access. Iterate on network rules in real time.

+++
{bdg-secondary}`Concept`
:::

:::{grid-item-card} Inference Routing
:link: inference/index
:link-type: doc

Keep inference traffic private by routing API calls to local or self-hosted backends.

+++
{bdg-secondary}`Concept`
:::

:::{grid-item-card} Reference
:link: reference/cli
:link-type: doc

CLI commands, policy schema, environment variables, and system architecture.

+++
{bdg-secondary}`Reference`
:::

::::

```{toctree}
:caption: About
:hidden:

Overview <about/overview>
Architecture <about/architecture>
Release Notes <about/release-notes>
```

```{toctree}
:caption: Get Started
:hidden:

get-started/quickstart
get-started/tutorials
```

```{toctree}
:caption: Sandboxes
:hidden:

sandboxes/index
sandboxes/create-and-manage
sandboxes/providers
sandboxes/custom-containers
sandboxes/community-sandboxes
sandboxes/terminal
```

```{toctree}
:caption: Safety and Privacy
:hidden:

safety-and-privacy/index
safety-and-privacy/security-model
safety-and-privacy/policies
safety-and-privacy/network-access-rules
```

```{toctree}
:caption: Inference Routing
:hidden:

inference/index
inference/configure-routes
```

```{toctree}
:caption: Reference
:hidden:

reference/cli
reference/policy-schema
```

```{toctree}
:caption: Troubleshooting
:hidden:

troubleshooting
```

```{toctree}
:caption: Resources
:hidden:

resources/eula
```
