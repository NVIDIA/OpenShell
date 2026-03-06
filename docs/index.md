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
that protect your data, credentials, and infrastructure — agents run with exactly the permissions they need and 
nothing more, governed by declarative policies that prevent unauthorized file access, data exfiltration, and 
uncontrolled network activity.

## Install and Create a Sandbox

NemoClaw is designed for minimal setup with safety and privacy built in from the start. Two commands take you from zero to a running, policy-enforced sandbox.

### Prerequisites

The following are the prerequisites for the NemoClaw CLI.

- Docker must be running.
- Python 3.12+ is required.

### Install the NemoClaw CLI

```console
$ pip install nemoclaw
```

### Create Your First NemoClaw Sandbox

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

For OpenCode or Codex, see the [](get-started/tutorials/run-opencode.md) tutorial for agent-specific setup.

---

## Next Steps

::::{grid} 2 2 3 3
:gutter: 3

:::{grid-item-card} Tutorials
:link: get-started/tutorials/index
:link-type: doc

Step-by-step walkthroughs for Claude Code, OpenClaw, and OpenCode with NVIDIA inference.

+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Security Model
:link: safety-and-privacy/security-model
:link-type: doc

How NemoClaw protects against data exfiltration, credential theft, unauthorized API calls, and privilege escalation.

+++
{bdg-secondary}`Concept`
:::

:::{grid-item-card} Sandboxes
:link: sandboxes/create-and-manage
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
:hidden:

Get Started <self>
get-started/tutorials/index
```

```{toctree}
:caption: Concepts
:hidden:

Overview <about/index>
about/how-it-works
about/release-notes
```

```{toctree}
:caption: Sandboxes
:hidden:

sandboxes/index
sandboxes/create-and-manage
sandboxes/providers
sandboxes/custom-containers
sandboxes/community-sandboxes
sandboxes/port-forwarding
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
inference/create-routes
inference/manage-routes
inference/connect-sandboxes
```

```{toctree}
:caption: Clusters
:hidden:

clusters/index
clusters/remote-deploy
```

```{toctree}
:caption: Observability
:hidden:

observability/index
observability/logs
observability/health
```

```{toctree}
:caption: Reference
:hidden:

reference/index
about/support-matrix
reference/cli
reference/policy-schema
reference/environment-variables
reference/architecture
```

```{toctree}
:caption: Troubleshooting
:hidden:

troubleshooting/cluster-issues
troubleshooting/sandbox-issues
troubleshooting/provider-issues
troubleshooting/custom-container-issues
troubleshooting/port-forwarding-issues
troubleshooting/getting-more-information
```

```{toctree}
:caption: Resources
:hidden:

resources/index
```
