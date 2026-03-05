---
title:
  page: "NVIDIA NemoClaw Developer Guide"
  nav: "NVIDIA NemoClaw"
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

# NVIDIA NemoClaw Developer Guide

NemoClaw is the safe, private runtime for autonomous AI agents. It provides sandboxed execution environments 
that protect your data, credentials, and infrastructure — agents run with exactly the permissions they need and 
nothing more, governed by declarative policies that prevent unauthorized file access, data exfiltration, and 
uncontrolled network activity.

---

## About NemoClaw

Understand what NemoClaw is, how the subsystems fit together, and what is new in the latest release.

::::{grid} 1 1 2 2
:gutter: 3

:::{grid-item-card} NemoClaw Overview
:link: about/index
:link-type: doc

Learn about the safety and privacy model, key capabilities, and use cases for sandboxed agent execution.
+++
{bdg-secondary}`Concept`
:::

:::{grid-item-card} How It Works
:link: about/how-it-works
:link-type: doc

Explore the architecture, major subsystems, and the end-to-end flow from cluster bootstrap to running sandbox.
+++
{bdg-secondary}`Concept`
:::

:::{grid-item-card} Support Matrix
:link: about/support-matrix
:link-type: doc

Platform requirements, supported providers, agent tools, and compatibility details.
+++
{bdg-secondary}`Reference`
:::

:::{grid-item-card} Release Notes
:link: about/release-notes
:link-type: doc

Track what changed in each version.
+++
{bdg-secondary}`Reference`
:::

::::

## Get Started

Install the CLI, bootstrap a cluster, and create your first sandbox.

::::{grid} 1 1 2 2
:gutter: 3

:::{grid-item-card} About Getting Started
:link: get-started/installation
:link-type: doc

Install the CLI, bootstrap a cluster, and launch your first sandbox in minutes.
+++
{bdg-secondary}`Get Started`
:::

:::{grid-item-card} Tutorials
:link: get-started/tutorials/index
:link-type: doc

Create, connect to, and manage sandboxes. Configure providers, sync files, forward ports, and bring your own containers.
+++
{bdg-secondary}`How To`
:::

::::

## Developer Guides

Configure safety policies, route inference traffic, manage clusters, and monitor agent activity.

::::{grid} 1 1 2 2
:gutter: 3

:::{grid-item-card} Safety and Privacy
:link: safety-and-privacy/index
:link-type: doc

Understand how NemoClaw keeps your data safe and private — and write policies that control filesystem, network, and inference access.
+++
{bdg-secondary}`Concept`
:::

:::{grid-item-card} Inference Routing
:link: inference/index
:link-type: doc

Keep inference traffic private by routing AI API calls to local or self-hosted backends — without modifying agent code.
+++
{bdg-secondary}`How To`
:::

:::{grid-item-card} Clusters
:link: clusters/index
:link-type: doc

Bootstrap, manage, and deploy NemoClaw clusters locally or on remote hosts via SSH.
+++
{bdg-secondary}`How To`
:::

:::{grid-item-card} Observability
:link: observability/index
:link-type: doc

Stream sandbox logs, audit agent activity, and monitor policy enforcement with the Gator TUI and CLI.
+++
{bdg-secondary}`How To`
:::

::::

## References

Look up CLI commands, policy schemas, environment variables, and troubleshooting guidance.

::::{grid} 1 1 2 2
:gutter: 3

:::{grid-item-card} Reference
:link: reference/index
:link-type: doc

CLI command reference, policy schema, environment variables, and system architecture diagrams.
+++
{bdg-secondary}`Reference`
:::

:::{grid-item-card} Troubleshooting
:link: troubleshooting/cluster-issues
:link-type: doc

Diagnose common issues with clusters, sandboxes, and networking.
+++
{bdg-secondary}`Troubleshooting`
:::

:::{grid-item-card} Resources
:link: resources/index
:link-type: doc

Links to the GitHub repository, related projects, and additional learning materials.
+++
{bdg-secondary}`Reference`
:::

::::

```{toctree}
:caption: About
:hidden:

Overview <about/index>
about/how-it-works
about/support-matrix
about/release-notes
```

```{toctree}
:caption: Get Started
:hidden:

get-started/installation
get-started/tutorials/index
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
