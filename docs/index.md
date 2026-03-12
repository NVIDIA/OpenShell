---
title:
  page: NVIDIA OpenShell Developer Guide
  nav: Get Started
  card: NVIDIA OpenShell
description: OpenShell is the safe, private runtime for autonomous AI agents. Run agents in sandboxed environments that protect your data, credentials, and infrastructure.
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

# NVIDIA OpenShell

[![GitHub](https://img.shields.io/badge/github-repo-green?logo=github)](https://github.com/NVIDIA/OpenShell)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](https://github.com/NVIDIA/OpenShell/blob/main/LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-openshell-orange?logo=pypi)](https://pypi.org/project/openshell/)

NVIDIA OpenShell is the safe, private runtime for autonomous AI agents. It provides sandboxed execution environments
that protect your data, credentials, and infrastructure. Agents run with exactly the permissions they need and
nothing more, governed by declarative policies that prevent unauthorized file access, data exfiltration, and
uncontrolled network activity.

## Get Started

Install the CLI and create your first sandbox in two commands.

```{raw} html
<style>
.nc-term {
  background: #1a1a2e;
  border-radius: 8px;
  overflow: hidden;
  margin: 1.5em 0;
  box-shadow: 0 4px 16px rgba(0,0,0,0.25);
  font-family: 'SFMono-Regular', Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
  font-size: 0.875em;
  line-height: 1.8;
}
.nc-term-bar {
  background: #252545;
  padding: 10px 14px;
  display: flex;
  gap: 7px;
  align-items: center;
}
.nc-term-dot { width: 12px; height: 12px; border-radius: 50%; }
.nc-term-dot-r { background: #ff5f56; }
.nc-term-dot-y { background: #ffbd2e; }
.nc-term-dot-g { background: #27c93f; }
.nc-term-body { padding: 16px 20px; color: #d4d4d8; }
.nc-term-body .nc-ps { color: #76b900; user-select: none; }
.nc-swap {
  display: inline-grid;
  vertical-align: baseline;
}
.nc-swap > span {
  grid-area: 1 / 1;
  white-space: nowrap;
  opacity: 0;
  animation: nc-cycle 12s ease-in-out infinite;
}
.nc-swap > span:nth-child(2) { animation-delay: 3s; }
.nc-swap > span:nth-child(3) { animation-delay: 6s; }
.nc-swap > span:nth-child(4) { animation-delay: 9s; }
@keyframes nc-cycle {
  0%, 3%     { opacity: 0; }
  5%, 20%    { opacity: 1; }
  25%, 100%  { opacity: 0; }
}
.nc-hl { color: #76b900; font-weight: 600; }
.nc-cursor {
  display: inline-block;
  width: 2px;
  height: 1.1em;
  background: #d4d4d8;
  vertical-align: text-bottom;
  margin-left: 1px;
  animation: nc-blink 1s step-end infinite;
}
@keyframes nc-blink { 50% { opacity: 0; } }
</style>
<div class="nc-term">
  <div class="nc-term-bar">
    <span class="nc-term-dot nc-term-dot-r"></span>
    <span class="nc-term-dot nc-term-dot-y"></span>
    <span class="nc-term-dot nc-term-dot-g"></span>
  </div>
  <div class="nc-term-body">
    <div><span class="nc-ps">$ </span>uv pip install openshell</div>
    <div><span class="nc-ps">$ </span>openshell sandbox create <span class="nc-swap"><span>-- <span class="nc-hl">claude</span></span><span>--from <span class="nc-hl">openclaw</span></span><span>-- <span class="nc-hl">opencode</span></span><span>-- <span class="nc-hl">codex</span></span></span><span class="nc-cursor"></span></div>
  </div>
</div>
```

Refer to the [Quickstart](get-started/quickstart.md) for more details.

---

## Explore

::::{grid} 2 2 3 3
:gutter: 3

:::{grid-item-card} About OpenShell
:link: about/overview
:link-type: doc

Learn about OpenShell and its capabilities.

+++
{bdg-secondary}`Concept`
:::

:::{grid-item-card} Quickstart
:link: get-started/quickstart
:link-type: doc

Install the CLI and create your first sandbox in two commands.

+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Set Up a Sandbox with GitHub Repo Access
:link: tutorials/github-sandbox
:link-type: doc

End-to-end guides: GitHub repo access, custom policies, and more.

+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Sandboxes
:link: sandboxes/index
:link-type: doc

Create, manage, and customize sandboxes. Configure policies, providers, and community images.

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

Home <self>
```

```{toctree}
:caption: About NVIDIA OpenShell
:hidden:

Overview <about/overview>
How It Works <about/architecture>
Release Notes <about/release-notes>
```

```{toctree}
:caption: Get Started
:hidden:

Quickstart <get-started/quickstart>
Tutorial: GitHub Policy Iteration <tutorials/github-sandbox>
```

```{toctree}
:caption: Sandboxes
:hidden:

sandboxes/index
sandboxes/create-and-manage
sandboxes/providers
sandboxes/policies
sandboxes/community-sandboxes
```

```{toctree}
:caption: Inference Routing
:hidden:

inference/index
inference/configure
```

```{toctree}
:caption: Reference
:hidden:

reference/cli
reference/default-policy
reference/policy-schema
reference/support-matrix
```

```{toctree}
:caption: Resources
:hidden:

resources/eula
```
