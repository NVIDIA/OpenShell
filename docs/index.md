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
    <div><span class="nc-ps">$ </span>uv tool install -U openshell</div>
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

:::{grid-item-card} Tutorials
:link: tutorials/index
:link-type: doc

Hands-on walkthroughs from first sandbox to custom policies.

+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Gateways and Sandboxes
:link: sandboxes/manage-gateways
:link-type: doc

Deploy gateways, create sandboxes, configure policies, providers, and community images for your AI agents.

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
:link: reference/default-policy
:link-type: doc

Policy schema, environment variables, and system architecture.

+++
{bdg-secondary}`Reference`
:::

:::{grid-item-card} Security Best Practices
:link: security/best-practices
:link-type: doc

Every configurable security control, its default, and the risk of changing it.

+++
{bdg-secondary}`Concept`
:::

::::

---

```{admonition} Notice and Disclaimer
:class: warning

This software automatically retrieves, accesses or interacts with external materials. Those retrieved materials are not distributed with this software and are governed solely by separate terms, conditions and licenses. You are solely responsible for finding, reviewing and complying with all applicable terms, conditions, and licenses, and for verifying the security, integrity and suitability of any retrieved materials for your specific use case. This software is provided "AS IS", without warranty of any kind. The author makes no representations or warranties regarding any retrieved materials, and assumes no liability for any losses, damages, liabilities or legal consequences from your use or inability to use this software or any retrieved materials. Use this software and the retrieved materials at your own risk.
```

```{toctree}
:hidden:

Home <self>
```

```{toctree}
:caption: About NVIDIA OpenShell
:hidden:

Overview <about/overview>
How It Works <about/architecture>
Supported Agents <about/supported-agents>
Release Notes <about/release-notes>
```

```{toctree}
:caption: Get Started
:hidden:

Quickstart <get-started/quickstart>
tutorials/index
```

```{toctree}
:caption: Gateways and Sandboxes
:hidden:

sandboxes/index
Sandboxes <sandboxes/manage-sandboxes>
Gateways <sandboxes/manage-gateways>
Providers <sandboxes/manage-providers>
Policies <sandboxes/policies>
Community Sandboxes <sandboxes/community-sandboxes>
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

reference/gateway-auth
reference/default-policy
reference/policy-schema
reference/support-matrix
```

```{toctree}
:caption: Security
:hidden:

security/best-practices
```

```{toctree}
:caption: Resources
:hidden:

resources/license
```
