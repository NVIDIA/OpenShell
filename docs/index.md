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
.nc-term-agent {
  position: relative;
  display: inline-block;
  min-width: 9ch;
  height: 1.2em;
  vertical-align: baseline;
  color: #76b900;
  font-weight: 600;
}
.nc-term-agent span {
  position: absolute;
  left: 0;
  top: 0;
  white-space: nowrap;
  opacity: 0;
  animation: nc-cycle 9s ease-in-out infinite;
}
.nc-term-agent span:nth-child(1) { animation-delay: 0s; }
.nc-term-agent span:nth-child(2) { animation-delay: 3s; }
.nc-term-agent span:nth-child(3) { animation-delay: 6s; }
@keyframes nc-cycle {
  0%, 3%     { opacity: 0; transform: translateY(4px); }
  8%, 28%    { opacity: 1; transform: translateY(0); }
  33.33%, 100% { opacity: 0; transform: translateY(-4px); }
}
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
    <div><span class="nc-ps">$ </span>pip install nemoclaw</div>
    <div><span class="nc-ps">$ </span>nemoclaw sandbox create -- <span class="nc-term-agent"><span>claude</span><span>openclaw</span><span>opencode</span></span><span class="nc-cursor"></span></div>
  </div>
</div>
```

Refer to the [Quickstart](get-started/quickstart.md) for more details.

---

## Explore

::::{grid} 2 2 3 3
:gutter: 3

:::{grid-item-card} About NemoClaw
:link: about/overview
:link-type: doc

Learn about NemoClaw and its capabilities.

+++
{bdg-secondary}`Concept`
:::

:::{grid-item-card} Get Started
:link: get-started/quickstart
:link-type: doc

Quickstart guide and tutorials for creating a NemoClaw sandbox with Claude Code, OpenClaw, and OpenCode.

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
How It Works <about/architecture>
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
reference/architecture
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
