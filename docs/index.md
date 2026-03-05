<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Welcome to NemoClaw

NemoClaw is the safe, private runtime for autonomous AI agents. Run any coding agent in an isolated sandbox — fully protected, in two commands.

## Get Started

**Install the CLI and create a sandbox:**

```console
$ pip install nemoclaw
$ nemoclaw sandbox create -- claude
```

**Here's what happens:**

```
✓ Runtime ready
✓ Discovered Claude credentials (ANTHROPIC_API_KEY)
✓ Created sandbox: keen-fox
✓ Policy loaded (4 protection layers active)

Connecting to keen-fox...
```

Your agent is now running inside a sandbox with filesystem, network, process, and inference protection active. Credentials are safe, network access is policy-controlled, and inference traffic stays private.

Claude Code works out of the box with the default policy. For opencode or Codex, see the [tutorials](tutorials/claude-code.md) for agent-specific setup.

:::{note}
**Prerequisites:** Docker must be running and Python 3.12+ is required. If you
use [uv](https://docs.astral.sh/uv/), you can install with
`uv pip install nemoclaw` instead.
:::

**Or launch a community sandbox:**

```console
$ nemoclaw sandbox create --from openclaw
```

The `--from` flag pulls a pre-built sandbox from the [NemoClaw Community](https://github.com/NVIDIA/NemoClaw-Community) catalog — a growing collection of domain-specific sandbox images, each bundled with its own container, policy, and skills.

NemoClaw is built for developers, teams, and organizations running coding agents who need isolation, policy enforcement, and inference privacy --- without giving up productivity. You configure everything through a single YAML policy that is hot-reloadable on a running sandbox.

## What's Next

::::{grid} 2 2 3 3
:gutter: 3

:::{grid-item-card} Tutorials
:link: tutorials/claude-code
:link-type: doc

Step-by-step walkthroughs for Claude Code, OpenClaw, and opencode with NVIDIA inference.
:::

:::{grid-item-card} Security Model
:link: safety-and-privacy/security-model
:link-type: doc

How NemoClaw protects against data exfiltration, credential theft, unauthorized API calls, and privilege escalation.
:::

:::{grid-item-card} Sandboxes
:link: sandboxes/create-and-manage
:link-type: doc

Create, manage, and customize sandboxes. Use community images or bring your own container.
:::

:::{grid-item-card} Safety & Privacy
:link: safety-and-privacy/policies
:link-type: doc

Write policies that control what agents can access. Iterate on network rules in real time.
:::

:::{grid-item-card} Inference Routing
:link: inference/index
:link-type: doc

Keep inference traffic private by routing API calls to local or self-hosted backends.
:::

:::{grid-item-card} Reference
:link: reference/cli
:link-type: doc

CLI commands, policy schema, environment variables, and system architecture.
:::

::::

```{toctree}
:caption: Get Started
:hidden:

self
```

```{toctree}
:caption: Tutorials
:hidden:

tutorials/claude-code
tutorials/openclaw
tutorials/opencode-nvidia
```

```{toctree}
:caption: Sandboxes
:hidden:

sandboxes/create-and-manage
sandboxes/terminal
sandboxes/community-sandboxes
sandboxes/providers
sandboxes/custom-containers
```

```{toctree}
:caption: Safety & Privacy
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

reference/troubleshooting
```
