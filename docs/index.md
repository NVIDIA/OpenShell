<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# NVIDIA NemoClaw Developer Guide

NemoClaw is the safe, private runtime for autonomous AI agents. It provides sandboxed execution environments that protect your data, credentials, and infrastructure — agents run with exactly the permissions they need and nothing more, governed by declarative policies that prevent unauthorized file access, data exfiltration, and uncontrolled network activity.

::::{grid} 2 2 3 3
:gutter: 3

:::{grid-item-card} About
:link: about/index
:link-type: doc

Learn what NemoClaw is, how the subsystems fit together, and the safety and privacy model that protects your data and infrastructure.
:::

:::{grid-item-card} Get Started
:link: get-started/index
:link-type: doc

Install the CLI, bootstrap a cluster, and launch your first sandbox in minutes.
:::

:::{grid-item-card} Sandboxes
:link: sandboxes/index
:link-type: doc

Create, connect to, and manage sandboxes with built-in safety guarantees. Configure providers, sync files, forward ports, and bring your own containers.
:::

:::{grid-item-card} Safety and Privacy
:link: security/index
:link-type: doc

Understand how NemoClaw keeps your data safe and private — and write policies that control filesystem, network, and inference access.
:::

:::{grid-item-card} Inference Routing
:link: inference/index
:link-type: doc

Keep inference traffic private by routing AI API calls to local or self-hosted backends — without modifying agent code.
:::

:::{grid-item-card} Clusters
:link: clusters/index
:link-type: doc

Bootstrap, manage, and deploy NemoClaw clusters locally or on remote hosts via SSH.
:::

:::{grid-item-card} Gator TUI
:link: gator/index
:link-type: doc

Use the keyboard-driven terminal dashboard for real-time cluster monitoring and sandbox management.
:::

:::{grid-item-card} Observability
:link: observability/index
:link-type: doc

Stream sandbox logs, audit agent activity, and monitor policy enforcement in real time.
:::

:::{grid-item-card} Reference
:link: reference/index
:link-type: doc

CLI command reference, policy schema, environment variables, and system architecture diagrams.
:::

:::{grid-item-card} Troubleshooting
:link: troubleshooting/index
:link-type: doc

Diagnose common issues with clusters, sandboxes, and networking.
:::

:::{grid-item-card} Resources
:link: resources/index
:link-type: doc

Links to the GitHub repository, related projects, and additional learning materials.
:::

::::

```{toctree}
:caption: About
:hidden:

about/index
about/how-it-works
about/support-matrix
about/release-notes
```

```{toctree}
:caption: Get Started
:hidden:

get-started/index
get-started/installation
get-started/first-sandbox
```

```{toctree}
:caption: Sandboxes
:hidden:

sandboxes/index
sandboxes/create-and-manage
sandboxes/providers
sandboxes/custom-containers
sandboxes/file-sync
sandboxes/port-forwarding
```

```{toctree}
:caption: Safety and Privacy
:hidden:

security/index
security/policies
security/network-access
```

```{toctree}
:caption: Inference Routing
:hidden:

inference/index
```

```{toctree}
:caption: Clusters
:hidden:

clusters/index
clusters/remote-deploy
```

```{toctree}
:caption: Gator TUI
:hidden:

gator/index
```

```{toctree}
:caption: Observability
:hidden:

observability/index
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

troubleshooting/index
```

```{toctree}
:caption: Resources
:hidden:

resources/index
```
