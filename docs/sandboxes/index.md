---
title:
  page: About Gateways and Sandboxes
  nav: Gateways and Sandboxes
description: Understand gateways, gateway types, sandbox lifecycle, supported agents, built-in default policy, and network access rules in OpenShell.
topics:
- Generative AI
- Cybersecurity
tags:
- Gateway
- Sandboxing
- AI Agents
- Security
- Policy
- Isolation
content:
  type: concept
  difficulty: technical_beginner
  audience:
  - engineer
  - data_scientist
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Gateways and Sandboxes

Every OpenShell deployment starts with a *gateway* and one or more *sandboxes*. The gateway is the control plane that manages sandbox lifecycle, providers, and policies. A sandbox is the data plane, a safe, private execution environment where an AI agent runs. Each sandbox runs with multiple layers of protection that prevent unauthorized data access, credential exposure, and network exfiltration. Protection layers include filesystem restrictions (Landlock), system call filtering (seccomp), network namespace isolation, and a privacy-enforcing HTTP CONNECT proxy.

## Gateway Types

A gateway provisions sandboxes, brokers CLI requests, enforces policies, and manages provider credentials. OpenShell supports three deployment models, so the gateway can run wherever your workload requires.

| Type | Where It Runs | Best For |
|---|---|---|
| **Local** | Docker on your workstation | Solo development and quick iteration. The CLI auto-bootstraps a local gateway if none exists. |
| **Remote** | Docker on a remote host via SSH | Running sandboxes on a more powerful machine (for example, a DGX Spark) while keeping the CLI on your laptop. |
| **Cloud** | Behind a reverse proxy (for example, Cloudflare Access) | Individual users accessing OpenShell behind a cloud VM. Cloud gateways are not yet intended for shared team access. |

All three types expose the same API surface. Sandboxes, policies, and providers work identically regardless of where the gateway runs. The only difference is how the CLI reaches the gateway, whether through a direct Docker socket, SSH tunnel, or HTTPS through a proxy.

:::{tip}
You do not need to deploy a gateway manually. Running `openshell sandbox create` without a gateway auto-bootstraps a local one for you.
:::

## Sandbox Lifecycle

Every sandbox moves through a defined set of phases:

| Phase | Description |
|---|---|
| Provisioning | The runtime is setting up the sandbox environment, injecting credentials, and applying your policy. |
| Ready | The sandbox is running. The agent process is active and all isolation layers are enforced. You can connect, sync files, and view logs. |
| Error | Something went wrong during provisioning or execution. Check logs with `openshell logs` for details. |
| Deleting | The sandbox is being torn down. The system releases resources and purges credentials. |

## Sandbox Policies

OpenShell ships a built-in policy that covers common agent workflows out of the box.
When you create a sandbox without `--policy`, the default policy is applied. It controls three areas.

| Layer | What It Controls | How It Works |
|---|---|---|
| Filesystem | What the agent can access on disk | Paths are split into read-only and read-write sets. [Landlock LSM](https://docs.kernel.org/security/landlock.html) enforces these restrictions at the kernel level. |
| Network | What the agent can reach on the network | Each policy block pairs allowed destinations (host and port) with allowed binaries (executable paths). The proxy matches every outbound connection to the binary that opened it. Both must match or the connection is denied. |
| Process | What privileges the agent has | The agent runs as an unprivileged user with seccomp filters that block dangerous system calls. No `sudo`, no `setuid`, no path to elevated privileges. |

For the full breakdown of each default policy block and agent compatibility details, refer to {doc}`../reference/default-policy`.

For the full policy structure with annotated YAML examples, refer to {doc}`policies`.

## Next Steps

Continue with one of the following:

- To create your first sandbox, refer to {doc}`manage-sandboxes`.
- To supply API keys or tokens, refer to {doc}`manage-providers`.
- To control what the agent can access, refer to {doc}`policies`.
- To use a pre-built environment, refer to the {doc}`community-sandboxes` catalog.
