---
title:
  page: Create and Manage Sandboxes
  nav: Create and Manage
description: Create, inspect, connect to, monitor, transfer files, and delete OpenShell sandboxes.
topics:
- Generative AI
- Cybersecurity
tags:
- Sandboxing
- AI Agents
- Sandbox Management
- CLI
content:
  type: how_to
  difficulty: technical_beginner
  audience:
  - engineer
  - data_scientist
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Create and Manage Sandboxes

This page walks you through the full sandbox lifecycle: creating, inspecting, connecting to, monitoring, and deleting sandboxes. For background on what sandboxes are and how the runtime works, refer to [About Sandboxes](index.md).

:::{warning}
Docker must be running before you create a sandbox. If it is not, the CLI
returns a connection-refused error (`os error 61`) without explaining
the cause. Start Docker and try again.
:::

## Create a Sandbox

Run a single command to create a sandbox and launch your agent:

```console
$ openshell sandbox create -- claude
```

If you have an existing gateway, the sandbox is created in it. Otherwise, a gateway is created automatically.


A fully specified creation command might look like:

```console
$ openshell sandbox create \
    --name dev \
    --provider my-claude \
    --policy policy.yaml \
    --upload \
    --keep \
    -- claude
```

:::{tip}
Use `--keep` to keep the sandbox running after the trailing command exits.
This is especially useful when you are iterating on a policy or want to
reconnect later from another terminal or VS Code.
:::

## Create from a Community Sandbox or Custom Image

Use `--from` to create a sandbox from a pre-built community package, a local directory, or a container image:

```console
$ openshell sandbox create --from openclaw
```

The CLI resolves the name against the [OpenShell Community](https://github.com/NVIDIA/OpenShell-Community) catalog, pulls the bundled Dockerfile and policy, builds the image locally, and creates the sandbox. For the full catalog and how to contribute your own, refer to {doc}`community-sandboxes`.

You can also point `--from` at a local directory or a container image reference:

```console
$ openshell sandbox create --from ./my-sandbox-dir
$ openshell sandbox create --from my-registry.example.com/my-image:latest
```

## List and Inspect Sandboxes

Check the status of your sandboxes and retrieve detailed information about individual ones.

List all sandboxes:

```console
$ openshell sandbox list
```

Get detailed information about a specific sandbox:

```console
$ openshell sandbox get my-sandbox
```

## Connect to a Sandbox

Access a running sandbox through an interactive SSH session or VS Code Remote-SSH.

### Interactive SSH

Open an SSH session into a running sandbox:

```console
$ openshell sandbox connect my-sandbox
```

## View Logs

Stream and filter sandbox logs to monitor agent activity and diagnose policy decisions.

Stream sandbox logs:

```console
$ openshell logs my-sandbox
```

Use flags to filter and follow output:

| Flag | Purpose | Example |
|---|---|---|
| `--tail` | Stream logs in real time | `openshell logs my-sandbox --tail` |
| `--source` | Filter by log source | `--source sandbox` |
| `--level` | Filter by severity | `--level warn` |
| `--since` | Show logs from a time window | `--since 5m` |

## Monitor Your Sandbox

OpenShell Terminal is a real-time dashboard that combines sandbox status and live logs in a single view.

```console
$ openshell term
```

The dashboard shows the following information.

- **Sandbox status**: Name, phase, image, attached providers, age, and active port forwards.
- **Live log stream**: Omutbound connections, policy decisions, and inference interceptions as they happen. Logs are labeled by source: `sandbox` (proxy and policy events) or `gateway` (lifecycle events).

Use the terminal to spot blocked connections (`action=deny` entries) and inference interceptions (`action=inspect_for_inference` entries). If a connection is blocked unexpectedly, add the host to your network policy — refer to {doc}`policies` for the workflow.


## Transfer Files

Transfer files between your host machine and a running sandbox.

Upload files from your host into the sandbox:

```console
$ openshell sandbox upload my-sandbox ./src /sandbox/src
```

Download files from the sandbox to your host:

```console
$ openshell sandbox download my-sandbox /sandbox/output ./local
```

:::{note}
You can also upload files at creation time with the `--upload` flag on
`openshell sandbox create`.
:::

## Delete Sandboxes

Remove sandboxes when they are no longer needed. Deleting a sandbox stops all processes, releases cluster resources, and purges injected credentials.

Delete a sandbox by name:

```console
$ openshell sandbox delete my-sandbox
```

Delete all sandboxes in the active gateway:

```console
$ openshell sandbox delete --all
```

## Next Steps

Explore related topics:

- To follow a complete end-to-end example, refer to the {doc}`/tutorials/github-sandbox` tutorial.
- To supply API keys or tokens, refer to {doc}`providers`.
- To control what the agent can access, refer to {doc}`policies`.
- To use a pre-built environment, refer to the {doc}`community-sandboxes` catalog.