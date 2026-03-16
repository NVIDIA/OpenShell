---
title:
  page: Manage Sandboxes
  nav: Sandboxes
description: Set up gateways, create sandboxes, and manage the full sandbox lifecycle.
topics:
- Generative AI
- Cybersecurity
tags:
- Gateway
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

# Manage Sandboxes

This page covers creating sandboxes and managing them. For background on what sandboxes are and how isolation works, refer to [About Sandboxes](index.md).

:::{important}
Docker must be running before you create a gateway or sandbox. If it is not, the CLI
returns a connection-refused error (`os error 61`) without explaining
the cause. Start Docker and try again.
:::

## Create a Sandbox

Create a sandbox with a single command. For example, to create a sandbox with Claude, run:

```console
$ openshell sandbox create -- claude
```

Every sandbox requires a gateway. If you run `openshell sandbox create` without a gateway, the CLI auto-bootstraps a local gateway.

### Remote Gateways

If you plan to run sandboxes on a remote host or a cloud-hosted gateway, set up the gateway first. Refer to {doc}`manage-gateways` for deployment options and multi-gateway management.

### GPU Resources

To request GPU resources, add `--gpu`:

```console
$ openshell sandbox create --gpu -- claude
```

### Custom Containers

Use `--from` to create a sandbox from a pre-built community package, a local directory, or a container image:

```console
$ openshell sandbox create --from openclaw
$ openshell sandbox create --from ./my-sandbox-dir
$ openshell sandbox create --from my-registry.example.com/my-image:latest
```

The CLI resolves community names against the [OpenShell Community](https://github.com/NVIDIA/OpenShell-Community) catalog, pulls the bundled Dockerfile and policy, builds the image locally, and creates the sandbox. For the full catalog and how to contribute your own, refer to {doc}`community-sandboxes`.

## Connect to a Sandbox

Open an SSH session into a running sandbox:

```console
$ openshell sandbox connect my-sandbox
```

Launch VS Code or Cursor directly into the sandbox workspace:

```console
$ openshell sandbox create --editor vscode --name my-sandbox
$ openshell sandbox connect my-sandbox --editor cursor
```

When `--editor` is used, OpenShell keeps the sandbox alive and installs an
OpenShell-managed SSH include file instead of cluttering your main
`~/.ssh/config` with generated host blocks.

## Monitor and Debug

List all sandboxes:

```console
$ openshell sandbox list
```

Get detailed information about a specific sandbox:

```console
$ openshell sandbox get my-sandbox
```

Stream sandbox logs to monitor agent activity and diagnose policy decisions:

```console
$ openshell logs my-sandbox
```

| Flag | Purpose | Example |
|---|---|---|
| `--tail` | Stream logs in real time | `openshell logs my-sandbox --tail` |
| `--source` | Filter by log source | `--source sandbox` |
| `--level` | Filter by severity | `--level warn` |
| `--since` | Show logs from a time window | `--since 5m` |

OpenShell Terminal combines sandbox status and live logs in a single real-time dashboard:

```console
$ openshell term
```

Use the terminal to spot blocked connections marked `action=deny` and inference interceptions marked `action=inspect_for_inference`. If a connection is blocked unexpectedly, add the host to your network policy. Refer to {doc}`policies` for the workflow.

## Port Forwarding

Forward a local port to a running sandbox to access services inside it, such as a web server or database:

```console
$ openshell forward start 8000 my-sandbox
$ openshell forward start 8000 my-sandbox -d    # run in background
```

List and stop active forwards:

```console
$ openshell forward list
$ openshell forward stop 8000 my-sandbox
```

:::{tip}
You can also forward a port at creation time with `--forward`:

```console
$ openshell sandbox create --forward 8000 -- claude
```
:::

## SSH Config

Generate an SSH config entry for a sandbox so tools like VS Code Remote-SSH can connect directly:

```console
$ openshell sandbox ssh-config my-sandbox
```

Append the output to `~/.ssh/config` or use `--editor` on `sandbox create`/`sandbox connect` for automatic setup.

## Transfer Files

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

Deleting a sandbox stops all processes, releases resources, and purges injected credentials.

```console
$ openshell sandbox delete my-sandbox
```

## Next Steps

- To follow a complete end-to-end example, refer to the {doc}`/tutorials/github-sandbox` tutorial.
- To supply API keys or tokens, refer to {doc}`manage-providers`.
- To control what the agent can access, refer to {doc}`policies`.
- To use a pre-built environment, refer to the {doc}`community-sandboxes` catalog.
