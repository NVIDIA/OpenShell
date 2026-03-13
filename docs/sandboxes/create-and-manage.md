---
title:
  page: Create and Manage
  nav: Create and Manage
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

# Create and Manage

This page covers setting up gateways, creating sandboxes, and managing both. For background on what sandboxes are and how isolation works, refer to [About Sandboxes](index.md).

:::{warning}
Docker must be running before you create a gateway or sandbox. If it is not, the CLI
returns a connection-refused error (`os error 61`) without explaining
the cause. Start Docker and try again.
:::

## Set Up a Gateway

Every sandbox requires a gateway. If you run `openshell sandbox create` without one, the CLI auto-bootstraps a local gateway. To deploy gateways manually, use remote hosts, or manage multiple gateways, refer to {doc}`gateways`.

## Create a Sandbox

Run a single command to create a sandbox and launch your agent:

```console
$ openshell sandbox create -- claude
```

If no gateway is running, the CLI auto-bootstraps a local gateway before creating the sandbox.

To request GPU resources, add `--gpu`:

```console
$ openshell sandbox create --gpu -- claude
```

Use `--from` to create a sandbox from a pre-built community package, a local directory, or a container image:

```console
$ openshell sandbox create --from openclaw
$ openshell sandbox create --from ./my-sandbox-dir
$ openshell sandbox create --from my-registry.example.com/my-image:latest
```

The CLI resolves community names against the [OpenShell Community](https://github.com/NVIDIA/OpenShell-Community) catalog, pulls the bundled Dockerfile and policy, builds the image locally, and creates the sandbox. For the full catalog and how to contribute your own, refer to {doc}`community-sandboxes`.

A fully specified creation command might look like:

```console
$ openshell sandbox create \
    --name dev \
    --provider my-claude \
    --policy policy.yaml \
    --upload \
    -- claude
```

Additional `sandbox create` flags:

| Flag | Purpose |
|---|---|
| `--no-keep` | Delete the sandbox automatically after the initial command exits |
| `--forward <port>` | Forward a local port to the sandbox before running |
| `--tty` / `--no-tty` | Force or disable pseudo-terminal allocation |
| `--no-bootstrap` | Error if no gateway is available instead of auto-bootstrapping |
| `--no-auto-providers` | Error if required providers are missing instead of prompting |

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
$ openshell sandbox delete --all
```

## Next Steps

- To follow a complete end-to-end example, refer to the {doc}`/tutorials/github-sandbox` tutorial.
- To supply API keys or tokens, refer to {doc}`providers`.
- To control what the agent can access, refer to {doc}`policies`.
- To use a pre-built environment, refer to the {doc}`community-sandboxes` catalog.
