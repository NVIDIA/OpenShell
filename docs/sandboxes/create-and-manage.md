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

The gateway is the control plane for OpenShell. Every sandbox is created using a gateway. If you run `openshell sandbox create` without one, the CLI auto-bootstraps a local gateway. To run sandboxes on a remote machine or a cloud-hosted gateway, set up the gateway first. For details on how authentication and credentials work, refer to {doc}`../reference/gateway-auth`.

### Deploy a local gateway

```console
$ openshell gateway start
```

The gateway becomes reachable at `https://127.0.0.1:8080`. To use a different port: `openshell gateway start --port 9090`.

### Deploy a remote gateway

Deploy to a remote machine over SSH. The only dependency on the remote host is Docker.

```console
$ openshell gateway start --remote user@hostname
```

:::{note}
For DGX Spark, use your Spark's mDNS hostname:

```console
$ openshell gateway start --remote <username>@<spark-ssid>.local
```
:::

### Register an existing gateway

Use `openshell gateway add` to register a gateway that is already running.

```console
$ openshell gateway add https://gateway.example.com                        # cloud (browser login)
$ openshell gateway add https://remote-host:8080 --remote user@remote-host # remote
$ openshell gateway add ssh://user@remote-host:8080                        # remote (ssh:// shorthand)
$ openshell gateway add https://127.0.0.1:8080 --local                     # local
```

If a cloud gateway token expires, re-authenticate with `openshell gateway login`.

### Manage multiple gateways

One gateway is always the **active gateway**. All CLI commands target it by default.

```console
$ openshell gateway select                     # list all gateways
$ openshell gateway select my-remote-cluster   # switch the active gateway
$ openshell status -g my-other-cluster         # override for a single command
```

### Stop and destroy gateways

```console
$ openshell gateway stop                       # preserve state for later restart
$ openshell gateway destroy                    # permanently remove all state
$ openshell gateway start --recreate           # destroy and re-deploy from scratch
```

For cloud gateways, `gateway destroy` removes only the local registration. It does not affect the remote deployment.

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

:::{tip}
Sandboxes stay running by default after the initial command or shell exits. Use `--no-keep` when you want the sandbox deleted automatically instead.
:::

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

Use the terminal to spot blocked connections (`action=deny` entries) and inference interceptions (`action=inspect_for_inference` entries). If a connection is blocked unexpectedly, add the host to your network policy. Refer to {doc}`policies` for the workflow.

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
