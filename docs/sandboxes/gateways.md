---
title:
  page: Gateways
  nav: Gateways
description: Deploy local and remote gateways, register cloud gateways, and manage multiple gateway environments.
topics:
- Generative AI
- Cybersecurity
tags:
- Gateway
- Deployment
- Remote Gateway
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

# Gateways

The gateway is the control plane for OpenShell. It coordinates sandbox lifecycle, manages providers, enforces policies, and brokers all requests between the CLI and running sandboxes.

OpenShell supports three gateway types:

| Type | Where it runs | How to create |
|---|---|---|
| **Local** | Docker on your workstation | `openshell gateway start` |
| **Remote** | Docker on a remote host via SSH | `openshell gateway start --remote user@host` |
| **Cloud** | Behind a reverse proxy (e.g. Cloudflare Access) | `openshell gateway add https://gateway.example.com` |

## Deploy a Local Gateway

Deploy a gateway on your workstation. The only prerequisite is a running Docker daemon.

```console
$ openshell gateway start
```

The gateway becomes reachable at `https://127.0.0.1:8080`. Verify it is healthy:

```console
$ openshell status
```

:::{tip}
You don't need to deploy a gateway manually. If you run `openshell sandbox create` without a gateway, the CLI auto-bootstraps a local gateway for you.
:::

To use a different port or name:

```console
$ openshell gateway start --port 9090
$ openshell gateway start --name dev-local
```

## Deploy a Remote Gateway

Deploy a gateway on a remote machine accessible via SSH. The only dependency on the remote host is Docker.

```console
$ openshell gateway start --remote user@hostname
```

The gateway is reachable at `https://<hostname>:8080`.

To specify an SSH key:

```console
$ openshell gateway start --remote user@hostname --ssh-key ~/.ssh/my_key
```

:::{note}
For DGX Spark, use your Spark's mDNS hostname:

```console
$ openshell gateway start --remote <username>@<spark-ssid>.local
```
:::

## Register an Existing Gateway

Use `openshell gateway add` to register a gateway that is already running.

### Cloud gateway

Register a gateway behind a reverse proxy (e.g. Cloudflare Access):

```console
$ openshell gateway add https://gateway.example.com
```

This opens your browser for the proxy's login flow. After authentication, the CLI stores a bearer token and sets the gateway as active.

To give the gateway a specific name (otherwise derived from the hostname):

```console
$ openshell gateway add https://gateway.example.com --name production
```

If the token expires later, re-authenticate with:

```console
$ openshell gateway login
```

### Remote gateway

Register a gateway on a remote host you have SSH access to:

```console
$ openshell gateway add https://remote-host:8080 --remote user@remote-host
```

Or use the `ssh://` scheme to combine the SSH destination and gateway port:

```console
$ openshell gateway add ssh://user@remote-host:8080
```

### Local gateway

Register a gateway running locally that was started outside the CLI:

```console
$ openshell gateway add https://127.0.0.1:8080 --local
```

## Manage Multiple Gateways

One gateway is always the **active gateway**. All CLI commands target it by default.

List all registered gateways:

```console
$ openshell gateway select
```

Switch the active gateway:

```console
$ openshell gateway select my-remote-cluster
```

Override the active gateway for a single command with `-g`:

```console
$ openshell status -g my-other-cluster
```

## Stop and Destroy

Stop a gateway while preserving its state for later restart:

```console
$ openshell gateway stop
```

Permanently destroy a gateway and all its state:

```console
$ openshell gateway destroy
```

For cloud gateways, `gateway destroy` removes only the local registration. It does not affect the remote deployment.

Target a specific gateway with `--name`:

```console
$ openshell gateway stop --name my-gateway
$ openshell gateway destroy --name my-gateway
```

## Troubleshoot

Check gateway health:

```console
$ openshell status
```

View gateway logs:

```console
$ openshell doctor logs
```

If the gateway is in a bad state, recreate it:

```console
$ openshell gateway start --recreate
```

## Next Steps

- To create a sandbox using the gateway, refer to {doc}`create-and-manage`.
- To install the CLI and get started quickly, refer to the {doc}`/get-started/quickstart`.
