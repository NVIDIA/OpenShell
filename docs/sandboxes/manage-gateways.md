---
title:
  page: Deploy and Manage Gateways
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

# Deploy and Manage Gateways

The gateway is the control plane for OpenShell. All control-plane traffic between the CLI and running sandboxes flows through the gateway.

The gateway is responsible for:

- Provisioning and managing sandboxes, including creation, deletion, and status monitoring.
- Storing provider credentials (API keys, tokens) and delivering them to sandboxes at startup.
- Delivering network and filesystem policies to sandboxes. Policy enforcement itself happens inside each sandbox through the proxy, OPA, Landlock, and seccomp.
- Managing inference configuration and serving inference bundles so sandboxes can route requests to the correct backend.
- Providing the SSH tunnel endpoint so you can connect to sandboxes without exposing them directly.

The gateway runs inside a Docker container and exposes a single port (gRPC and HTTP multiplexed), secured by mTLS by default. No separate Kubernetes installation is required. It can be deployed locally, on a remote host via SSH, or behind a cloud reverse proxy.

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
You do not need to deploy a gateway manually. If you run `openshell sandbox create` without a gateway, the CLI auto-bootstraps a local gateway for you.
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

### Cloud Gateway

Register a gateway behind a reverse proxy such as Cloudflare Access:

```console
$ openshell gateway add https://gateway.example.com
```

This opens your browser for the proxy's login flow. After authentication, the CLI stores a bearer token and sets the gateway as active.

To give the gateway a specific name instead of deriving it from the hostname, use `--name`:

```console
$ openshell gateway add https://gateway.example.com --name production
```

If the token expires later, re-authenticate with:

```console
$ openshell gateway login
```

### Remote Gateway

Register a gateway on a remote host you have SSH access to:

```console
$ openshell gateway add https://remote-host:8080 --remote user@remote-host
```

Or use the `ssh://` scheme to combine the SSH destination and gateway port:

```console
$ openshell gateway add ssh://user@remote-host:8080
```

### Local Gateway

Register a gateway running locally that was started outside the CLI:

```console
$ openshell gateway add https://127.0.0.1:8080 --local
```

## Manage Multiple Gateways

One gateway is always the active gateway. All CLI commands target it by default. Both `gateway start` and `gateway add` automatically set the new gateway as active.

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

Show deployment details for a gateway, including endpoint, auth mode, and port:

```console
$ openshell gateway info
$ openshell gateway info --name my-remote-cluster
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
$ openshell doctor logs --tail              # stream live
$ openshell doctor logs --lines 50          # last 50 lines
```

Run a command inside the gateway container for deeper inspection:

```console
$ openshell doctor exec -- kubectl get pods -A
$ openshell doctor exec -- sh
```

If the gateway is in a bad state, recreate it:

```console
$ openshell gateway start --recreate
```

## Next Steps

- To create a sandbox using the gateway, refer to {doc}`manage-sandboxes`.
- To install the CLI and get started quickly, refer to the {doc}`/get-started/quickstart`.
