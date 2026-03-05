<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Create and Manage Sandboxes

This page walks you through the full sandbox lifecycle: creating, inspecting, connecting to, monitoring, and deleting sandboxes.

## Sandbox Lifecycle

Every sandbox moves through a defined set of phases:

| Phase | Description |
|---|---|
| **Provisioning** | The runtime is setting up the sandbox environment, injecting credentials, and applying your policy. |
| **Ready** | The sandbox is running. The agent process is active and all isolation layers are enforced. You can connect, sync files, and view logs. |
| **Error** | Something went wrong during provisioning or execution. Check logs with `nemoclaw sandbox logs` for details. |
| **Deleting** | The sandbox is being torn down. Resources are released and credentials are purged. |

## The NemoClaw Runtime

Sandboxes run inside a lightweight runtime cluster that NemoClaw manages for
you. The cluster runs as a [k3s](https://k3s.io/) Kubernetes distribution
inside a Docker container on your machine.

**You do not need to set this up manually.** The first time you run a command
that needs a cluster (such as `nemoclaw sandbox create`), the CLI provisions
one automatically. This is the "Runtime ready" line you see in the output.
Subsequent commands reuse the existing cluster.

For teams or when you need more resources, you can deploy the cluster to a
remote host instead of your local machine:

```console
$ nemoclaw cluster admin deploy --remote user@host
```

See [Remote Deployment](../reference/architecture.md) for
details. If you have multiple clusters (local and remote), switch between them
with `nemoclaw cluster use <name>`. See the
[CLI Reference](../reference/cli.md#cluster-commands) for the full command set.

## Prerequisites

- NemoClaw CLI installed (`pip install nemoclaw`)
- Docker running on your machine

## Create a Sandbox

The simplest way to create a sandbox is to specify a trailing command:

```console
$ nemoclaw sandbox create -- claude
```

The CLI bootstraps the runtime (if this is your first run), discovers your
credentials, applies the default policy, and drops you into the sandbox.

You can customize creation with flags like `--name`, `--provider`, `--policy`,
`--sync`, `--keep`, `--forward`, and `--from`. See the
[CLI Reference](../reference/cli.md) for the full flag list.

A fully specified creation command might look like:

```console
$ nemoclaw sandbox create \
    --name dev \
    --provider my-claude \
    --policy policy.yaml \
    --sync \
    --keep \
    -- claude
```

:::{tip}
Use `--keep` to keep the sandbox running after the trailing command exits.
This is especially useful when you are iterating on a policy or want to
reconnect later from another terminal or VS Code.
:::

## List and Inspect Sandboxes

List all sandboxes:

```console
$ nemoclaw sandbox list
```

Get detailed information about a specific sandbox:

```console
$ nemoclaw sandbox get my-sandbox
```

## Connect to a Sandbox

### Interactive SSH

Open an SSH session into a running sandbox:

```console
$ nemoclaw sandbox connect my-sandbox
```

### VS Code Remote-SSH

Export the sandbox SSH configuration and append it to your SSH config:

```console
$ nemoclaw sandbox ssh-config my-sandbox >> ~/.ssh/config
```

Then open VS Code, install the **Remote - SSH** extension if you have not
already, and connect to the host named `my-sandbox`.

## View Logs

Stream sandbox logs:

```console
$ nemoclaw sandbox logs my-sandbox
```

Use flags to filter and follow output:

| Flag | Purpose | Example |
|---|---|---|
| `--tail` | Stream logs in real time | `nemoclaw sandbox logs my-sandbox --tail` |
| `--source` | Filter by log source | `--source sandbox` |
| `--level` | Filter by severity | `--level warn` |
| `--since` | Show logs from a time window | `--since 5m` |

Combine flags to narrow in on what you need:

```console
$ nemoclaw sandbox logs my-sandbox --tail --source sandbox --level warn --since 5m
```

:::{tip}
For a real-time dashboard that combines sandbox status and logs in one view,
run `nemoclaw gator`. See {doc}`terminal` for details on reading log entries and
diagnosing blocked connections.
:::

## Sync Files

Push files from your host into the sandbox:

```console
$ nemoclaw sandbox sync my-sandbox --up ./src /sandbox/src
```

Pull files from the sandbox to your host:

```console
$ nemoclaw sandbox sync my-sandbox --down /sandbox/output ./local
```

:::{note}
You can also sync files at creation time with the `--sync` flag on
`nemoclaw sandbox create`.
:::

## Port Forwarding

Forward a port from the sandbox to your host machine. This runs in the
foreground by default:

```console
$ nemoclaw sandbox forward start 8080 my-sandbox
```

Add `-d` to run the forward in the background:

```console
$ nemoclaw sandbox forward start 8080 my-sandbox -d
```

List active port forwards:

```console
$ nemoclaw sandbox forward list
```

Stop a port forward:

```console
$ nemoclaw sandbox forward stop 8080 my-sandbox
```

:::{note}
You can set up port forwarding at creation time with the `--forward` flag on
`nemoclaw sandbox create`, which is convenient when you know upfront that
your workload exposes a service.
:::

## Delete Sandboxes

Delete a sandbox by name:

```console
$ nemoclaw sandbox delete my-sandbox
```

You can delete multiple sandboxes in a single command:

```console
$ nemoclaw sandbox delete sandbox-a sandbox-b sandbox-c
```

## Next Steps

- {doc}`community-sandboxes` --- use pre-built sandboxes from the community catalog
- {doc}`providers` --- create and attach credential providers
- {doc}`custom-containers` --- build and run your own container image
- {doc}`../safety-and-privacy/policies` --- control what the agent can access