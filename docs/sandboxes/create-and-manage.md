<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Create and Manage Sandboxes

This page walks you through the full sandbox lifecycle: creating, inspecting, connecting to, monitoring, and deleting sandboxes. For background on what sandboxes are and how the runtime works, refer to [About Sandboxes](index.md).

## Prerequisites

Ensure the following are installed before creating sandboxes.

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

Check the status of your sandboxes and retrieve detailed information about individual ones.

List all sandboxes:

```console
$ nemoclaw sandbox list
```

Get detailed information about a specific sandbox:

```console
$ nemoclaw sandbox get my-sandbox
```

## Connect to a Sandbox

Access a running sandbox through an interactive SSH session or VS Code Remote-SSH.

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

Then open VS Code, install the Remote - SSH extension if you have not
already, and connect to the host named `my-sandbox`.

## View Logs

Stream and filter sandbox logs to monitor agent activity and diagnose policy decisions.

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
run `nemoclaw term`. Refer to {doc}`terminal` for details on reading log entries and
diagnosing blocked connections.
:::

## Sync Files

Transfer files between your host machine and a running sandbox.

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

Remove sandboxes when they are no longer needed. Deleting a sandbox stops all processes, releases cluster resources, and purges injected credentials.

Delete a sandbox by name:

```console
$ nemoclaw sandbox delete my-sandbox
```

You can delete multiple sandboxes in a single command:

```console
$ nemoclaw sandbox delete sandbox-a sandbox-b sandbox-c
```

## Next Steps

- {doc}`community-sandboxes`: Use pre-built sandboxes from the community catalog
- {doc}`providers`: Create and attach credential providers
- {doc}`custom-containers`: Build and run your own container image
- {doc}`../safety-and-privacy/policies`: Control what the agent can access