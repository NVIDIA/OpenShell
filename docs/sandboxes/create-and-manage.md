<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Create and Manage Sandboxes

## Creating a Sandbox

The simplest form creates a sandbox with defaults and drops you into an interactive shell:

```console
$ nemoclaw sandbox create
```

### With an Agent Tool

When the trailing command is a recognized tool, the CLI auto-creates the required provider from local credentials:

```console
$ nemoclaw sandbox create -- claude
$ nemoclaw sandbox create -- codex
```

### With Options

```console
$ nemoclaw sandbox create \
  --name my-sandbox \
  --provider my-github \
  --provider my-claude \
  --policy ./my-policy.yaml \
  --sync \
  -- claude
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Sandbox name (auto-generated if omitted). |
| `--provider <NAME>` | Provider to attach (repeatable). |
| `--policy <PATH>` | Custom policy YAML. Uses the built-in default if omitted. |
| `--sync` | Push local git-tracked files to `/sandbox` in the container. |
| `--keep` | Keep sandbox alive after the command exits. |
| `--forward <PORT>` | Forward a local port to the sandbox (implies `--keep`). |
| `--image <IMAGE>` | Custom container image (see [Custom Containers](custom-containers.md)). |

### Auto-Bootstrap

If no cluster is running, `sandbox create` offers to bootstrap one automatically. This is equivalent to running `nemoclaw cluster admin deploy` first.

## Listing Sandboxes

```console
$ nemoclaw sandbox list
```

| Flag | Description |
|------|-------------|
| `--limit <N>` | Maximum number of sandboxes to return (default: 100). |
| `--offset <N>` | Pagination offset. |
| `--names` | Print only sandbox names. |

## Inspecting a Sandbox

```console
$ nemoclaw sandbox get my-sandbox
```

Shows sandbox details including ID, name, namespace, phase, and policy.

## Connecting to a Sandbox

```console
$ nemoclaw sandbox connect my-sandbox
```

Opens an interactive SSH session. All provider credentials are available as environment variables inside the sandbox.

### VS Code Remote-SSH

```console
$ nemoclaw sandbox ssh-config my-sandbox >> ~/.ssh/config
```

Then use VS Code's Remote-SSH extension to connect to the host `my-sandbox`.

## Viewing Logs

```console
$ nemoclaw sandbox logs my-sandbox
```

| Flag | Description |
|------|-------------|
| `-n <N>` | Number of log lines (default: 200). |
| `--tail` | Stream live logs. |
| `--since <DURATION>` | Show logs from this duration ago (e.g., `5m`, `1h`). |
| `--source <SOURCE>` | Filter by source: `gateway`, `sandbox`, or `all` (repeatable). |
| `--level <LEVEL>` | Minimum level: `error`, `warn`, `info`, `debug`, `trace`. |

### Monitoring for Denied Actions

When iterating on a sandbox policy, watch for denied network requests:

```console
$ nemoclaw sandbox logs my-sandbox --tail --source sandbox
```

Denied actions include the destination host/port, the binary that attempted the connection, and the reason for denial.

## Deleting Sandboxes

```console
$ nemoclaw sandbox delete my-sandbox
$ nemoclaw sandbox delete sandbox-1 sandbox-2 sandbox-3
```

Deleting a sandbox also stops any active port forwards.
