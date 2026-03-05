<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# CLI Reference

The `nemoclaw` CLI (also available as `ncl`) is the primary interface for managing sandboxes, providers, inference routes, and clusters.

:::{tip}
The CLI has comprehensive built-in help. Use `nemoclaw <command> --help` at any level to discover commands and flags.
:::

## Global Options

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Increase verbosity (`-v` = info, `-vv` = debug, `-vvv` = trace). |
| `-c`, `--cluster <NAME>` | Cluster to operate on (also via `NEMOCLAW_CLUSTER` env var). |

## Command Tree

```
nemoclaw (ncl)
├── cluster
│   ├── status                          # Check gateway connectivity
│   ├── use <name>                      # Set active cluster
│   ├── list                            # List all clusters
│   └── admin
│       ├── deploy [opts]               # Provision or restart cluster
│       ├── stop [opts]                 # Stop cluster (preserve state)
│       ├── destroy [opts]              # Destroy cluster permanently
│       ├── info [--name]               # Show deployment details
│       └── tunnel [opts]               # SSH tunnel for kubectl access
├── sandbox
│   ├── create [opts] [-- CMD...]       # Create sandbox and connect
│   ├── get <name>                      # Show sandbox details
│   ├── list [opts]                     # List sandboxes
│   ├── delete <name>...                # Delete sandboxes
│   ├── connect <name>                  # SSH into sandbox
│   ├── sync <name> {--up|--down}       # Sync files
│   ├── logs <name> [opts]              # View/stream logs
│   ├── ssh-config <name>               # Print SSH config block
│   ├── forward
│   │   ├── start <port> <name> [-d]    # Start port forward
│   │   ├── stop <port> <name>          # Stop port forward
│   │   └── list                        # List active forwards
│   ├── image
│   │   └── push [opts]                 # Build and push custom image
│   └── policy
│       ├── set <name> --policy <path>  # Update live policy
│       ├── get <name> [--full]         # Show current policy
│       └── list <name>                 # Policy revision history
├── provider
│   ├── create --name --type [opts]     # Create provider
│   ├── get <name>                      # Show provider details
│   ├── list [opts]                     # List providers
│   ├── update <name> --type [opts]     # Update provider
│   └── delete <name>...                # Delete providers
├── inference
│   ├── create [opts]                   # Create inference route
│   ├── update <name> [opts]            # Update inference route
│   ├── delete <name>...                # Delete inference routes
│   └── list [opts]                     # List inference routes
├── gator                               # Launch TUI
└── completions <shell>                 # Generate shell completions
```

## Cluster Commands

### `nemoclaw cluster admin deploy`

Provision or start a cluster (local or remote).

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | `nemoclaw` | Cluster name. |
| `--remote <USER@HOST>` | — | SSH destination for remote deployment. |
| `--ssh-key <PATH>` | — | SSH private key for remote deployment. |
| `--port <PORT>` | 8080 | Host port mapped to gateway. |
| `--kube-port [PORT]` | — | Expose K8s control plane on host port. |

### `nemoclaw cluster admin stop`

Stop a cluster container (preserves state for later restart).

### `nemoclaw cluster admin destroy`

Destroy a cluster and all its state permanently.

### `nemoclaw cluster admin info`

Show deployment details: endpoint, kubeconfig path, kube port, remote host.

### `nemoclaw cluster admin tunnel`

Start or print an SSH tunnel for kubectl access to a remote cluster.

## Sandbox Commands

### `nemoclaw sandbox create [OPTIONS] [-- COMMAND...]`

Create a sandbox, wait for readiness, then connect or execute the trailing command.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Sandbox name (auto-generated if omitted). |
| `--image <IMAGE>` | Custom container image (BYOC). |
| `--sync` | Sync local git-tracked files to `/sandbox`. |
| `--keep` | Keep sandbox alive after command exits. |
| `--provider <NAME>` | Provider to attach (repeatable). |
| `--policy <PATH>` | Path to custom policy YAML. |
| `--forward <PORT>` | Forward local port to sandbox (implies `--keep`). |
| `--remote <USER@HOST>` | SSH destination for auto-bootstrap. |

### `nemoclaw sandbox logs <name>`

| Flag | Default | Description |
|------|---------|-------------|
| `-n <N>` | 200 | Number of log lines. |
| `--tail` | — | Stream live logs. |
| `--since <DURATION>` | — | Logs from this duration ago (e.g., `5m`, `1h`). |
| `--source <SOURCE>` | `all` | Filter: `gateway`, `sandbox`, or `all`. |
| `--level <LEVEL>` | — | Minimum level: `error`, `warn`, `info`, `debug`, `trace`. |

### `nemoclaw sandbox sync <name> {--up|--down} <path> [dest]`

Sync files to/from a sandbox.

### `nemoclaw sandbox forward start <port> <name>`

Start forwarding a local port to a sandbox. `-d` runs in background.

## Policy Commands

### `nemoclaw sandbox policy set <name> --policy <path>`

Update the policy on a live sandbox. Only dynamic fields can change at runtime.

| Flag | Description |
|------|-------------|
| `--wait` | Wait for sandbox to confirm policy is loaded. |
| `--timeout <SECS>` | Timeout for `--wait` (default: 60). |

### `nemoclaw sandbox policy get <name>`

| Flag | Description |
|------|-------------|
| `--rev <VERSION>` | Show a specific revision (default: latest). |
| `--full` | Print full policy as YAML (round-trips with `--policy`). |

### `nemoclaw sandbox policy list <name>`

Show policy revision history.

## Provider Commands

### `nemoclaw provider create --name <NAME> --type <TYPE>`

| Flag | Description |
|------|-------------|
| `--from-existing` | Discover credentials from local machine. |
| `--credential KEY[=VALUE]` | Credential pair (repeatable). Bare `KEY` reads from env var. |
| `--config KEY=VALUE` | Config key/value pair (repeatable). |

Supported types: `claude`, `opencode`, `codex`, `generic`, `nvidia`, `gitlab`, `github`, `outlook`.

## Inference Commands

### `nemoclaw inference create`

| Flag | Description |
|------|-------------|
| `--routing-hint <HINT>` (required) | Routing hint for policy matching. |
| `--base-url <URL>` (required) | Backend endpoint URL. |
| `--model-id <ID>` (required) | Model identifier. |
| `--api-key <KEY>` | API key for the endpoint. |
| `--protocol <PROTO>` | Protocol (auto-detected if omitted, repeatable). |
| `--disabled` | Create in disabled state. |
