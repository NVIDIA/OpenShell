<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# CLI Reference

Complete command reference for the `nemoclaw` CLI. Every subcommand, flag, and option is documented here.

## Command Tree

```text
nemoclaw
├── status
├── logs [name]
├── term
├── forward
│   ├── start <port> <name>
│   ├── stop <port> <name>
│   └── list
├── gateway
│   ├── start
│   ├── stop
│   ├── destroy
│   ├── info
│   ├── tunnel
│   └── select [name]
├── sandbox
│   ├── create
│   ├── get [name]
│   ├── list
│   ├── delete <name...>
│   ├── connect [name]
│   ├── upload [name]
│   ├── download [name]
│   └── ssh-config <name>
├── policy
│   ├── set <name>
│   ├── get <name>
│   └── list <name>
├── provider
│   ├── create
│   ├── get <name>
│   ├── list
│   ├── update <name>
│   └── delete <name>
├── inference
│   ├── set
│   ├── update
│   └── get
└── completions <shell>
```

:::{tip}
Commands that accept an optional `[name]` argument — such as `get`, `connect`, `upload`, `download`, and `logs` — fall back to the last-used sandbox when the name is omitted. The CLI records the sandbox name each time you create or connect, and prints a hint showing which sandbox was selected.
:::

## Status, Logs, and Terminal

| Command | Description |
|---|---|
| `nemoclaw status` | Show the health and status of the active gateway. |
| `nemoclaw logs [name]` | View sandbox logs. Use `--tail` for streaming, `--source` and `--level` to filter. |
| `nemoclaw term` | Launch the OpenShell Terminal — a dashboard showing sandbox status, live logs, and policy decisions in a single view. Navigate with `j`/`k`, press `f` to follow live output, `s` to filter by source, and `q` to quit. |

Refer to {doc}`/sandboxes/create-and-manage` for more on monitoring sandboxes and reading log entries.

## Gateway Commands

Manage the OpenShell runtime cluster.

| Command | Description |
|---|---|
| `nemoclaw gateway start` | Deploy a new cluster. Add `--remote user@host` for remote deployment. |
| `nemoclaw gateway stop` | Stop the active cluster, preserving state. |
| `nemoclaw gateway destroy` | Permanently remove the cluster and all its data. |
| `nemoclaw gateway info` | Show detailed information about the cluster. |
| `nemoclaw gateway tunnel` | Set up a kubectl tunnel to a remote cluster. |
| `nemoclaw gateway select <name>` | Set the active cluster. All subsequent commands target this cluster. |
| `nemoclaw gateway select` | List all registered clusters (when called without a name). |

## Sandbox Commands

Create and manage isolated agent execution environments.

| Command | Description |
|---|---|
| `nemoclaw sandbox create` | Create a new sandbox. See flag reference below. |
| `nemoclaw sandbox get [name]` | Show detailed information about a sandbox. |
| `nemoclaw sandbox list` | List all sandboxes in the active cluster. |
| `nemoclaw sandbox delete <name...>` | Delete one or more sandboxes by name. |
| `nemoclaw sandbox connect [name]` | Open an interactive SSH session into a running sandbox. |
| `nemoclaw sandbox upload [name]` | Upload files from the host into a sandbox. |
| `nemoclaw sandbox download [name]` | Download files from a sandbox to the host. |
| `nemoclaw sandbox ssh-config <name>` | Print SSH config for a sandbox. Append to `~/.ssh/config` for VS Code Remote-SSH. |

### Sandbox Create Flags

| Flag | Description |
|---|---|
| `--name` | Assign a human-readable name to the sandbox. Auto-generated if omitted. |
| `--provider` | Attach a credential provider. Repeatable for multiple providers. |
| `--policy` | Path to a policy YAML file to apply at creation time. |
| `--upload` | Upload local files into the sandbox before running. |
| `--keep` | Keep the sandbox alive after the trailing command exits. |
| `--forward` | Forward a local port into the sandbox at startup. |
| `--from` | Build from a community sandbox name, local Dockerfile directory, or container image reference. |
| `-- <command>` | The command to run inside the sandbox. Everything after `--` is passed as the agent command. |

## Policy Commands

Apply and inspect sandbox policies at runtime.

| Command | Description |
|---|---|
| `nemoclaw policy set <name>` | Apply or update a policy on a running sandbox. Pass `--policy <file>`. |
| `nemoclaw policy get <name>` | Show the active policy for a sandbox. Add `--full` for the complete policy with metadata. |
| `nemoclaw policy list <name>` | List all policy versions applied to a sandbox, with status. |

## Port Forwarding Commands

Forward sandbox ports to the host for local access.

| Command | Description |
|---|---|
| `nemoclaw forward start <port> <name>` | Forward a sandbox port to the host. Add `-d` for background mode. |
| `nemoclaw forward stop <port> <name>` | Stop an active port forward. |
| `nemoclaw forward list` | List all active port forwards. |

## Provider Commands

Manage credential providers that inject secrets into sandboxes.

| Command | Description |
|---|---|
| `nemoclaw provider create` | Create a new credential provider. See flag reference below. |
| `nemoclaw provider get <name>` | Show details of a provider. |
| `nemoclaw provider list` | List all providers in the active cluster. |
| `nemoclaw provider update <name>` | Update a provider's credentials or configuration. |
| `nemoclaw provider delete <name>` | Delete a provider. |

### Provider Create Flags

| Flag | Description |
|---|---|
| `--name` | Name for the provider. |
| `--type` | Provider type: `claude`, `codex`, `opencode`, `github`, `gitlab`, `nvidia`, `generic`, `outlook`. |
| `--from-existing` | Discover credentials from your current shell environment variables. |
| `--credential` | Set a credential explicitly. Format: `KEY=VALUE` or bare `KEY` to read from env. Repeatable. |
| `--config` | Set a configuration value. Format: `KEY=VALUE`. Repeatable. |

## Inference Commands

Configure the backend used by `https://inference.local`.

### `nemoclaw inference set`

Set the provider and model for managed inference. Both flags are required.

| Flag | Description |
|---|---|
| `--provider` | Provider record name to use for injected credentials. |
| `--model` | Model identifier to force on generation requests. |

### `nemoclaw inference update`

Update only the fields you specify.

| Flag | Description |
|---|---|
| `--provider` | Replace the current provider record. |
| `--model` | Replace the current model ID. |

### `nemoclaw inference get`

Show the current inference configuration, including provider, model, and version.

## Environment Variables

| Variable | Description |
|---|---|
| `NEMOCLAW_CLUSTER` | Name of the cluster to operate on. Overrides the active cluster set by `nemoclaw gateway select`. |
| `NEMOCLAW_SANDBOX_POLICY` | Default path to a policy YAML file. When set, `nemoclaw sandbox create` uses this policy if no `--policy` flag is provided. |

## Shell Completions

Generate shell completion scripts for tab completion:

```console
$ nemoclaw completions bash
$ nemoclaw completions zsh
$ nemoclaw completions fish
```

Pipe the output to your shell's config file:

```console
$ nemoclaw completions zsh >> ~/.zshrc
$ source ~/.zshrc
```

## Built-in Help

Every command and subcommand includes built-in help. Use `--help` at any level to see available subcommands, flags, and usage examples:

```console
$ nemoclaw --help
$ nemoclaw sandbox --help
$ nemoclaw sandbox create --help
$ nemoclaw gateway --help
```
