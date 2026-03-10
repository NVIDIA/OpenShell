<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# CLI Reference

Complete command reference for the `openshell` CLI. Every subcommand, flag, and option is documented here.

## Command Tree

```text
openshell
├── status
├── logs [name]
├── forward
│   ├── start <port> <name>
│   ├── stop <port> <name>
│   └── list
├── policy
│   ├── set <name>
│   ├── get <name>
│   └── list <name>
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
├── term
└── completions <shell>
```

## Top-Level Commands

Commands available directly under `openshell` for common operations.

| Command | Description |
|---|---|
| `openshell status` | Show the health and status of the active gateway. |
| `openshell logs [name]` | View sandbox logs. Use `--tail` for streaming, `--source` and `--level` to filter. When name is omitted, uses the last-used sandbox. |
| `openshell forward start <port> <name>` | Forward a sandbox port to the host. Add `-d` for background mode. |
| `openshell forward stop <port> <name>` | Stop an active port forward. |
| `openshell forward list` | List all active port forwards. |
| `openshell policy set <name>` | Apply or update a policy on a running sandbox. Pass `--policy <file>`. |
| `openshell policy get <name>` | Show the active policy for a sandbox. Add `--full` for the complete policy with metadata. |
| `openshell policy list <name>` | List all policy versions applied to a sandbox, with status. |

## Gateway Commands

Manage the OpenShell runtime cluster.

| Command | Description |
|---|---|
| `openshell gateway start` | Deploy a new cluster. Add `--remote user@host` for remote deployment. |
| `openshell gateway stop` | Stop the active cluster, preserving state. |
| `openshell gateway destroy` | Permanently remove the cluster and all its data. |
| `openshell gateway info` | Show detailed information about the cluster. |
| `openshell gateway tunnel` | Set up a kubectl tunnel to a remote cluster. |
| `openshell gateway select <name>` | Set the active cluster. All subsequent commands target this cluster. |
| `openshell gateway select` | List all registered clusters (when called without a name). |

## Sandbox Commands

Create and manage isolated agent execution environments.

| Command | Description |
|---|---|
| `openshell sandbox create` | Create a new sandbox. See flag reference below. |
| `openshell sandbox get [name]` | Show detailed information about a sandbox. When name is omitted, uses the last-used sandbox. |
| `openshell sandbox list` | List all sandboxes in the active cluster. |
| `openshell sandbox delete <name...>` | Delete one or more sandboxes by name. |
| `openshell sandbox connect [name]` | Open an interactive SSH session into a running sandbox. When name is omitted, reconnects to the last-used sandbox. |
| `openshell sandbox upload [name]` | Upload files from the host into a sandbox. When name is omitted, uses the last-used sandbox. |
| `openshell sandbox download [name]` | Download files from a sandbox to the host. When name is omitted, uses the last-used sandbox. |
| `openshell sandbox ssh-config <name>` | Print SSH config for a sandbox. Append to `~/.ssh/config` for VS Code Remote-SSH. |

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

## Provider Commands

Manage credential providers that inject secrets into sandboxes.

| Command | Description |
|---|---|
| `openshell provider create` | Create a new credential provider. See flag reference below. |
| `openshell provider get <name>` | Show details of a provider. |
| `openshell provider list` | List all providers in the active cluster. |
| `openshell provider update <name>` | Update a provider's credentials or configuration. |
| `openshell provider delete <name>` | Delete a provider. |

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

### `openshell inference set`

Set the provider and model for managed inference. Both flags are required.

| Flag | Description |
|---|---|
| `--provider` | Provider record name to use for injected credentials. |
| `--model` | Model identifier to force on generation requests. |

### `openshell inference update`

Update only the fields you specify.

| Flag | Description |
|---|---|
| `--provider` | Replace the current provider record. |
| `--model` | Replace the current model ID. |

### `openshell inference get`

Show the current inference configuration, including provider, model, and
version.

## OpenShell Terminal

`openshell term` launches the OpenShell Terminal, a dashboard that shows sandbox
status, live logs, and policy decisions in a single view. Navigate with `j`/`k`,
press `f` to follow live output, `s` to filter by source, and `q` to quit.

Refer to {doc}`/sandboxes/create-and-manage` for more on monitoring sandboxes and reading log entries.

## Sandbox Name Fallback

Commands that accept an optional `[name]` argument, such as `get`, `connect`, `upload`, `download`, and `logs`, fall back to the last-used sandbox when the name is omitted. The CLI records the sandbox name each time you create or connect to a sandbox. When falling back, the CLI prints a hint showing which sandbox was selected.

If no sandbox has been used yet and no name is provided, the command exits with an error prompting you to specify a name.

## Environment Variables

| Variable | Description |
|---|---|
| `OPENSHELL_CLUSTER` | Name of the cluster to operate on. Overrides the active cluster set by `openshell gateway select`. |
| `OPENSHELL_SANDBOX_POLICY` | Default path to a policy YAML file. When set, `openshell sandbox create` uses this policy if no `--policy` flag is provided. |

## Shell Completions

Generate shell completion scripts for tab completion:

```console
$ openshell completions bash
$ openshell completions zsh
$ openshell completions fish
```

Pipe the output to your shell's config file:

```console
$ openshell completions zsh >> ~/.zshrc
$ source ~/.zshrc
```

## Self-Teaching

Every command and subcommand includes built-in help. Use `--help` at any level to see available subcommands, flags, and usage examples:

```console
$ openshell --help
$ openshell sandbox --help
$ openshell sandbox create --help
$ openshell gateway --help
```
