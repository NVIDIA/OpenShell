---
title:
  page: CLI Reference
  nav: CLI
description: Complete command reference for the openshell CLI including all subcommands, flags, and environment variables.
topics:
- Generative AI
- Cybersecurity
tags:
- CLI
- Reference
- Commands
- AI Agents
content:
  type: reference
  difficulty: technical_beginner
  audience:
  - engineer
  - data_scientist
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# CLI Reference

Complete command reference for the `openshell` CLI. Every subcommand, flag, and option is documented here.

## Command Tree

The full hierarchy of `openshell` subcommands:

```text
openshell
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
│   ├── add <url>
│   └── select [name]
├── sandbox
│   ├── create
│   ├── get [name]
│   ├── list
│   ├── delete <name...> [--all]
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
├── doctor
│   ├── logs
│   └── exec
└── completions <shell>
```

:::{tip}
Commands that accept an optional `[name]` argument — such as `get`, `connect`, `upload`, `download`, and `logs` — fall back to the last-used sandbox when the name is omitted. The CLI records the sandbox name each time you create or connect, and prints a hint showing which sandbox was selected.
:::

## Status, Logs, and Terminal

Check gateway health, stream sandbox logs, and launch the terminal dashboard:

| Command | Description |
|---|---|
| `openshell status` | Show the health and status of the active gateway. |
| `openshell logs [name]` | View sandbox logs. Use `--tail` for streaming, `--source` and `--level` to filter. |
| `openshell term` | Launch the OpenShell Terminal — a dashboard showing sandbox status, live logs, and policy decisions in a single view. Navigate with `j`/`k`, press `f` to follow live output, `s` to filter by source, and `q` to quit. |

Refer to {doc}`/sandboxes/create-and-manage` for more on monitoring sandboxes and reading log entries.

## Gateway Commands

Manage the OpenShell runtime cluster.

| Command | Description |
|---|---|
| `openshell gateway start` | Deploy a new cluster. Add `--remote user@host` for remote deployment. |
| `openshell gateway stop` | Stop the active cluster, preserving state. |
| `openshell gateway destroy` | Permanently remove the cluster and all its data. |
| `openshell gateway info` | Show detailed information about the cluster. |
| `openshell gateway add <url>` | Register an existing remote gateway by URL. |
| `openshell gateway select <name>` | Set the active cluster. All subsequent commands target this cluster. |
| `openshell gateway select` | List all registered clusters (when called without a name). |

## Diagnostic Commands

Troubleshoot gateway issues.

| Command | Description |
|---|---|
| `openshell doctor logs` | Fetch logs from the gateway Docker container. Use `--tail` for streaming, `-n` to limit line count. |
| `openshell doctor exec -- <command>` | Run a command inside the gateway container (e.g., `kubectl get pods -A`, `k9s`, `sh`). |

## Sandbox Commands

Create and manage isolated agent execution environments.

| Command | Description |
|---|---|
| `openshell sandbox create` | Create a new sandbox. Refer to the flag reference below. |
| `openshell sandbox get [name]` | Show detailed information about a sandbox. |
| `openshell sandbox list` | List all sandboxes in the active cluster. |
| `openshell sandbox delete <name...>` | Delete one or more sandboxes by name. Use `--all` to delete every sandbox in the active gateway. |
| `openshell sandbox connect [name]` | Open an interactive SSH session into a running sandbox. |
| `openshell sandbox upload [name]` | Upload files from the host into a sandbox. |
| `openshell sandbox download [name]` | Download files from a sandbox to the host. |
| `openshell sandbox ssh-config <name>` | Print the generated SSH config block for a sandbox. |

### Sandbox Create Flags

The following flags control sandbox creation:

| Flag | Description |
|---|---|
| `--name` | Assign a human-readable name to the sandbox. Auto-generated if omitted. |
| `--provider` | Attach a credential provider. Repeatable for multiple providers. |
| `--policy` | Path to a policy YAML file to apply at creation time. |
| `--upload` | Upload local files into the sandbox before running. |
| `--keep` | Keep the sandbox alive after the initial command or shell exits. |
| `--editor` | Launch `vscode` or `cursor` into `/sandbox`; installs OpenShell-managed SSH config and implies `--keep`. |
| `--forward` | Forward a local port into the sandbox at startup. Implies `--keep`. |
| `--from` | Build from a community sandbox name, local Dockerfile directory, or container image reference. |
| `-- <command>` | The command to run inside the sandbox. Everything after `--` is passed as the agent command. |

## Policy Commands

Apply and inspect sandbox policies at runtime.

| Command | Description |
|---|---|
| `openshell policy set <name>` | Apply or update a policy on a running sandbox. Pass `--policy <file>`. |
| `openshell policy get <name>` | Show the active policy for a sandbox. Add `--full` for the complete policy with metadata. |
| `openshell policy list <name>` | List all policy versions applied to a sandbox, with status. |

## Port Forwarding Commands

Forward sandbox ports to the host for local access.

| Command | Description |
|---|---|
| `openshell forward start <port> <name>` | Forward a sandbox port to the host. Add `-d` for background mode. |
| `openshell forward stop <port> <name>` | Stop an active port forward. |
| `openshell forward list` | List all active port forwards. |

## Provider Commands

Manage credential providers that inject secrets into sandboxes.

| Command | Description |
|---|---|
| `openshell provider create` | Create a new credential provider. Refer to the flag reference below. |
| `openshell provider get <name>` | Show details of a provider. |
| `openshell provider list` | List all providers in the active cluster. |
| `openshell provider update <name>` | Update a provider's credentials or configuration. |
| `openshell provider delete <name>` | Delete a provider. |

### Provider Create Flags

The following flags control provider creation:

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

Show the current inference configuration, including provider, model, and version.

## Environment Variables

The following environment variables override CLI defaults:

| Variable | Description |
|---|---|
| `OPENSHELL_GATEWAY` | Name of the gateway to operate on. Overrides the active gateway set by `openshell gateway select`. |
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

## Built-in Help

Every command and subcommand includes built-in help. Use `--help` at any level to see available subcommands, flags, and usage examples:

```console
$ openshell --help
$ openshell sandbox --help
$ openshell sandbox create --help
$ openshell gateway --help
```

Help output groups flags under distinct headings: `FLAGS` for command-specific options, `GATEWAY FLAGS` for `--gateway` and `--gateway-endpoint`, and `GLOBAL FLAGS` for `--verbose`, `--help`, and `--version`.
