<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# CLI Reference

Complete command reference for the `nemoclaw` CLI. Every subcommand, flag, and option is documented here.

## Command Tree

```text
nemoclaw
├── cluster
│   ├── status
│   ├── use <name>
│   ├── list
│   └── admin
│       ├── deploy
│       ├── stop
│       ├── destroy
│       ├── info
│       └── tunnel
├── sandbox
│   ├── create
│   ├── get [name]
│   ├── list
│   ├── delete <name...>
│   ├── connect [name]
│   ├── sync [name]
│   ├── logs [name]
│   ├── ssh-config <name>
│   ├── forward
│   │   ├── start <port> <name>
│   │   ├── stop <port> <name>
│   │   └── list
│   └── policy
│       ├── set <name>
│       ├── get <name>
│       └── list <name>
├── provider
│   ├── create
│   ├── get <name>
│   ├── list
│   ├── update <name>
│   └── delete <name>
├── inference
│   ├── create
│   ├── update <name>
│   ├── delete <name>
│   └── list
├── term
└── completions <shell>
```

## Cluster Commands

Manage the NemoClaw runtime cluster.

| Command | Description |
|---|---|
| `nemoclaw cluster status` | Show the health and status of the active cluster. |
| `nemoclaw cluster use <name>` | Set the active cluster. All subsequent commands target this cluster. |
| `nemoclaw cluster list` | List all registered clusters. |
| `nemoclaw cluster admin deploy` | Deploy a new cluster. Add `--remote user@host` for remote deployment. |
| `nemoclaw cluster admin stop` | Stop the active cluster, preserving state. |
| `nemoclaw cluster admin destroy` | Permanently remove the cluster and all its data. |
| `nemoclaw cluster admin info` | Show detailed information about the cluster. |
| `nemoclaw cluster admin tunnel` | Set up a kubectl tunnel to a remote cluster. |

## Sandbox Commands

Create and manage isolated agent execution environments.

| Command | Description |
|---|---|
| `nemoclaw sandbox create` | Create a new sandbox. See flag reference below. |
| `nemoclaw sandbox get [name]` | Show detailed information about a sandbox. When name is omitted, uses the last-used sandbox. |
| `nemoclaw sandbox list` | List all sandboxes in the active cluster. |
| `nemoclaw sandbox delete <name...>` | Delete one or more sandboxes by name. |
| `nemoclaw sandbox connect [name]` | Open an interactive SSH session into a running sandbox. When name is omitted, reconnects to the last-used sandbox. |
| `nemoclaw sandbox sync [name]` | Sync files between host and sandbox. Use `--up` or `--down`. When name is omitted, uses the last-used sandbox. |
| `nemoclaw sandbox logs [name]` | View sandbox logs. Use `--tail` for streaming, `--source` and `--level` to filter. When name is omitted, uses the last-used sandbox. |
| `nemoclaw sandbox ssh-config <name>` | Print SSH config for a sandbox. Append to `~/.ssh/config` for VS Code Remote-SSH. |
| `nemoclaw sandbox forward start <port> <name>` | Forward a sandbox port to the host. Add `-d` for background mode. |
| `nemoclaw sandbox forward stop <port> <name>` | Stop an active port forward. |
| `nemoclaw sandbox forward list` | List all active port forwards. |
| `nemoclaw sandbox policy set <name>` | Apply or update a policy on a running sandbox. Pass `--policy <file>`. |
| `nemoclaw sandbox policy get <name>` | Show the active policy for a sandbox. Add `--full` for the complete policy with metadata. |
| `nemoclaw sandbox policy list <name>` | List all policy versions applied to a sandbox, with status. |

### Sandbox Create Flags

| Flag | Description |
|---|---|
| `--name` | Assign a human-readable name to the sandbox. Auto-generated if omitted. |
| `--provider` | Attach a credential provider. Repeatable for multiple providers. |
| `--policy` | Path to a policy YAML file to apply at creation time. |
| `--sync` | Sync local files into the sandbox before running. |
| `--keep` | Keep the sandbox alive after the trailing command exits. |
| `--forward` | Forward a local port into the sandbox at startup. |
| `--from` | Build from a community sandbox name, local Dockerfile directory, or container image reference. |
| `-- <command>` | The command to run inside the sandbox. Everything after `--` is passed as the agent command. |

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

Manage inference routes that intercept and reroute LLM API calls from userland code.

| Command | Description |
|---|---|
| `nemoclaw inference create` | Create a new inference route. See flag reference below. |
| `nemoclaw inference update <name>` | Update an existing route's configuration. |
| `nemoclaw inference delete <name>` | Delete an inference route. |
| `nemoclaw inference list` | List all inference routes in the active cluster. |

### Inference Create Flags

| Flag | Description |
|---|---|
| `--routing-hint` | Short label that identifies this route (for example, `local`, `nvidia`, `staging`). Referenced by `allowed_routes` in sandbox policies. |
| `--base-url` | Base URL of the inference backend (for example, `https://vllm.internal:8000`). |
| `--model-id` | Model identifier to send to the backend (for example, `meta/llama-3.1-8b`). |
| `--api-key` | API key for authenticating with the backend. |
| `--protocol` | API protocol: `openai` or `anthropic`. Defaults to `openai`. |
| `--disabled` | Create the route in a disabled state. |

## NemoClaw Terminal

`nemoclaw term` launches the NemoClaw Terminal, a dashboard that shows sandbox
status, live logs, and policy decisions in a single view. Navigate with `j`/`k`,
press `f` to follow live output, `s` to filter by source, and `q` to quit.

Refer to {doc}`/sandboxes/terminal` for the full guide, including how to read log
entries, diagnose blocked connections, and interpret inference interception.

## Sandbox Name Fallback

Commands that accept an optional `[name]` argument---`get`, `connect`, `sync`, and `logs`---fall back to the last-used sandbox when the name is omitted. The CLI records the sandbox name each time you create or connect to a sandbox. When falling back, the CLI prints a hint showing which sandbox was selected.

If no sandbox has been used yet and no name is provided, the command exits with an error prompting you to specify a name.

## Environment Variables

| Variable | Description |
|---|---|
| `NEMOCLAW_CLUSTER` | Name of the cluster to operate on. Overrides the active cluster set by `nemoclaw cluster use`. |
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

## Self-Teaching

Every command and subcommand includes built-in help. Use `--help` at any level to see available subcommands, flags, and usage examples:

```console
$ nemoclaw --help
$ nemoclaw sandbox --help
$ nemoclaw sandbox create --help
$ nemoclaw cluster admin --help
```
