# NemoClaw CLI Reference

Quick-reference for the `nemoclaw` command-line interface. For workflow guidance, see [SKILL.md](SKILL.md).

> **Self-teaching**: If a command or flag is not listed here, use `nemoclaw <command> --help` to discover it. The CLI has comprehensive built-in help at every level.

## Global Options

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Increase verbosity (`-v` = info, `-vv` = debug, `-vvv` = trace) |
| `-c`, `--cluster <NAME>` | Cluster to operate on. Also settable via `NEMOCLAW_CLUSTER` env var. Falls back to active cluster in `~/.config/nemoclaw/active_cluster`. |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NEMOCLAW_CLUSTER` | Override active cluster name (same as `--cluster`) |
| `NEMOCLAW_SANDBOX_POLICY` | Path to default sandbox policy YAML (fallback when `--policy` is not provided) |

---

## Complete Command Tree

```
nemoclaw
├── cluster
│   ├── status
│   ├── use <name>
│   ├── list
│   └── admin
│       ├── deploy [opts]
│       ├── stop [opts]
│       ├── destroy [opts]
│       ├── info [--name]
│       └── tunnel [opts]
├── sandbox
│   ├── create [opts] [-- CMD...]
│   ├── get <name>
│   ├── list [opts]
│   ├── delete <name>...
│   ├── connect <name>
│   ├── sync <name> {--up|--down} <path> [dest]
│   ├── logs <name> [opts]
│   ├── ssh-config <name>
│   ├── forward
│   │   ├── start <port> <name> [-d]
│   │   ├── stop <port> <name>
│   │   └── list
│   ├── image
│   │   └── push [opts]
│   └── policy
│       ├── set <name> --policy <path> [--wait]
│       ├── get <name> [--full]
│       └── list <name>
├── provider
│   ├── create --name --type [opts]
│   ├── get <name>
│   ├── list [opts]
│   ├── update <name> --type [opts]
│   └── delete <name>...
├── inference
│   ├── create [opts]
│   ├── update <name> [opts]
│   ├── delete <name>...
│   └── list [opts]
├── gator
├── completions <shell>
└── ssh-proxy [opts]
```

---

## Cluster Commands

### `nemoclaw cluster status`

Show server connectivity and version.

### `nemoclaw cluster use <name>`

Set the active cluster. Writes to `~/.config/nemoclaw/active_cluster`.

### `nemoclaw cluster list`

List all provisioned clusters. Active cluster marked with `*`.

### `nemoclaw cluster admin deploy`

Provision or start a cluster (local or remote).

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | `nemoclaw` | Cluster name |
| `--remote <USER@HOST>` | none | SSH destination for remote deployment |
| `--ssh-key <PATH>` | none | SSH private key for remote deployment |
| `--port <PORT>` | 8080 | Host port mapped to gateway |
| `--gateway-host <HOST>` | none | Override gateway host in metadata |
| `--kube-port [PORT]` | none | Expose K8s control plane on host port |
| `--update-kube-config` | false | Write kubeconfig into `~/.kube/config` |
| `--get-kubeconfig` | false | Print kubeconfig to stdout |

### `nemoclaw cluster admin stop`

Stop a cluster (preserves state for later restart).

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Cluster name (defaults to active) |
| `--remote <USER@HOST>` | SSH destination |
| `--ssh-key <PATH>` | SSH private key |

### `nemoclaw cluster admin destroy`

Destroy a cluster and all its state. Same flags as `stop`.

### `nemoclaw cluster admin info`

Show deployment details: endpoint, kubeconfig path, kube port, remote host.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Cluster name (defaults to active) |

### `nemoclaw cluster admin tunnel`

Print or start an SSH tunnel for kubectl access to a remote cluster.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Cluster name (defaults to active) |
| `--remote <USER@HOST>` | SSH destination |
| `--ssh-key <PATH>` | SSH private key |
| `--print-command` | Only print the SSH command, don't execute |

---

## Sandbox Commands

### `nemoclaw sandbox create [OPTIONS] [-- COMMAND...]`

Create a sandbox, wait for readiness, then connect or execute the trailing command. Auto-bootstraps a cluster if none exists.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Sandbox name (auto-generated if omitted) |
| `--from <SOURCE>` | Sandbox source: community name, Dockerfile path, directory, or image reference (BYOC) |
| `--sync` | Sync local git-tracked files into sandbox at `/sandbox` |
| `--keep` | Keep sandbox alive after non-interactive commands finish |
| `--provider <NAME>` | Provider to attach (repeatable) |
| `--policy <PATH>` | Path to custom policy YAML |
| `--forward <PORT>` | Forward local port to sandbox (implies `--keep`) |
| `--remote <USER@HOST>` | SSH destination for auto-bootstrap |
| `--ssh-key <PATH>` | SSH private key for auto-bootstrap |
| `--tty` | Force pseudo-terminal allocation |
| `--no-tty` | Disable pseudo-terminal allocation |
| `[-- COMMAND...]` | Command to execute (defaults to interactive shell) |

### `nemoclaw sandbox get <name>`

Show sandbox details (id, name, namespace, phase, policy).

### `nemoclaw sandbox list`

List sandboxes in a table.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit <N>` | 100 | Max sandboxes to return |
| `--offset <N>` | 0 | Pagination offset |
| `--ids` | false | Print only sandbox IDs |
| `--names` | false | Print only sandbox names |

### `nemoclaw sandbox delete <NAME>...`

Delete one or more sandboxes by name. Stops any background port forwards.

### `nemoclaw sandbox connect <name>`

Open an interactive SSH shell to a sandbox.

### `nemoclaw sandbox sync <name> {--up <path> | --down <path>} [dest]`

Sync files to/from a sandbox using tar-over-SSH.

| Flag | Description |
|------|-------------|
| `--up <LOCAL_PATH>` | Push local files to sandbox |
| `--down <SANDBOX_PATH>` | Pull sandbox files to local |
| `[DEST]` | Destination path (default: `/sandbox` for up, `.` for down) |

### `nemoclaw sandbox logs <name>`

View sandbox logs. Supports one-shot and streaming.

| Flag | Default | Description |
|------|---------|-------------|
| `-n <N>` | 200 | Number of log lines |
| `--tail` | false | Stream live logs |
| `--since <DURATION>` | none | Only show logs from this duration ago (e.g., `5m`, `1h`) |
| `--source <SOURCE>` | `all` | Filter: `gateway`, `sandbox`, or `all` (repeatable) |
| `--level <LEVEL>` | none | Minimum level: `error`, `warn`, `info`, `debug`, `trace` |

### `nemoclaw sandbox ssh-config <name>`

Print an SSH config `Host` block for a sandbox. Useful for VS Code Remote-SSH.

---

## Port Forwarding Commands

### `nemoclaw sandbox forward start <port> <name>`

Start forwarding a local port to a sandbox.

| Flag | Description |
|------|-------------|
| `<port>` | Port number (used as both local and remote) |
| `<name>` | Sandbox name |
| `-d`, `--background` | Run in background |

### `nemoclaw sandbox forward stop <port> <name>`

Stop a background port forward.

### `nemoclaw sandbox forward list`

List all active port forwards (sandbox, port, PID, status).

---

## Policy Commands

### `nemoclaw sandbox policy set <name> --policy <PATH>`

Update the policy on a live sandbox. Only dynamic fields (`network_policies`, `inference`) can be changed at runtime.

| Flag | Default | Description |
|------|---------|-------------|
| `--policy <PATH>` | -- | Path to policy YAML (required) |
| `--wait` | false | Wait for sandbox to confirm policy is loaded |
| `--timeout <SECS>` | 60 | Timeout for `--wait` |

Exit codes with `--wait`: 0 = loaded, 1 = failed, 124 = timeout.

### `nemoclaw sandbox policy get <name>`

Show current active policy for a sandbox.

| Flag | Default | Description |
|------|---------|-------------|
| `--rev <VERSION>` | 0 (latest) | Show a specific revision |
| `--full` | false | Print the full policy as YAML (round-trips with `--policy` input) |

### `nemoclaw sandbox policy list <name>`

List policy revision history (version, hash, status, created, error).

| Flag | Default | Description |
|------|---------|-------------|
| `--limit <N>` | 20 | Max revisions to return |

---

## Provider Commands

Supported provider types: `claude`, `opencode`, `codex`, `generic`, `nvidia`, `gitlab`, `github`, `outlook`.

### `nemoclaw provider create --name <NAME> --type <TYPE>`

Create a provider configuration.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Provider name (required) |
| `--type <TYPE>` | Provider type (required) |
| `--from-existing` | Load credentials from local state (mutually exclusive with `--credential`) |
| `--credential KEY[=VALUE]` | Credential pair. Bare `KEY` reads from env var. Repeatable. |
| `--config KEY=VALUE` | Config key/value pair. Repeatable. |

### `nemoclaw provider get <name>`

Show provider details (id, name, type, credential keys, config keys).

### `nemoclaw provider list`

List providers in a table.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit <N>` | 100 | Max providers |
| `--offset <N>` | 0 | Pagination offset |
| `--names` | false | Print only names |

### `nemoclaw provider update <name> --type <TYPE>`

Update an existing provider. Same flags as `create`.

### `nemoclaw provider delete <NAME>...`

Delete one or more providers by name.

---

## Inference Commands

### `nemoclaw inference create`

Create an inference route. Auto-detects supported protocols if `--protocol` is omitted.

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | auto-generated | Route name |
| `--routing-hint <HINT>` | -- | Routing hint (required) |
| `--base-url <URL>` | -- | Inference endpoint base URL (required) |
| `--protocol <PROTO>` | auto-detected | Protocol(s): `openai_chat_completions`, `openai_completions`, `anthropic_messages`. Repeatable. |
| `--api-key <KEY>` | `""` | API key for the endpoint |
| `--model-id <ID>` | -- | Model identifier (required) |
| `--disabled` | false | Create in disabled state |

### `nemoclaw inference update <name>`

Update an existing inference route. Same flags as `create`.

### `nemoclaw inference delete <NAME>...`

Delete inference routes by name.

### `nemoclaw inference list`

List inference routes.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit <N>` | 100 | Max routes |
| `--offset <N>` | 0 | Pagination offset |

---

## Other Commands

### `nemoclaw gator`

Launch the Gator interactive TUI.

### `nemoclaw completions <shell>`

Generate shell completion scripts. Supported shells: `bash`, `fish`, `zsh`, `powershell`.

### `nemoclaw ssh-proxy`

SSH proxy used as a `ProxyCommand`. Not typically invoked directly.
