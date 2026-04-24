# OpenShell CLI Reference

Quick-reference for the `openshell` command-line interface. For workflow guidance, see [SKILL.md](SKILL.md).

> **Self-teaching**: If a command or flag is not listed here, use `openshell <command> --help` to discover it. The CLI has comprehensive built-in help at every level.

## Global Options

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Increase verbosity (`-v` = info, `-vv` = debug, `-vvv` = trace) |
| `-g`, `--gateway <NAME>` | Gateway to operate on. Also settable via `OPENSHELL_GATEWAY` env var. Falls back to active gateway in `~/.config/openshell/active_gateway`. |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENSHELL_GATEWAY` | Override active gateway name (same as `--gateway`) |
| `OPENSHELL_SANDBOX_POLICY` | Path to default sandbox policy YAML (fallback when `--policy` is not provided) |

---

## Complete Command Tree

```
openshell
├── gateway
│   ├── start [opts]
│   ├── stop [opts]
│   ├── destroy [opts]
│   ├── info [--name]
│   └── select [name]
├── status
├── inference
│   ├── set --provider --model
│   ├── update [--provider] [--model]
│   └── get
├── sandbox
│   ├── create [opts] [-- CMD...]
│   ├── get <name>
│   ├── list [opts]
│   ├── delete <name>...
│   ├── connect <name>
│   ├── upload <name> <path> [dest]
│   ├── download <name> <path> [dest]
│   ├── ssh-config <name>
│   └── image
│       └── push [opts]
├── forward
│   ├── start <port> <name> [-d]
│   ├── stop <port> <name>
│   └── list
├── logs <name> [opts]
├── policy
│   ├── set <name> --policy <path> [--wait]
│   ├── get <name> [--full]
│   └── list <name>
├── provider
│   ├── create --name --type [opts]
│   ├── get <name>
│   ├── list [opts]
│   ├── update <name> --type [opts]
│   └── delete <name>...
├── doctor
│   ├── logs [--name] [-n] [--tail] [--remote] [--ssh-key]
│   └── exec [--name] [--remote] [--ssh-key] -- <command...>
├── term
├── completions <shell>
└── ssh-proxy [opts]
```

---

## Gateway Commands

### `openshell gateway start`

Provision or start a cluster (local or remote).

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | `openshell` | Cluster name |
| `--remote <USER@HOST>` | none | SSH destination for remote deployment |
| `--ssh-key <PATH>` | none | SSH private key for remote deployment |
| `--port <PORT>` | 8080 | Host port mapped to gateway |
| `--gateway-host <HOST>` | none | Override gateway host in metadata |
| `--recreate` | false | Destroy and recreate from scratch if a gateway already exists (skips interactive prompt) |

### `openshell gateway stop`

Stop a cluster (preserves state for later restart).

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Cluster name (defaults to active) |
| `--remote <USER@HOST>` | SSH destination |
| `--ssh-key <PATH>` | SSH private key |

### `openshell gateway destroy`

Destroy a cluster and all its state. Same flags as `stop`.

### `openshell gateway info`

Show deployment details: endpoint and remote host.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Cluster name (defaults to active) |

### `openshell gateway select [name]`

Set the active gateway. Writes to `~/.config/openshell/active_gateway`. When called without arguments, lists all provisioned gateways with the active one marked with `*`.

---

## Doctor Commands

### `openshell doctor logs`

Fetch logs from the gateway Docker container.

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | active gateway | Gateway name |
| `-n, --lines <N>` | all | Number of log lines to return |
| `--tail` | false | Stream live logs (follow mode) |
| `--remote <USER@HOST>` | auto-resolved | SSH destination for remote gateways |
| `--ssh-key <PATH>` | none | SSH private key for remote gateways |

### `openshell doctor exec -- <COMMAND...>`

Run a command inside the gateway container with KUBECONFIG pre-configured.
Launches an interactive `docker exec` session (tunnelled over SSH for remote gateways).

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | active gateway | Gateway name |
| `--remote <USER@HOST>` | auto-resolved | SSH destination for remote gateways |
| `--ssh-key <PATH>` | none | SSH private key for remote gateways |

Examples:
- `openshell doctor exec -- kubectl get pods -A`
- `openshell doctor exec -- k9s`
- `openshell doctor exec -- sh` (interactive shell)

---

## Status Command

### `openshell status`

Show server connectivity and version for the active gateway.

---

## Sandbox Commands

### `openshell sandbox create [OPTIONS] [-- COMMAND...]`

Create a sandbox, wait for readiness, then connect or execute the trailing command. Auto-bootstraps a cluster if none exists.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Sandbox name (auto-generated if omitted) |
| `--from <SOURCE>` | Sandbox source: community name, Dockerfile path, directory, or image reference (BYOC) |
| `--upload <PATH>[:<DEST>]` | Upload local files into sandbox (default dest: `/sandbox`) |
| `--no-keep` | Delete sandbox after the initial command or shell exits |
| `--provider <NAME>` | Provider to attach (repeatable) |
| `--policy <PATH>` | Path to custom policy YAML |
| `--forward <PORT>` | Forward local port to sandbox (keeps the sandbox alive) |
| `--remote <USER@HOST>` | SSH destination for auto-bootstrap |
| `--ssh-key <PATH>` | SSH private key for auto-bootstrap |
| `--tty` | Force pseudo-terminal allocation |
| `--no-tty` | Disable pseudo-terminal allocation |
| `--bootstrap` | Auto-bootstrap a gateway if none is available (skips interactive prompt) |
| `--no-bootstrap` | Never auto-bootstrap; error immediately if no gateway is available |
| `--auto-providers` | Auto-create missing providers from local credentials (skips interactive prompt) |
| `--no-auto-providers` | Never auto-create providers; skip missing providers silently |
| `[-- COMMAND...]` | Command to execute (defaults to interactive shell) |

### `openshell sandbox get <name>`

Show sandbox details (id, name, namespace, phase) and the **active** policy from the gateway (same source whether policy is sandbox-scoped or global). Metadata includes **Policy source** (`sandbox` or `global`) and **Revision** (global policy row when source is global, otherwise sandbox policy row).

| Flag | Description |
|------|-------------|
| `--policy-only` | Print only the active policy YAML to stdout (same policy as above; use for scripts and piping) |

### `openshell sandbox list`

List sandboxes in a table.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit <N>` | 100 | Max sandboxes to return |
| `--offset <N>` | 0 | Pagination offset |
| `--ids` | false | Print only sandbox IDs |
| `--names` | false | Print only sandbox names |

### `openshell sandbox delete <NAME>...`

Delete one or more sandboxes by name. Stops any background port forwards.

### `openshell sandbox connect <name>`

Open an interactive SSH shell to a sandbox.

### `openshell sandbox upload <name> <path> [dest]`

Upload local files to a sandbox using tar-over-SSH.

| Argument | Default | Description |
|----------|---------|-------------|
| `<name>` | -- | Sandbox name (required) |
| `<path>` | -- | Local path to upload (required) |
| `[dest]` | `/sandbox` | Destination path in sandbox |

### `openshell sandbox download <name> <path> [dest]`

Download files from a sandbox using tar-over-SSH.

| Argument | Default | Description |
|----------|---------|-------------|
| `<name>` | -- | Sandbox name (required) |
| `<path>` | -- | Sandbox path to download (required) |
| `[dest]` | `.` | Local destination path |

### `openshell sandbox ssh-config <name>`

Print an SSH config `Host` block for a sandbox. Useful for VS Code Remote-SSH.

---

## Port Forwarding Commands

### `openshell forward start <port> <name>`

Start forwarding a local port to a sandbox.

| Flag | Description |
|------|-------------|
| `<port>` | Port number (used as both local and remote) |
| `<name>` | Sandbox name |
| `-d`, `--background` | Run in background |

### `openshell forward stop <port> <name>`

Stop a background port forward.

### `openshell forward list`

List all active port forwards (sandbox, port, PID, status).

---

## Logs Command

### `openshell logs <name>`

View sandbox logs. Supports one-shot and streaming.

| Flag | Default | Description |
|------|---------|-------------|
| `-n <N>` | 200 | Number of log lines |
| `--tail` | false | Stream live logs |
| `--since <DURATION>` | none | Only show logs from this duration ago (e.g., `5m`, `1h`) |
| `--source <SOURCE>` | `all` | Filter: `gateway`, `sandbox`, or `all` (repeatable) |
| `--level <LEVEL>` | none | Minimum level: `error`, `warn`, `info`, `debug`, `trace` |

---

## Policy Commands

### `openshell policy update <name>`

Incrementally merge live network policy changes into the current sandbox policy. Multiple flags in one invocation are applied as one atomic batch and create at most one new revision.

| Flag | Default | Description |
|------|---------|-------------|
| `--add-endpoint <SPEC>` | repeatable | `host:port[:access[:protocol[:enforcement]]]`. Adds or merges an endpoint. `access`: `read-only`, `read-write`, `full`. `protocol`: `rest`, `sql`. `enforcement`: `enforce`, `audit`. |
| `--remove-endpoint <SPEC>` | repeatable | `host:port`. Removes the endpoint or just the requested port from a multi-port endpoint. |
| `--add-allow <SPEC>` | repeatable | `host:port:METHOD:path_glob`. Adds REST allow rules to an existing `protocol: rest` endpoint. |
| `--add-deny <SPEC>` | repeatable | `host:port:METHOD:path_glob`. Adds REST deny rules to an existing `protocol: rest` endpoint that already has an allow base. |
| `--remove-rule <NAME>` | repeatable | Deletes a named network rule. |
| `--binary <PATH>` | repeatable | Adds binaries to each `--add-endpoint` rule. Valid only with `--add-endpoint`. |
| `--rule-name <NAME>` | none | Overrides the generated rule name. Valid only when exactly one `--add-endpoint` is provided. |
| `--dry-run` | false | Preview the merged policy locally without sending an update to the gateway. |
| `--wait` | false | Wait for the sandbox to confirm the new policy revision is loaded. |
| `--timeout <SECS>` | 60 | Timeout for `--wait`. |

Notes:

- `--add-allow` and `--add-deny` currently operate only on `protocol: rest` endpoints.
- `--wait` cannot be combined with `--dry-run`.
- Use `policy set` when replacing the full policy or changing static sections.

### `openshell policy set <name> --policy <PATH>`

Replace the full policy on a live sandbox. Only the dynamic `network_policies` field can be changed at runtime.

| Flag | Default | Description |
|------|---------|-------------|
| `--policy <PATH>` | -- | Path to policy YAML (required) |
| `--wait` | false | Wait for sandbox to confirm policy is loaded |
| `--timeout <SECS>` | 60 | Timeout for `--wait` |

Exit codes with `--wait`: 0 = loaded, 1 = failed, 124 = timeout.

### `openshell policy get <name>`

Show current active policy for a sandbox.

| Flag | Default | Description |
|------|---------|-------------|
| `--rev <VERSION>` | 0 (latest) | Show a specific revision |
| `--full` | false | Print the full policy as YAML (round-trips with `--policy` input) |

### `openshell policy list <name>`

List policy revision history (version, hash, status, created, error).

| Flag | Default | Description |
|------|---------|-------------|
| `--limit <N>` | 20 | Max revisions to return |

---

## Provider Commands

Supported provider types: `claude`, `opencode`, `codex`, `generic`, `nvidia`, `gitlab`, `github`, `outlook`.

### `openshell provider create --name <NAME> --type <TYPE>`

Create a provider configuration.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Provider name (required) |
| `--type <TYPE>` | Provider type (required) |
| `--from-existing` | Load credentials from local state (mutually exclusive with `--credential`) |
| `--credential KEY[=VALUE]` | Credential pair. Bare `KEY` reads from env var. Repeatable. |
| `--config KEY=VALUE` | Config key/value pair. Repeatable. |

### `openshell provider get <name>`

Show provider details (id, name, type, credential keys, config keys).

### `openshell provider list`

List providers in a table.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit <N>` | 100 | Max providers |
| `--offset <N>` | 0 | Pagination offset |
| `--names` | false | Print only names |

### `openshell provider update <name> --type <TYPE>`

Update an existing provider. Same flags as `create`.

### `openshell provider delete <NAME>...`

Delete one or more providers by name.

---

## Inference Commands

### `openshell inference set`

Configure the managed gateway inference route used by `inference.local`. Both flags are required.

| Flag | Default | Description |
|------|---------|-------------|
| `--provider <NAME>` | -- | Provider record name (required) |
| `--model <ID>` | -- | Model identifier to use for generation requests (required) |

### `openshell inference update`

Partially update the gateway inference configuration. Fetches the current config and applies only the provided overrides. At least one flag is required.

| Flag | Default | Description |
|------|---------|-------------|
| `--provider <NAME>` | unchanged | Provider record name |
| `--model <ID>` | unchanged | Model identifier |

### `openshell inference get`

Show the current gateway inference configuration.

---

## Other Commands

### `openshell term`

Launch the OpenShell interactive TUI.

### `openshell completions <shell>`

Generate shell completion scripts. Supported shells: `bash`, `fish`, `zsh`, `powershell`.

### `openshell ssh-proxy`

SSH proxy used as a `ProxyCommand`. Not typically invoked directly.
