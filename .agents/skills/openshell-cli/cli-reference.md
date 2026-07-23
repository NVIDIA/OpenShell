# OpenShell CLI Reference

Quick-reference for the `openshell` command-line interface. For workflow guidance, see [SKILL.md](SKILL.md).

> **Self-teaching**: If a command or flag is not listed here, use `openshell <command> --help` to discover it. The CLI has comprehensive built-in help at every level.

## Global Options

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Increase verbosity (`-v` = info, `-vv` = debug, `-vvv` = trace) |
| `-g`, `--gateway <NAME>` | Gateway to operate on. Also settable via `OPENSHELL_GATEWAY` env var. Falls back to active gateway in `~/.config/openshell/active_gateway`. |
| `--gateway-endpoint <URL>` | Connect directly to a gateway endpoint without looking up stored metadata. Also settable via `OPENSHELL_GATEWAY_ENDPOINT`. |
| `--gateway-insecure` | Skip TLS certificate verification. Also settable via `OPENSHELL_GATEWAY_INSECURE`; use only for trusted development endpoints. |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENSHELL_GATEWAY` | Override active gateway name (same as `--gateway`) |
| `OPENSHELL_GATEWAY_ENDPOINT` | Connect directly to a gateway endpoint (same as `--gateway-endpoint`) |
| `OPENSHELL_GATEWAY_INSECURE` | Skip TLS verification when set (same as `--gateway-insecure`) |
| `OPENSHELL_SANDBOX_POLICY` | Path to default sandbox policy YAML (fallback when `--policy` is not provided) |
| `OPENSHELL_COMMUNITY_REGISTRY` | Override the community sandbox image registry prefix used by `sandbox create --from <name>` |
| `OPENSHELL_THEME` | TUI theme: `auto`, `dark`, or `light` |

---

## Complete Command Tree

```
openshell
├── gateway
│   ├── add <endpoint> [opts]
│   ├── login [name]
│   ├── logout [name]
│   ├── remove [name]
│   ├── info [--name]
│   ├── list
│   └── select [name]
├── status
├── inference
│   ├── set --provider --model
│   ├── update [--provider] [--model]
│   └── get
├── sandbox
│   ├── create [opts] [-- CMD...]
│   ├── get [name]
│   ├── list [opts]
│   ├── delete [name]... [--all]
│   ├── exec [--name <name>] [opts] -- CMD...
│   ├── connect [name] [--editor <editor>]
│   ├── upload <name> <path> [dest]
│   ├── download <name> <path> [dest]
│   ├── ssh-config [name]
│   └── provider
│       ├── list [name]
│       ├── attach <name> <provider>
│       └── detach <name> <provider>
├── forward
│   ├── start <port> [name] [-d]
│   ├── stop <port> [name]
│   ├── list
│   └── service [name] --target-port <port> [opts]
├── service
│   ├── expose <sandbox> <target-port> [service]
│   ├── list [sandbox]
│   ├── get <sandbox> [service]
│   └── delete <sandbox> [service]
├── logs [name] [opts]
├── policy
│   ├── set [name] --policy <path> [--global] [--wait]
│   ├── update [name] [opts]
│   ├── get [name] [--full|--base] [--global]
│   ├── list [name] [--global]
│   ├── delete --global
│   └── prove --policy <path> --credentials <path> [opts]
├── settings
│   ├── get [name] [--global]
│   ├── set [name] --key <key> --value <value> [--global]
│   └── delete [name] --key <key> [--global]
├── rule (advanced; hidden from top-level help)
│   ├── get [name] [--status <status>]
│   ├── approve [name] --chunk-id <id>
│   ├── reject [name] --chunk-id <id> [--reason <reason>]
│   ├── approve-all [name] [--include-security-flagged]
│   ├── clear [name]
│   └── history [name]
├── provider
│   ├── create --name --type [opts]
│   ├── refresh
│   │   ├── status <name> [opts]
│   │   ├── configure <name> [opts]
│   │   ├── rotate <name> --credential-key <key>
│   │   └── delete <name> --credential-key <key>
│   ├── get <name>
│   ├── list [opts]
│   ├── list-profiles [opts]
│   ├── profile
│   │   ├── export <id> [opts]
│   │   ├── import (--file <path>|--from <dir>)
│   │   ├── update <id> --file <path>
│   │   ├── lint (--file <path>|--from <dir>)
│   │   └── delete <id>
│   ├── update <name> [opts]
│   └── delete <name>...
├── doctor
│   └── check
├── term
├── completions <shell>
└── ssh-proxy [opts]
```

---

## Gateway Commands

### `openshell gateway add <ENDPOINT>`

Register an existing gateway endpoint.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Gateway name |
| `--local` | Register a local mTLS gateway; with HTTP, store a local plaintext registration |
| `--remote <USER@HOST>` | Register a remote mTLS gateway over SSH; with HTTP, store a remote plaintext registration |
| `--oidc-issuer <URL>` | Register an OIDC-authenticated gateway |
| `--oidc-client-id <ID>` | OIDC client ID (default: `openshell-cli`; requires `--oidc-issuer`) |
| `--oidc-audience <AUDIENCE>` | OIDC API audience (requires `--oidc-issuer`) |
| `--oidc-scopes <SCOPES>` | Space-separated OAuth2 scopes (requires `--oidc-issuer`) |

Examples:

- `openshell gateway add http://127.0.0.1:8080 --local --name local`
- `openshell gateway add https://gateway.example.com --name production`
- `openshell gateway add ssh://user@gateway.example.com:8080 --name remote`

An `http://` endpoint is direct plaintext. A plain `https://` endpoint uses edge authentication. `--local` and `--remote` select mTLS registration modes when used with HTTPS; required certificates must already exist. An `ssh://` endpoint is shorthand for a remote gateway.

### `openshell gateway remove [name]`

Remove a local gateway registration. This removes CLI metadata and stored auth tokens only; package managers, systemd, Helm, Docker, and other platform tools still own the gateway process.

### `openshell gateway login [name]`

Refresh browser-based authentication for an edge-authenticated or OIDC gateway.

### `openshell gateway logout [name]`

Clear locally stored OIDC or edge credentials for a gateway.

### `openshell gateway info`

Show gateway details: endpoint, auth mode, and remote host metadata when present.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Gateway name (defaults to active) |

### `openshell gateway select [name]`

Set the active gateway. Writes to `~/.config/openshell/active_gateway`. Without a name, opens an interactive chooser on a TTY or lists gateways in non-interactive mode.

### `openshell gateway list`

List registered gateways and mark the active one. `--output table|yaml|json` selects the format.

---

## Doctor Commands

### `openshell doctor check`

Validate local Docker prerequisites for standalone gateway development. For
package-managed or Helm gateways, use `systemctl`, `journalctl`, `kubectl`, and
`helm` directly.

---

## Status Command

### `openshell status`

Show server connectivity and version for the active gateway.

---

## Sandbox Commands

### `openshell sandbox create [OPTIONS] [-- COMMAND...]`

Create a sandbox through the selected gateway, wait for readiness, then connect, open an editor, or execute the trailing command.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Sandbox name (auto-generated if omitted) |
| `--from <SOURCE>` | Community name, Dockerfile path, directory, or image reference (BYOC) |
| `--no-keep` | Delete the sandbox after the initial command or shell exits |
| `--editor vscode|cursor` | Launch a remote editor and keep the sandbox alive |
| `--gpu [COUNT]` | Request the driver's default GPU selection or a specific count |
| `--cpu <QUANTITY>` | CPU limit (for example: `500m`, `1`, `2.5`) |
| `--memory <QUANTITY>` | Memory limit (for example: `512Mi`, `4Gi`, `8G`) |
| `--driver-config-json <JSON>` | Experimental driver-keyed configuration object |
| `--provider <NAME>` | Provider to attach (repeatable) |
| `--policy <PATH>` | Custom policy YAML; overrides the built-in default and `OPENSHELL_SANDBOX_POLICY` |
| `--forward <[BIND:]PORT>` | Start a local port forward and keep the sandbox alive |
| `--tty`, `--no-tty` | Force or disable pseudo-terminal allocation |
| `--auto-providers` | Auto-create missing providers from local credentials |
| `--no-auto-providers` | Never auto-create providers; error if a required provider is missing |
| `--label <KEY=VALUE>` | Attach a label (repeatable) |
| `--env <KEY=VALUE>` | Inject an environment variable (repeatable) |
| `--approval-mode manual|auto` | Handle agent-authored policy proposals; default: `manual` |
| `--upload <PATH>[:<DEST>]` | Upload local files to the working directory or an explicit destination (repeatable) |
| `--no-git-ignore` | Disable `.gitignore` filtering for `--upload` |
| `[-- COMMAND...]` | Initial command (defaults to an interactive shell) |

### `openshell sandbox get [name]`

Show sandbox details and the active policy. Metadata identifies sandbox or global policy source and the corresponding revision. The name defaults to the last-used sandbox.

| Flag | Description |
|------|-------------|
| `--policy-only` | Print only the active policy YAML to stdout |

### `openshell sandbox list`

| Flag | Default | Description |
|------|---------|-------------|
| `--limit <N>` | 100 | Maximum sandboxes |
| `--offset <N>` | 0 | Pagination offset |
| `--ids` | false | Print only sandbox IDs |
| `--names` | false | Print only sandbox names |
| `--selector <SELECTOR>` | none | Filter by `key1=value1,key2=value2` |
| `--output table|yaml|json` | `table` | Output format |

### `openshell sandbox delete [NAME]...`

Delete one or more named sandboxes, or use `--all`. Deletion stops background port forwards.

### `openshell sandbox exec [OPTIONS] -- COMMAND...`

Execute a command through the gRPC exec endpoint, stream its output, and exit with the remote command's exit code.

| Flag | Default | Description |
|------|---------|-------------|
| `-n`, `--name <NAME>` | last-used | Sandbox name |
| `--workdir <PATH>` | none | Working directory in the sandbox |
| `--timeout <SECONDS>` | 0 | Command timeout; `0` disables it |
| `--tty`, `--no-tty` | auto | Force or disable a pseudo-terminal |
| `--env <KEY=VALUE>` | none | Command environment variable (repeatable) |

### `openshell sandbox connect [name]`

Open an interactive SSH shell. The name defaults to the last-used sandbox. `--editor vscode|cursor` launches a supported remote editor instead.

### `openshell sandbox upload <name> <path> [dest]`

Upload files using tar-over-SSH. The destination defaults to the container working directory. `.gitignore` filtering is enabled unless `--no-git-ignore` is passed.

### `openshell sandbox download <name> <path> [dest]`

Download files using tar-over-SSH. The local destination defaults to `.`.

### `openshell sandbox ssh-config [name]`

Print an SSH config `Host` block. The name defaults to the last-used sandbox.

### `openshell sandbox provider`

Manage providers on an existing sandbox:

- `openshell sandbox provider list [name]`
- `openshell sandbox provider attach <name> <provider>`
- `openshell sandbox provider detach <name> <provider>`

---

## Port Forwarding Commands

### `openshell forward start <port> [name]`

Start forwarding a local port to a sandbox.

| Flag | Description |
|------|-------------|
| `<port>` | `[bind_address:]port`; the port is used locally and remotely |
| `[name]` | Sandbox name (defaults to last-used) |
| `-d`, `--background` | Run in background |

### `openshell forward stop <port> [name]`

Stop a background port forward. When the sandbox name is omitted, it is inferred from active forwards.

### `openshell forward list`

List all active port forwards (sandbox, port, PID, status).

### `openshell forward service [name] --target-port <port>`

Forward a local TCP port to a loopback service inside a sandbox over the gRPC relay.

| Flag | Default | Description |
|------|---------|-------------|
| `--target-port <PORT>` | required | Service port inside the sandbox |
| `--target-host <HOST>` | `127.0.0.1` | Loopback service host |
| `--local <[BIND:]PORT>` | target port | Local bind; port `0` requests dynamic assignment |

---

## Service Commands

Gateway-managed HTTP service endpoints:

- `openshell service expose <sandbox> <target-port> [service]`
- `openshell service list [sandbox] [--limit N] [--offset N]`
- `openshell service get <sandbox> [service]`
- `openshell service delete <sandbox> [service]`

---

## Logs Command

### `openshell logs [name]`

View sandbox logs. Supports one-shot and streaming.

| Flag | Default | Description |
|------|---------|-------------|
| `-n <N>` | 200 | Number of log lines |
| `--tail` | false | Stream live logs |
| `--since <DURATION>` | none | Only show logs from this duration ago (e.g., `5m`, `1h`) |
| `--source <SOURCE>` | `all` | Filter: `gateway`, `sandbox`, or `all` (repeatable) |
| `--level <LEVEL>` | none | Minimum level: `error`, `warn`, `info`, `debug`, `trace` |

The sandbox name defaults to the last-used sandbox.

---

## Policy Commands

### `openshell policy update [name]`

Incrementally merge live network policy changes into the current sandbox policy. Multiple flags in one invocation are applied as one atomic batch and create at most one new revision.

| Flag | Default | Description |
|------|---------|-------------|
| `--add-endpoint <SPEC>` | repeatable | `host:port[:access[:protocol[:enforcement[:options]]]]`. Adds or merges an endpoint. |
| `--remove-endpoint <SPEC>` | repeatable | `host:port`. Removes the endpoint or just the requested port from a multi-port endpoint. |
| `--add-allow <SPEC>` | repeatable | `host:port:METHOD:path_glob`. Adds REST or WebSocket allow rules. |
| `--add-deny <SPEC>` | repeatable | `host:port:METHOD:path_glob`. Adds REST or WebSocket deny rules. |
| `--remove-rule <NAME>` | repeatable | Deletes a named network rule. |
| `--binary <PATH>` | repeatable | Adds binaries to each `--add-endpoint` rule. Valid only with `--add-endpoint`. |
| `--rule-name <NAME>` | none | Overrides the generated rule name. Valid only when exactly one `--add-endpoint` is provided. |
| `--dry-run` | false | Preview the merged policy locally without sending an update to the gateway. |
| `--wait` | false | Wait for the sandbox to confirm the new policy revision is loaded. |
| `--timeout <SECS>` | 60 | Timeout for `--wait`. |

Notes:

- The sandbox name defaults to the last-used sandbox.
- `--add-allow` and `--add-deny` operate on REST and WebSocket endpoints. Use full YAML for JSON-RPC, MCP, SQL, or other policy structure.
- `--wait` cannot be combined with `--dry-run`.
- Use `policy set` when replacing the full policy or changing static sections.

### `openshell policy set [name] --policy <PATH>`

Replace the full policy on a live sandbox. Only the dynamic `network_policies` field can be changed at runtime.

| Flag | Default | Description |
|------|---------|-------------|
| `--policy <PATH>` | -- | Path to policy YAML (required) |
| `--global` | false | Apply as the gateway-global policy |
| `--yes` | false | Skip confirmation for a global update |
| `--wait` | false | Wait for sandbox to confirm policy is loaded |
| `--timeout <SECS>` | 60 | Timeout for `--wait` |

Exit codes with `--wait`: 0 = loaded, 1 = failed, 124 = timeout.

### `openshell policy get [name]`

Show the current effective sandbox policy or stored global policy.

| Flag | Default | Description |
|------|---------|-------------|
| `--rev <VERSION>` | 0 | Show a stored revision; `0` shows the current effective policy |
| `--full` | false | Include the effective policy payload and provider-composed entries |
| `--base` | false | Include the base policy payload without provider-composed entries |
| `--output table|json` | `table` | Output format |
| `--global` | false | Show the global policy revision |

### `openshell policy list [name]`

List policy revision history (version, hash, status, created, error).

| Flag | Default | Description |
|------|---------|-------------|
| `--limit <N>` | 20 | Max revisions to return |
| `--global` | false | List global policy revisions |

### `openshell policy delete --global`

Delete the global policy lock and restore sandbox-level policy control. `--yes` skips confirmation.

### `openshell policy prove`

Prove policy properties or find counterexamples.

| Flag | Description |
|------|-------------|
| `--policy <PATH>` | Policy YAML (required) |
| `--credentials <PATH>` | Credential descriptor YAML (required) |
| `--registry <DIR>` | Capability registry directory (defaults to bundled) |
| `--accepted-risks <PATH>` | Accepted-risks YAML |
| `--compact` | One-line-per-finding output |

### `openshell rule` (advanced)

Review agent-authored network rule proposals. This command group is intentionally hidden from top-level help but is part of the policy-advisor workflow.

- `openshell rule get [name] [--status pending|approved|rejected]`
- `openshell rule approve [name] --chunk-id <id>`
- `openshell rule reject [name] --chunk-id <id> [--reason <reason>]`
- `openshell rule approve-all [name] [--include-security-flagged]`
- `openshell rule clear [name]`
- `openshell rule history [name]`

Sandbox names default to the last-used sandbox. Bulk approval of security-flagged proposals requires explicit `--include-security-flagged`.

---

## Settings Commands

Settings support sandbox and gateway-global scopes:

- `openshell settings get [name] [--global] [--json]`
- `openshell settings set [name] --key <key> --value <value> [--global] [--yes]`
- `openshell settings delete [name] --key <key> [--global] [--yes]`

Sandbox names default to the last-used sandbox. Global mutations prompt unless `--yes` is passed.

---

## Provider Commands

Provider types are defined by built-in and custom provider profiles. Use `openshell provider list-profiles` to discover the selected gateway's current inventory.

### `openshell provider create --name <NAME> --type <TYPE>`

Create a provider configuration.

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Provider name (required) |
| `--type <TYPE>` | Provider type (required) |
| `--from-existing` | Load credentials and config from local state |
| `--credential KEY[=VALUE]` | Credential pair. Bare `KEY` reads from env var. Repeatable. |
| `--from-gcloud-adc` | Load a compatible credential from gcloud Application Default Credentials |
| `--runtime-credentials` | Resolve required credentials at runtime in the gateway or sandbox |
| `--config KEY=VALUE` | Config key/value pair. Repeatable. |

Exactly one credential source is required. Credential-source flags conflict with one another.

### `openshell provider get <name>`

Show provider details (id, name, type, credential keys, config keys).

### `openshell provider list`

List providers in a table.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit <N>` | 100 | Max providers |
| `--offset <N>` | 0 | Pagination offset |
| `--names` | false | Print only names |
| `--output table|yaml|json` | `table` | Output format |

### `openshell provider update <name>`

Update an existing provider without changing its type.

| Flag | Description |
|------|-------------|
| `--from-existing` | Rediscover local credentials and config |
| `--credential KEY[=VALUE]` | Update a credential (repeatable) |
| `--config KEY=VALUE` | Update config (repeatable) |
| `--credential-expires-at KEY=TIMESTAMP` | Set or clear credential expiry; accepts epoch milliseconds or RFC3339, and `0` clears |

### `openshell provider delete <NAME>...`

Delete one or more providers by name.

### Provider profiles

- `openshell provider list-profiles [--output table|yaml|json]`
- `openshell provider profile export <id> [--output table|yaml|json]`
- `openshell provider profile import (--file <path>|--from <dir>)`
- `openshell provider profile update <id> --file <path>`
- `openshell provider profile lint (--file <path>|--from <dir>)`
- `openshell provider profile delete <id>`

### Provider credential refresh

- `openshell provider refresh status <name> [--credential-key <key>]`
- `openshell provider refresh rotate <name> --credential-key <key>`
- `openshell provider refresh delete <name> --credential-key <key>`

`provider refresh configure <name>` accepts:

| Flag | Description |
|------|-------------|
| `--credential-key <KEY>` | Injectable credential key (required) |
| `--strategy <STRATEGY>` | `oauth2-refresh-token`, `oauth2-client-credentials`, or `google-service-account-jwt` |
| `--material KEY=VALUE` | Non-secret refresh material (repeatable) |
| `--secret-material-env KEY[=ENVVAR]` | Secret refresh material read from the CLI environment (repeatable) |
| `--secret-material-key KEY` | Mark a supplied material key secret (repeatable) |
| `--credential-expires-at TIMESTAMP` | Current credential expiry in epoch milliseconds or RFC3339 |

---

## Inference Commands

### `openshell inference set`

Configure the gateway's user-facing `inference.local` route or the platform-only system route. Provider and model are required.

| Flag | Default | Description |
|------|---------|-------------|
| `--provider <NAME>` | -- | Provider record name (required) |
| `--model <ID>` | -- | Model identifier to use for generation requests (required) |
| `--system` | false | Configure the system inference route |
| `--no-verify` | false | Skip endpoint verification before saving |
| `--timeout <SECONDS>` | 0 | Request timeout; `0` uses the 60-second default |

### `openshell inference update`

Partially update the selected inference route.

| Flag | Default | Description |
|------|---------|-------------|
| `--provider <NAME>` | unchanged | Provider record name |
| `--model <ID>` | unchanged | Model identifier |
| `--system` | false | Target the system inference route |
| `--no-verify` | false | Skip endpoint verification before saving |
| `--timeout <SECONDS>` | unchanged | Request timeout; `0` uses the 60-second default |

### `openshell inference get`

Show both inference routes. `--system` shows only the system route.

---

## Other Commands

### `openshell term`

Launch the OpenShell interactive TUI. `--theme auto|dark|light` overrides `OPENSHELL_THEME`.

### `openshell completions <shell>`

Generate shell completion scripts. Supported shells: `bash`, `fish`, `zsh`, `powershell`.

### `openshell ssh-proxy`

SSH proxy used as a `ProxyCommand`. Not typically invoked directly.
