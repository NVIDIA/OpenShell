---
name: openshell-cli
description: Guide agents through using the OpenShell CLI (openshell) for sandbox management, gateway registration, provider configuration and refresh, policy iteration, settings, service exposure, BYOC workflows, and inference routing. Covers basic through advanced multi-step workflows. Trigger keywords - openshell, sandbox create, sandbox exec, sandbox connect, logs, provider create, provider profile, provider refresh, policy set, policy get, settings, service expose, forward, port forward, BYOC, bring your own container, inference, use openshell, run openshell, CLI usage, manage sandbox, manage provider, gateway add, gateway select.
---

# OpenShell CLI

Guide agents through using the `openshell` CLI for sandbox and platform management -- from basic operations to advanced multi-step workflows.

## Overview

The OpenShell CLI (`openshell`) is the primary interface for managing sandboxes, providers, policies, settings, exposed services, inference routes, and gateway registrations. Gateway service lifecycle is handled outside the CLI by packages, systemd, Helm, or development tasks. This skill teaches agents how to orchestrate CLI commands for common and complex workflows.

**Companion skill**: For creating or modifying sandbox policy YAML content (network rules, L7 inspection, access presets), use the `generate-sandbox-policy` skill. This skill covers the CLI *commands* for the policy lifecycle; `generate-sandbox-policy` covers policy *content authoring*.

**Self-teaching**: The CLI has comprehensive built-in help. When you encounter a command or option not covered in this skill, walk the help tree:

```bash
openshell --help                    # Top-level commands
openshell <group> --help            # Subcommands in a group
openshell <group> <cmd> --help      # Flags for a specific command
```

This is your primary fallback. Use it freely -- the CLI's help output is authoritative and always up-to-date.

## Prerequisites

- `openshell` is on the PATH (install via `cargo install --path crates/openshell-cli`)
- A reachable OpenShell gateway backed by Docker, Podman, Kubernetes, or the experimental VM driver
- Docker is running only when using BYOC local builds or Docker-backed development workflows
- For Kubernetes deployments: `kubectl` and Helm access to the target cluster

## Command Reference

See [cli-reference.md](cli-reference.md) for the current command tree and commonly used flags. Use it as a quick-reference, then confirm uncommon or security-sensitive options with `--help`.

---

## Workflow 1: Getting Started

Use this workflow when the user has a gateway endpoint and wants to get a sandbox running for the first time.

### Step 1: Register a gateway

```bash
openshell gateway add http://127.0.0.1:8080 --local --name local
```

Use an `http://` endpoint only for trusted local port-forwarding or a protected private path. For a gateway behind an authenticated reverse proxy, register its HTTPS endpoint with `openshell gateway add https://gateway.example.com`.

### Step 2: Verify the gateway

```bash
openshell status
```

Confirm the gateway is reachable and shows a version.

### Step 3: Create a sandbox

The simplest way to get a sandbox running:

```bash
openshell sandbox create
```

This creates a sandbox with defaults and drops you into an interactive shell.

When supplying `--name`, use a portable DNS-1123 label: at most 63 lowercase alphanumeric or `-` characters, beginning and ending with an alphanumeric character. The Kubernetes driver rejects uppercase letters, underscores, dots, and other names that cannot become Kubernetes resource labels.

**Shortcut for known tools**: When the trailing command is a recognized tool, the CLI auto-creates the required provider from local credentials:

```bash
openshell sandbox create -- claude        # Auto-creates claude provider
openshell sandbox create -- codex         # Auto-creates codex provider
```

The agent will be prompted interactively if credentials are missing.

### Step 4: Exit and clean up

Exit the sandbox shell (`exit` or Ctrl-D), then:

```bash
openshell sandbox delete <name>
```

---

## Workflow 2: Provider Management

Providers supply credentials and provider-specific configuration to sandboxes. Provider types come from built-in and custom profiles; do not rely on a hard-coded type list. Discover the profiles available on the selected gateway:

```bash
openshell provider list-profiles
openshell provider list-profiles --output json
```

### Create a provider from local credentials

```bash
openshell provider create --name my-github --type github --from-existing
```

The `--from-existing` flag discovers credentials from local state (e.g., `gh auth` tokens, Claude config files).

### Create a provider with explicit credentials

```bash
openshell provider create --name my-api --type generic \
  --credential API_KEY \
  --config base_url=https://api.example.com
```

Bare `KEY` reads the value from the environment variable of that name and avoids placing the secret in shell history. Use `KEY=VALUE` only when the user explicitly accepts that exposure.

Other credential sources are `--from-gcloud-adc` for compatible profiles and `--runtime-credentials` when the gateway or sandbox resolves the required credentials at runtime.

Profile-backed provider policy and composition are controlled by the gateway-global `providers_v2_enabled` setting:

```bash
openshell settings get --global
openshell settings set --global --key providers_v2_enabled --value true
```

### Inspect and manage provider profiles

```bash
openshell provider profile export github --output yaml
openshell provider profile lint --file ./my-profile.yaml
openshell provider profile import --file ./my-profile.yaml
```

### List, inspect, update, delete

```bash
openshell provider list
openshell provider list --output json
openshell provider get my-github
openshell provider update my-github --from-existing
openshell provider delete my-github
```

`provider update` does not take `--type`. It updates credentials, config, or credential expiry on the existing provider.

### Configure credential refresh

Use refresh commands only when the provider profile and gateway support refreshable credentials:

```bash
openshell provider refresh status my-outlook
openshell provider refresh configure my-outlook \
  --credential-key MS_GRAPH_ACCESS_TOKEN \
  --strategy oauth2-refresh-token \
  --secret-material-env REFRESH_TOKEN=MS_GRAPH_REFRESH_TOKEN \
  --credential-expires-at 2026-07-16T00:00:00Z
openshell provider refresh rotate my-outlook --credential-key MS_GRAPH_ACCESS_TOKEN
```

Prefer `--secret-material-env KEY[=ENVVAR]` for secret refresh material. `--material KEY=VALUE` is for non-secret material; `--secret-material-key` marks supplied material keys as secret.

---

## Workflow 3: Sandbox Lifecycle

### Create with options

```bash
openshell sandbox create \
  --name my-sandbox \
  --provider my-github \
  --provider my-claude \
  --policy ./my-policy.yaml \
  --upload .:/workspace \
  --label team=agents \
  -- claude
```

Key flags:
- `--provider`: Attach one or more providers (repeatable)
- `--policy`: Custom policy YAML (otherwise uses built-in default or `OPENSHELL_SANDBOX_POLICY` env var)
- `--gpu [COUNT]`: Request the driver's default GPU selection or a specific GPU count
- `--cpu`, `--memory`: Set per-sandbox compute sizing. Docker/Podman apply limits; Kubernetes applies matching requests and limits.
- `--driver-config-json`: Pass experimental driver-specific sandbox configuration
- `--label KEY=VALUE`: Add labels for later selection (repeatable)
- `--env KEY=VALUE`: Inject sandbox environment variables (repeatable)
- `--approval-mode manual|auto`: Control handling of agent-authored policy proposals; `manual` is the default
- `--upload <PATH>[:<DEST>]`: Upload local files into the container working directory or an explicit destination
- `--no-git-ignore`: Disable `.gitignore` filtering for uploads
- `--no-keep`: Delete the sandbox after the initial command or shell exits
- `--forward [BIND_ADDRESS:]PORT`: Forward a local port and keep the sandbox alive
- `--editor vscode|cursor`: Open a remote editor after creation and keep the sandbox alive

### List and inspect sandboxes

```bash
openshell sandbox list
openshell sandbox list --selector team=agents --output json
openshell sandbox get my-sandbox
```

Most commands with an optional sandbox name use the last-used sandbox. Pass an explicit name in automation.

### Connect to a running sandbox

```bash
openshell sandbox connect my-sandbox
openshell sandbox connect my-sandbox --editor vscode
```

Opens an interactive SSH shell. To configure VS Code Remote-SSH:

```bash
openshell sandbox ssh-config my-sandbox >> ~/.ssh/config
```

### Upload and download files

```bash
# Upload local files to sandbox
openshell sandbox upload my-sandbox ./src /sandbox/src

# Download files from sandbox
openshell sandbox download my-sandbox /sandbox/output ./local-output
```

Uploads honor `.gitignore` by default. Add `--no-git-ignore` only when ignored files are intentionally in scope.

Uploads preserve symlinks, including dangling symlinks, instead of dereferencing their targets. A symlink source bypasses Git-aware filtering so the link itself is archived.

### Execute a non-interactive command

```bash
openshell sandbox exec --name my-sandbox --workdir /workspace -- ls -la
openshell sandbox exec --name my-sandbox --env MODE=test -- cargo test
```

`sandbox exec` streams output and exits with the remote command's exit code. Use `sandbox connect` for an interactive shell.

### Change attached providers

```bash
openshell sandbox provider list my-sandbox
openshell sandbox provider attach my-sandbox my-github
openshell sandbox provider detach my-sandbox my-github
```

### View logs

```bash
# Recent logs
openshell logs my-sandbox

# Stream live logs
openshell logs my-sandbox --tail

# Filter by source and level
openshell logs my-sandbox --tail --source sandbox --level warn

# Logs from the last 5 minutes
openshell logs my-sandbox --since 5m
```

### Delete sandboxes

```bash
openshell sandbox delete my-sandbox
openshell sandbox delete sandbox-1 sandbox-2 sandbox-3   # Multiple at once
openshell sandbox delete --all
```

---

## Workflow 4: Policy Iteration Loop

This is the most important multi-step workflow. It enables a tight feedback cycle where sandbox policy is refined based on observed activity.

**Key concept**: Policies have static fields (immutable after creation: `filesystem_policy`, `landlock`, `process`) and two dynamic fields: `network_policies` and `network_middlewares`. Both dynamic fields can be updated without recreating the sandbox.

```
Create sandbox with initial policy
        │
        ▼
   Monitor logs ◄──────────────────┐
        │                          │
        ▼                          │
  Observe denied actions           │
        │                          │
        ▼                          │
  Pull current policy              │
        │                          │
        ▼                          │
  Modify policy YAML               │
  (use generate-sandbox-policy)    │
        │                          │
        ▼                          │
  Push updated policy              │
        │                          │
        ▼                          │
  Verify reload succeeded ─────────┘
```

### Step 1: Create sandbox with initial policy

```bash
openshell sandbox create --name dev --policy ./initial-policy.yaml -- claude
```

Sandboxes stay alive by default for iteration. Add `--no-keep` only when the sandbox should be deleted automatically after the initial session.

### Step 2: Monitor logs for denied actions

In a separate terminal or as the agent:

```bash
openshell logs dev --tail --source sandbox
```

Look for log lines with `action: deny` -- these indicate blocked network requests. The logs include:
- **Destination host and port** (what was blocked)
- **Binary path** (which process attempted the connection)
- **Deny reason** (why it was blocked)

### Step 3: Pull the current policy

```bash
openshell policy get dev --full > current-policy.yaml
```

The `--full` flag includes the effective policy, including provider-composed entries. Use `--base` instead when the editable base policy is needed without provider-composed entries. Before resubmitting a `--full` result, review composed entries and prefer incremental updates or the base policy when appropriate.

### Step 4: Modify the policy

Edit `current-policy.yaml` to allow the blocked actions. **For policy content authoring, delegate to the `generate-sandbox-policy` skill.** That skill handles:
- Network endpoint rule structure
- L4 vs REST, WebSocket, JSON-RPC, MCP, and SQL L7 policy decisions
- Access presets (`read-only`, `read-write`, `full`)
- TLS termination configuration
- Enforcement modes (`audit` vs `enforce`)
- Binary matching patterns
- Ordered `network_middlewares`, host selection, and `fail_open` or `fail_closed` behavior

`network_policies` and `network_middlewares` can be modified at runtime. If `filesystem_policy`, `landlock`, or `process` need changes, the sandbox must be recreated. Built-in middleware such as `openshell/regex` needs no gateway registration. An operator-run middleware must already be registered under `[[openshell.supervisor.middleware]]`; changing that static registration requires a gateway restart.

### Step 5: Push the updated policy

```bash
openshell policy set dev --policy current-policy.yaml --wait
```

The `--wait` flag blocks until the sandbox confirms the policy is loaded (polls every second). Exit codes:
- **0**: Policy loaded successfully
- **1**: Policy load failed
- **124**: Timeout (default 60 seconds)

### Step 6: Verify the update

```bash
openshell policy list dev
```

Check that the latest revision shows status `loaded`. If `failed`, check the error column for details.

### Step 7: Repeat

Return to Step 2. Continue monitoring logs and refining the policy until all required actions are allowed and no unnecessary permissions exist.

### Policy revision history

View all revisions to understand how the policy evolved:

```bash
openshell policy list dev --limit 50
```

Fetch a specific historical revision:

```bash
openshell policy get dev --rev 3 --full
```

Gateway-global policy commands use `--global` and require confirmation unless `--yes` is supplied:

```bash
openshell policy get --global --full
openshell policy set --global --policy ./global-policy.yaml
openshell policy list --global
openshell policy delete --global
```

Avoid `--yes` during interactive work. A global policy locks policy control for all sandboxes on the gateway.

### Review agent-authored rule proposals

Sandboxes created with `--approval-mode manual` place every proposal in the review inbox. `auto` approves only proposals with an empty prover delta; findings still require review.

```bash
openshell rule get dev --status pending
openshell rule approve dev --chunk-id <chunk-id>
openshell rule reject dev --chunk-id <chunk-id> --reason "too broad"
openshell rule history dev
```

Review the proposed scope and prover findings before approval. Treat `rule approve-all --include-security-flagged` as a high-risk bulk action.

---

## Workflow 5: BYOC (Bring Your Own Container)

Build a custom container image and run it as a sandbox.

### Create a sandbox from a Dockerfile

```bash
openshell sandbox create --from ./Dockerfile --name my-app
```

The `--from` flag accepts a Dockerfile path, a directory containing a Dockerfile, a full image reference such as `myregistry.com/img:tag`, or a community sandbox name such as `ollama`.

Local Dockerfile and directory builds require a local gateway because the CLI builds through the local Docker daemon. Use a registry image reference for remote gateways. Bare community names resolve under `ghcr.io/nvidia/openshell-community/sandboxes` unless `OPENSHELL_COMMUNITY_REGISTRY` overrides the prefix.

### Forward ports

```bash
# Foreground (blocks)
openshell forward start 8080 my-app

# Background (returns immediately)
openshell forward start 8080 my-app -d
```

The service is now reachable at `localhost:8080`.

Manage or iterate on the sandbox:

```bash
openshell forward list
openshell forward stop 8080 my-app
openshell sandbox delete my-app
openshell sandbox create --from ./Dockerfile --name my-app --forward 8080
```

Create and forward in one command:

```bash
openshell sandbox create --from ./Dockerfile --forward 8080 -- ./start-server.sh
```

The `--forward` flag starts a background port forward before the command runs.

## Workflow 6: Agent-Assisted Sandbox Session

Support a human working in a sandbox while an agent monitors activity and refines the policy in parallel.

Create the sandbox and keep it alive:

```bash
openshell sandbox create \
  --name work-session \
  --provider github \
  --provider claude \
  --policy ./dev-policy.yaml
```

Tell the user to connect in another shell:

```bash
openshell sandbox connect work-session
openshell sandbox connect work-session --editor vscode
```

Monitor denied activity:

```bash
openshell logs work-session --tail --source sandbox --level warn
```

When denied actions appear:

1. Prefer incremental updates for additive network changes:
   `openshell policy update work-session --add-endpoint api.github.com:443:read-only:rest:enforce --binary /usr/bin/gh --wait`
   `openshell policy update work-session --add-allow 'api.github.com:443:POST:/repos/*/issues' --wait`
2. Use full YAML replacement for broad changes or non-network fields:
   `openshell policy get work-session --full > policy.yaml`
   Modify the policy with the `generate-sandbox-policy` skill.
   `openshell policy set work-session --policy policy.yaml --wait`
3. Verify with `openshell policy list work-session`.

The user does not need to disconnect. Policy updates are hot-reloaded; `--wait` blocks until the sandbox confirms the revision or the timeout expires. Delete the sandbox when the session ends:

```bash
openshell sandbox delete work-session
```

## Workflow 7: Managed Inference

Configure the user-facing `inference.local` route or the system inference route used by platform functions.

Ensure the provider exists, then set the route:

```bash
openshell provider list
openshell inference set \
  --provider nvidia \
  --model nvidia/nemotron-3-nano-30b-a3b
```

This updates the managed `inference.local` route. Endpoint verification runs before the route is saved. Use `--no-verify` only when verification is intentionally impossible, and use `--timeout SECONDS` to configure the request timeout. Add `--system` to `set` or `update` for the platform-only system route.

Inspect both configurations:

```bash
openshell inference get
openshell inference get --system
```

Agents send HTTPS requests to `inference.local`; the sandbox intercepts them and routes them through the configured inference route. Sandbox policy remains separate from inference route configuration.

## Workflow 8: Gateway Management

List, switch, and verify gateways:

```bash
openshell gateway select
openshell gateway list --output json
openshell gateway select production
openshell gateway info --name production
openshell status
```

Register or remove gateways:

```bash
openshell gateway add http://127.0.0.1:8080 --local --name local
openshell gateway add https://gateway.example.com --name production
openshell gateway remove local
```

`https://` registrations default to edge authentication. Use `gateway login` and `gateway logout` to refresh or clear stored authentication. For an OIDC gateway, supply `--oidc-issuer` and, when needed, `--oidc-client-id`, `--oidc-audience`, and `--oidc-scopes`. For remote mTLS gateways, use `--remote USER@HOST` or an `ssh://` endpoint.

For one-off automation, `--gateway-endpoint URL` connects directly without stored metadata. Limit `--gateway-insecure` to explicitly trusted development endpoints.

Inspect a Kubernetes deployment:

```bash
helm -n openshell status openshell
kubectl -n openshell get deployment,statefulset,pods,svc
kubectl -n openshell logs deployment/openshell -c openshell-gateway --tail=100
kubectl -n openshell logs statefulset/openshell -c openshell-gateway --tail=100
```

For Docker, Podman, and VM-backed gateways, inspect the gateway process or container logs and the selected runtime directly.

## Workflow 9: Settings Management

Manage sandbox-scoped or gateway-global settings:

```bash
openshell settings get work-session
openshell settings set work-session --key ocsf_json_enabled --value true
openshell settings delete work-session --key ocsf_json_enabled

openshell settings get --global --json
openshell settings set --global --key providers_v2_enabled --value true
```

Global mutations prompt for confirmation. Use `--yes` only in reviewed automation.

## Workflow 10: Service Access

Use `forward` for local access and `service` for a gateway-managed HTTP endpoint:

```bash
# SSH-based same-port forwarding; optional bind address is accepted.
openshell forward start 127.0.0.1:8080 my-app -d

# gRPC relay to a loopback TCP service, with an optional dynamic local port.
openshell forward service my-app --target-port 8000 --local 127.0.0.1:0

# Expose and manage an HTTP service through the gateway.
openshell service expose my-app 8080 web
openshell service list my-app
openshell service get my-app web
openshell service delete my-app web
```

Prefer loopback binds unless the user explicitly needs LAN-visible local access.

---

## Self-Teaching via `--help`

When you encounter a command or option not covered in this skill:

1. **Start broad**: `openshell --help` to see all command groups.
2. **Narrow down**: `openshell <group> --help` to see subcommands (e.g., `openshell sandbox --help`).
3. **Get specific**: `openshell <group> <cmd> --help` for flags and usage (e.g., `openshell sandbox create --help`).

The CLI help is always authoritative. If the help output contradicts this skill, follow the help output -- the CLI may have been updated since this skill was written.

### Example: discovering an unfamiliar command

```bash
$ openshell sandbox --help
# Shows: create, get, list, delete, exec, connect, upload, download, ssh-config, provider

$ openshell sandbox upload --help
# Shows: positional arguments (name, path, dest), usage examples
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Register local port-forwarded gateway | `openshell gateway add http://127.0.0.1:8080 --local --name local` |
| Check gateway health | `openshell status` |
| List/switch gateways | `openshell gateway select [name]` |
| Connect directly to a gateway | `openshell --gateway-endpoint <url> status` |
| Create sandbox (interactive) | `openshell sandbox create` |
| Create sandbox with tool | `openshell sandbox create -- claude` |
| Create sandbox with GPUs | `openshell sandbox create --gpu 1` |
| Create with custom policy | `openshell sandbox create --policy ./p.yaml` |
| Connect to sandbox | `openshell sandbox connect <name>` |
| Execute in sandbox | `openshell sandbox exec --name <name> -- <command>` |
| Stream live logs | `openshell logs <name> --tail` |
| Incremental policy update | `openshell policy update <name> --add-endpoint host:443:read-only:rest:enforce --binary /usr/bin/curl --wait` |
| Pull current policy | `openshell policy get <name> --full > p.yaml` |
| Push updated policy | `openshell policy set <name> --policy p.yaml --wait` |
| Policy revision history | `openshell policy list <name>` |
| View global policy | `openshell policy get --global --full` |
| Review proposed rules | `openshell rule get <name> --status pending` |
| Create sandbox from Dockerfile | `openshell sandbox create --from ./Dockerfile` |
| Forward a port | `openshell forward start <port> <name> -d` |
| Expose an HTTP service | `openshell service expose <name> <port> [service]` |
| Upload files to sandbox | `openshell sandbox upload <name> <path>` |
| Download files from sandbox | `openshell sandbox download <name> <path>` |
| Create provider | `openshell provider create --name N --type T --from-existing` |
| List providers | `openshell provider list` |
| Discover provider profiles | `openshell provider list-profiles` |
| List attached providers | `openshell sandbox provider list <name>` |
| View settings | `openshell settings get [name]` |
| Configure managed inference | `openshell inference set --provider P --model M` |
| View managed inference | `openshell inference get` |
| Delete sandbox | `openshell sandbox delete <name>` |
| Remove gateway registration | `openshell gateway remove <name>` |
| Self-teach any command | `openshell <group> <cmd> --help` |

## Companion Skills

| Skill | When to use |
|-------|------------|
| `generate-sandbox-policy` | Creating or modifying policy YAML content (network rules, L7 inspection, access presets, endpoint configuration, and network middleware) |
| `debug-openshell-cluster` | Diagnosing gateway deployment, runtime, or health failures |
| `debug-inference` | Diagnosing `inference.local`, host-backed local inference, and provider base URL issues |
| `tui-development` | Developing features for the OpenShell TUI (`openshell term`) |
