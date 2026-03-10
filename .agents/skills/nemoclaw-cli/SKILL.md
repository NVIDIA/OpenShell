---
name: openshell-cli
description: Guide agents through using the OpenShell CLI (openshell) for sandbox management, provider configuration, policy iteration, BYOC workflows, and inference routing. Covers basic through advanced multi-step workflows. Trigger keywords - openshell, sandbox create, sandbox connect, logs, provider create, policy set, policy get, image push, forward, port forward, BYOC, bring your own container, use openshell, run openshell, CLI usage, manage sandbox, manage provider, gateway start, gateway select.
---

# OpenShell CLI

Guide agents through using the `openshell` CLI for sandbox and platform management -- from basic operations to advanced multi-step workflows.

## Overview

The OpenShell CLI (`openshell`) is the primary interface for managing sandboxes, providers, policies, inference routes, and gateways. This skill teaches agents how to orchestrate CLI commands for common and complex workflows.

**Companion skill**: For creating or modifying sandbox policy YAML content (network rules, L7 inspection, access presets), use the `generate-sandbox-policy` skill. This skill covers the CLI *commands* for the policy lifecycle; `generate-sandbox-policy` covers policy *content authoring*.

**Self-teaching**: The CLI has comprehensive built-in help. When you encounter a command or option not covered in this skill, walk the help tree:

```bash
openshell --help                    # Top-level commands
openshell <group> --help            # Subcommands in a group
openshell <group> <cmd> --help      # Flags for a specific command
```

This is your primary fallback. Use it freely -- the CLI's help output is authoritative and always up-to-date.

## Prerequisites

- `openshell` is on the PATH (install via `cargo install --path crates/navigator-cli`)
- Docker is running (required for gateway operations and BYOC)
- For remote clusters: SSH access to the target host

## Command Reference

See [cli-reference.md](cli-reference.md) for the full command tree with all flags and options. Use it as a quick-reference to avoid round-tripping through `--help` for common commands.

---

## Workflow 1: Getting Started

Use this workflow when no cluster exists yet and the user wants to get a sandbox running for the first time.

### Step 1: Bootstrap a cluster

```bash
openshell gateway start
```

This provisions a local k3s cluster in Docker. The CLI will prompt interactively if a cluster already exists. The cluster is automatically set as the active gateway.

For remote deployment:

```bash
openshell gateway start --remote user@host --ssh-key ~/.ssh/id_rsa
```

### Step 2: Verify the cluster

```bash
openshell status
```

Confirm the cluster is reachable and shows a version.

### Step 3: Create a sandbox

The simplest way to get a sandbox running:

```bash
openshell sandbox create
```

This creates a sandbox with defaults and drops you into an interactive shell. The CLI auto-bootstraps a cluster if none exists.

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

Providers supply credentials to sandboxes (API keys, tokens, etc.). Manage them before creating sandboxes that need them.

Supported types: `claude`, `opencode`, `codex`, `generic`, `nvidia`, `gitlab`, `github`, `outlook`.

### Create a provider from local credentials

```bash
openshell provider create --name my-github --type github --from-existing
```

The `--from-existing` flag discovers credentials from local state (e.g., `gh auth` tokens, Claude config files).

### Create a provider with explicit credentials

```bash
openshell provider create --name my-api --type generic \
  --credential API_KEY=sk-abc123 \
  --config base_url=https://api.example.com
```

Bare `KEY` (without `=VALUE`) reads the value from the environment variable of that name:

```bash
openshell provider create --name my-api --type generic --credential API_KEY
```

### List, inspect, update, delete

```bash
openshell provider list
openshell provider get my-github
openshell provider update my-github --type github --from-existing
openshell provider delete my-github
```

---

## Workflow 3: Sandbox Lifecycle

### Create with options

```bash
openshell sandbox create \
  --name my-sandbox \
  --provider my-github \
  --provider my-claude \
  --policy ./my-policy.yaml \
  --upload .:/sandbox \
  -- claude
```

Key flags:
- `--provider`: Attach one or more providers (repeatable)
- `--policy`: Custom policy YAML (otherwise uses built-in default or `OPENSHELL_SANDBOX_POLICY` env var)
- `--upload <PATH>[:<DEST>]`: Upload local files into the sandbox (default dest: `/sandbox`)
- `--keep`: Keep sandbox alive after the command exits (useful for non-interactive commands)
- `--forward <PORT>`: Forward a local port (implies `--keep`)

### List and inspect sandboxes

```bash
openshell sandbox list
openshell sandbox get my-sandbox
```

### Connect to a running sandbox

```bash
openshell sandbox connect my-sandbox
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
```

---

## Workflow 4: Policy Iteration Loop

This is the most important multi-step workflow. It enables a tight feedback cycle where sandbox policy is refined based on observed activity.

**Key concept**: Policies have static fields (immutable after creation: `filesystem_policy`, `landlock`, `process`) and dynamic fields (hot-reloadable on a running sandbox: `network_policies`, `inference`). Only dynamic fields can be updated without recreating the sandbox.

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
openshell sandbox create --name dev --policy ./initial-policy.yaml --keep -- claude
```

Use `--keep` so the sandbox stays alive for iteration. The user can work in the sandbox via a separate shell.

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

The `--full` flag outputs valid YAML that can be directly re-submitted. This is the round-trip format.

### Step 4: Modify the policy

Edit `current-policy.yaml` to allow the blocked actions. **For policy content authoring, delegate to the `generate-sandbox-policy` skill.** That skill handles:
- Network endpoint rule structure
- L4 vs L7 policy decisions
- Access presets (`read-only`, `read-write`, `full`)
- TLS termination configuration
- Enforcement modes (`audit` vs `enforce`)
- Binary matching patterns

Only `network_policies` and `inference` sections can be modified at runtime. If `filesystem_policy`, `landlock`, or `process` need changes, the sandbox must be recreated.

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

---

## Workflow 5: BYOC (Bring Your Own Container)

Build a custom container image and run it as a sandbox.

### Step 1: Create a sandbox from a Dockerfile

```bash
openshell sandbox create --from ./Dockerfile --keep --name my-app
```

The `--from` flag accepts a Dockerfile path, a directory containing a Dockerfile, a full image reference (e.g. `myregistry.com/img:tag`), or a community sandbox name (e.g. `openclaw`).

When given a Dockerfile or directory, the image is built locally via Docker and imported directly into the cluster's containerd runtime. No external registry needed.

When `--from` is specified, the CLI:
- Clears default `run_as_user`/`run_as_group` (custom images may not have the `sandbox` user)
- Uses a supervisor bootstrap pattern (init container copies the sandbox supervisor into a shared volume)

### Step 2: Forward ports (if the container runs a service)

```bash
# Foreground (blocks)
openshell forward start 8080 my-app

# Background (returns immediately)
openshell forward start 8080 my-app -d
```

The service is now reachable at `localhost:8080`.

### Step 3: Manage port forwards

```bash
# List active forwards
openshell forward list

# Stop a forward
openshell forward stop 8080 my-app
```

### Step 4: Iterate

To update the container:

```bash
openshell sandbox delete my-app
openshell sandbox create --from ./Dockerfile --keep --name my-app --forward 8080
```

### Shortcut: Create with port forward in one command

```bash
openshell sandbox create --from ./Dockerfile --forward 8080 --keep -- ./start-server.sh
```

The `--forward` flag starts a background port forward before the command runs, so the service is reachable immediately.

### Limitations

- Distroless / `FROM scratch` images are not supported (the supervisor needs glibc, `/proc`, and a shell)
- Missing `iproute2` or required capabilities blocks startup in proxy mode

---

## Workflow 6: Agent-Assisted Sandbox Session

This workflow supports a human working in a sandbox while an agent monitors activity and refines the policy in parallel.

### Step 1: Create sandbox with providers and keep alive

```bash
openshell sandbox create \
  --name work-session \
  --provider github \
  --provider claude \
  --policy ./dev-policy.yaml \
  --keep
```

### Step 2: User connects in a separate shell

Tell the user to run:

```bash
openshell sandbox connect work-session
```

Or for VS Code:

```bash
openshell sandbox ssh-config work-session >> ~/.ssh/config
# Then connect via VS Code Remote-SSH to the host "work-session"
```

### Step 3: Agent monitors logs

While the user works, monitor the sandbox logs:

```bash
openshell logs work-session --tail --source sandbox --level warn
```

Watch for `deny` actions that indicate the user's work is being blocked by policy.

### Step 4: Agent refines policy

When denied actions are observed:

1. Pull current policy: `openshell policy get work-session --full > policy.yaml`
2. Modify the policy to allow the blocked actions (use `generate-sandbox-policy` skill for content)
3. Push the update: `openshell policy set work-session --policy policy.yaml --wait`
4. Verify: `openshell policy list work-session`

The user does not need to disconnect -- policy updates are hot-reloaded within ~30 seconds (or immediately when using `--wait`, which polls for confirmation).

### Step 5: Clean up when done

```bash
openshell sandbox delete work-session
```

---

## Workflow 7: Gateway Inference

Configure the gateway's managed inference route for `inference.local`.

### Set gateway inference

First ensure the provider record exists:

```bash
openshell provider list
```

Then point gateway inference at that provider and model:

```bash
openshell inference set \
  --provider nvidia \
  --model nvidia/nemotron-3-nano-30b-a3b
```

This updates the gateway-managed `inference.local` route. There is no per-route create/list/update/delete workflow for sandbox inference.

### Inspect current inference config

```bash
openshell inference get
```

### How sandboxes use it

- Agents send HTTPS requests to `inference.local`.
- The sandbox intercepts those requests locally and routes them through the cluster inference config.
- Sandbox policy is separate from cluster inference configuration.

---

## Workflow 8: Gateway Management

### List and switch gateways

```bash
openshell gateway select            # See all gateways (no args shows list)
openshell gateway select my-cluster # Switch active gateway
openshell status                    # Verify connectivity
```

### Lifecycle

```bash
openshell gateway start                                 # Start local cluster
openshell gateway stop                                  # Stop (preserves state)
openshell gateway start                                 # Restart (reuses state)
openshell gateway destroy                               # Destroy permanently
```

### Remote clusters

```bash
# Deploy to remote host
openshell gateway start --remote user@host --ssh-key ~/.ssh/id_rsa --name remote-cluster

# Set up kubectl access
openshell gateway tunnel --name remote-cluster

# Get cluster info
openshell gateway info --name remote-cluster
```

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
# Shows: create, get, list, delete, connect, upload, download, ssh-config, image

$ openshell sandbox upload --help
# Shows: positional arguments (name, path, dest), usage examples
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Deploy local cluster | `openshell gateway start` |
| Check cluster health | `openshell status` |
| List/switch gateways | `openshell gateway select [name]` |
| Create sandbox (interactive) | `openshell sandbox create` |
| Create sandbox with tool | `openshell sandbox create -- claude` |
| Create with custom policy | `openshell sandbox create --policy ./p.yaml --keep` |
| Connect to sandbox | `openshell sandbox connect <name>` |
| Stream live logs | `openshell logs <name> --tail` |
| Pull current policy | `openshell policy get <name> --full > p.yaml` |
| Push updated policy | `openshell policy set <name> --policy p.yaml --wait` |
| Policy revision history | `openshell policy list <name>` |
| Create sandbox from Dockerfile | `openshell sandbox create --from ./Dockerfile --keep` |
| Forward a port | `openshell forward start <port> <name> -d` |
| Upload files to sandbox | `openshell sandbox upload <name> <path>` |
| Download files from sandbox | `openshell sandbox download <name> <path>` |
| Create provider | `openshell provider create --name N --type T --from-existing` |
| List providers | `openshell provider list` |
| Configure gateway inference | `openshell inference set --provider P --model M` |
| View gateway inference | `openshell inference get` |
| Delete sandbox | `openshell sandbox delete <name>` |
| Destroy cluster | `openshell gateway destroy` |
| Self-teach any command | `openshell <group> <cmd> --help` |

## Companion Skills

| Skill | When to use |
|-------|------------|
| `generate-sandbox-policy` | Creating or modifying policy YAML content (network rules, L7 inspection, access presets, endpoint configuration) |
| `debug-navigator-cluster` | Diagnosing cluster startup or health failures |
| `tui-development` | Developing features for the OpenShell TUI (`openshell term`) |
