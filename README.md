# OpenShell

[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](https://github.com/NVIDIA/OpenShell/blob/main/LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-openshell-orange?logo=pypi)](https://pypi.org/project/openshell/)

OpenShell is the safe, private runtime for autonomous AI agents. It provides sandboxed execution environments that protect your data, credentials, and infrastructure — governed by declarative YAML policies that prevent unauthorized file access, data exfiltration, and uncontrolled network activity.

## Quickstart

Want to run on cloud compute? [Launch on Brev](https://brev.nvidia.com/launchable/deploy/now?launchableID=env-3Ap3tL55zq4a8kew1AuW0FpSLsg). Otherwise, follow the steps below to run locally.

### Prerequisites

- **Docker** — Docker Desktop (or a Docker daemon) must be running.

### Install

**Binary (recommended):**

```bash
curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
```

The install script auto-detects your platform (Linux x86_64, Linux aarch64, macOS Apple Silicon) and places the `openshell` binary in `/usr/local/bin`. See the [releases page](https://github.com/NVIDIA/OpenShell/releases) for manual download options.

**From PyPI (requires [uv](https://docs.astral.sh/uv/)):**

```bash
uv tool install -U openshell
```

### Create a sandbox

```bash
openshell sandbox create -- claude  # or opencode, codex, --from openclaw
```

A gateway cluster is created automatically on first use. To deploy on a remote host instead, use `openshell gateway start --remote user@host`.

The sandbox container includes the following tools by default:

| Category   | Tools                                                    |
| ---------- | -------------------------------------------------------- |
| Agent      | `claude`, `opencode`, `codex`                            |
| Language   | `python` (3.13), `node` (22)                             |
| Developer  | `gh`, `git`, `vim`, `nano`                               |
| Networking | `ping`, `dig`, `nslookup`, `nc`, `traceroute`, `netstat` |

### See network policy in action

Every sandbox starts with **minimal outbound access**. You open additional access with a short YAML policy that the proxy enforces at the HTTP method and path level, without restarting anything.

```bash
# 1. Create a sandbox (starts with minimal outbound access)
openshell sandbox create --name demo --keep --no-auto-providers

# 2. Inside the sandbox — blocked
sandbox$ curl -sS https://api.github.com/zen
curl: (56) Received HTTP code 403 from proxy after CONNECT

# 3. Back on the host — apply a read-only GitHub API policy
sandbox$ exit
openshell policy set demo --policy examples/sandbox-policy-quickstart/policy.yaml --wait

# 4. Reconnect — GET allowed, POST blocked by L7
openshell sandbox connect demo
sandbox$ curl -sS https://api.github.com/zen
Anything added dilutes everything else.

sandbox$ curl -sS -X POST https://api.github.com/repos/octocat/hello-world/issues -d '{"title":"oops"}'
{"error":"policy_denied","detail":"POST /repos/octocat/hello-world/issues not permitted by policy"}
```

See the [full walkthrough](examples/sandbox-policy-quickstart/) or run the automated demo:

```bash
bash examples/sandbox-policy-quickstart/demo.sh
```

## Protection Layers

OpenShell applies defense in depth across four policy domains:

| Layer      | What it protects                                    | When it applies             |
| ---------- | --------------------------------------------------- | --------------------------- |
| Filesystem | Prevents reads/writes outside allowed paths.        | Locked at sandbox creation. |
| Network    | Blocks unauthorized outbound connections.            | Hot-reloadable at runtime.  |
| Process    | Blocks privilege escalation and dangerous syscalls.  | Locked at sandbox creation. |
| Inference  | Reroutes model API calls to controlled backends.     | Hot-reloadable at runtime.  |

Policies are declarative YAML files. Static sections (filesystem, process) are locked at creation; dynamic sections (network, inference) can be hot-reloaded on a running sandbox with `openshell policy set`.

## Supported Agents

| Agent | Source | Notes |
|---|---|---|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | Built-in | Works out of the box. Requires `ANTHROPIC_API_KEY`. |
| [OpenCode](https://opencode.ai/) | Built-in | Works out of the box. Requires `OPENAI_API_KEY` or `OPENROUTER_API_KEY`. |
| [Codex](https://developers.openai.com/codex) | Built-in | Works out of the box. Requires `OPENAI_API_KEY`. |
| [OpenClaw](https://openclaw.ai/) | [Community](https://github.com/NVIDIA/OpenShell-Community) | Launch with `openshell sandbox create --from openclaw`. |

## How It Works

OpenShell isolates each sandbox in its own container with policy-enforced egress routing. A lightweight gateway coordinates sandbox lifecycle, and every outbound connection is intercepted by the policy engine, which does one of three things:

- **Allows** — the destination and binary match a policy block.
- **Routes for inference** — strips caller credentials, injects backend credentials, and forwards to the managed model.
- **Denies** — blocks the request and logs it.

Under the hood, the gateway runs as a [K3s](https://k3s.io/) Kubernetes cluster inside Docker — no separate K8s install required.

| Component | Role |
|---|---|
| **Gateway** | Control-plane API that coordinates sandbox lifecycle and acts as the auth boundary. |
| **Sandbox** | Isolated runtime with container supervision and policy-enforced egress routing. |
| **Policy Engine** | Enforces filesystem, network, and process constraints from application layer down to kernel. |
| **Privacy Router** | Privacy-aware LLM routing that keeps sensitive context on sandbox compute. |

## Key Commands

| Command | Description |
|---|---|
| `openshell sandbox create -- <agent>` | Create a sandbox and launch an agent. |
| `openshell sandbox connect [name]` | SSH into a running sandbox. |
| `openshell sandbox list` | List all sandboxes. |
| `openshell sandbox delete <name>` | Delete a sandbox. |
| `openshell provider create --type claude --from-existing` | Create a credential provider from env vars. |
| `openshell policy set <name> --policy file.yaml` | Apply or update a policy on a running sandbox. |
| `openshell policy get <name>` | Show the active policy. |
| `openshell inference set --provider <p> --model <m>` | Configure the `inference.local` endpoint. |
| `openshell logs [name] --tail` | Stream sandbox logs. |
| `openshell term` | Launch the real-time terminal UI for debugging. |

See the full [CLI reference](https://github.com/NVIDIA/OpenShell/blob/main/docs/reference/cli.md) for all commands, flags, and environment variables.

## Terminal UI

OpenShell includes a real-time terminal dashboard for monitoring gateways, sandboxes, and providers — inspired by [k9s](https://k9scli.io/).

```bash
openshell term
```

<p align="center">
  <img src="docs/assets/openshell-terminal.png" alt="OpenShell Terminal UI">
</p>

The TUI gives you a live, keyboard-driven view of your cluster. Navigate with `Tab` to switch panels, `j`/`k` to move through lists, `Enter` to select, and `:` for command mode. Cluster health and sandbox status auto-refresh every two seconds.

## Community Sandboxes and BYOC

Use `--from` to create sandboxes from the [OpenShell Community](https://github.com/NVIDIA/OpenShell-Community) catalog, a local directory, or a container image:

```bash
openshell sandbox create --from openclaw           # community catalog
openshell sandbox create --from ./my-sandbox-dir   # local Dockerfile
openshell sandbox create --from registry.io/img:v1 # container image
```

See the [community sandboxes](https://github.com/NVIDIA/OpenShell/blob/main/docs/sandboxes/community-sandboxes.md) catalog and the [BYOC example](https://github.com/NVIDIA/OpenShell/tree/main/examples/bring-your-own-container) for details.

## Learn More

- [Full Documentation](https://github.com/NVIDIA/OpenShell/tree/main/docs) — overview, architecture, tutorials, and reference
- [Quickstart](https://github.com/NVIDIA/OpenShell/blob/main/docs/get-started/quickstart.md) — detailed install and first sandbox walkthrough
- [GitHub Sandbox Tutorial](https://github.com/NVIDIA/OpenShell/blob/main/docs/tutorials/github-sandbox.md) — end-to-end scoped GitHub repo access
- [Architecture](https://github.com/NVIDIA/OpenShell/tree/main/architecture) — detailed architecture docs and design decisions
- [Support Matrix](https://github.com/NVIDIA/OpenShell/blob/main/docs/reference/support-matrix.md) — platforms, versions, and kernel requirements
- [Brev Launchable](https://brev.nvidia.com/launchable/deploy/now?launchableID=env-3Ap3tL55zq4a8kew1AuW0FpSLsg) — try OpenShell on cloud compute without local setup

## Contributing

See [CONTRIBUTING.md](https://github.com/NVIDIA/OpenShell/blob/main/CONTRIBUTING.md) for building from source and contributing to OpenShell.

## License

This project is licensed under the [Apache License 2.0](https://github.com/NVIDIA/OpenShell/blob/main/LICENSE).
