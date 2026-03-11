# OpenShell

[![GitHub](https://img.shields.io/badge/github-repo-green?logo=github)](https://github.com/NVIDIA/OpenShell)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](https://github.com/NVIDIA/OpenShell/blob/main/LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-openshell-orange?logo=pypi)](https://pypi.org/project/openshell/)

OpenShell is the safe, private runtime for autonomous AI agents. It provides sandboxed execution environments that protect your data, credentials, and infrastructure — governed by declarative YAML policies that prevent unauthorized file access, data exfiltration, and uncontrolled network activity.

## Quickstart

### Prerequisites

- **Docker** — Docker Desktop (or a Docker daemon) must be running.
- **Python 3.12+**
- [**uv**](https://docs.astral.sh/uv/) 0.9+

### Install

**From PyPI (recommended):**

```bash
uv pip install openshell
```

**From a pre-built binary:**

<!-- TODO: uncomment once release binaries are published -->
<!-- Download the latest release from https://github.com/NVIDIA/OpenShell/releases -->

```bash
curl -L https://github.com/NVIDIA/OpenShell/releases/latest/download/openshell-$(uname -s)-$(uname -m) -o openshell
chmod +x openshell
sudo mv openshell /usr/local/bin/
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
| Language   | `python` (3.12), `node` (22)                             |
| Developer  | `gh`, `git`, `vim`, `nano`                               |
| Networking | `ping`, `dig`, `nslookup`, `nc`, `traceroute`, `netstat` |

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
| [OpenCode](https://opencode.ai/) | Built-in | Add `opencode.ai` endpoint and OpenCode binary paths to the policy for full functionality. |
| [Codex](https://developers.openai.com/codex) | Built-in | Requires a custom policy with OpenAI endpoints and Codex binary paths. Requires `OPENAI_API_KEY`. |
| [OpenClaw](https://openclaw.ai/) | [Community](https://github.com/NVIDIA/OpenShell-Community) | Launch with `openshell sandbox create --from openclaw`. |

## How It Works

OpenShell runs as a [K3s](https://k3s.io/) Kubernetes cluster inside a Docker container. Each sandbox is an isolated pod with policy-enforced egress routing.

| Component | Role |
|---|---|
| **Gateway** | Control-plane API that coordinates sandbox lifecycle and acts as the auth boundary. |
| **Sandbox** | Isolated runtime with container supervision and policy-enforced egress routing. |
| **Policy Engine** | Enforces filesystem, network, and process constraints from application layer down to kernel. |
| **Privacy Router** | Privacy-aware LLM routing that keeps sensitive context on sandbox compute. |

Every outbound connection is intercepted: the policy engine either **allows** it (destination and binary match a policy block), **routes it for inference** (strips credentials, injects backend credentials, forwards to the managed model), or **denies** it (blocked and logged).

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

See the full [CLI reference](docs/reference/cli.md) for all commands, flags, and environment variables.

## Community Sandboxes and BYOC

Use `--from` to create sandboxes from the [OpenShell Community](https://github.com/NVIDIA/OpenShell-Community) catalog, a local directory, or a container image:

```bash
openshell sandbox create --from openclaw           # community catalog
openshell sandbox create --from ./my-sandbox-dir   # local Dockerfile
openshell sandbox create --from registry.io/img:v1 # container image
```

See the [community sandboxes](docs/sandboxes/community-sandboxes.md) catalog and the [BYOC example](examples/bring-your-own-container) for details.

## Learn More

- [Full Documentation](docs/) — overview, architecture, tutorials, and reference
- [Quickstart](docs/get-started/quickstart.md) — detailed install and first sandbox walkthrough
- [GitHub Sandbox Tutorial](docs/tutorials/github-sandbox.md) — end-to-end scoped GitHub repo access
- [Architecture](architecture/) — detailed architecture docs and design decisions
- [Support Matrix](docs/reference/support-matrix.md) — platforms, versions, and kernel requirements
