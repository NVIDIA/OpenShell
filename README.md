# Navigator 🗺️

Navigator is the runtime environment for autonomous agents—the "Matrix" where they live, work, and verify.

While coding tools like Claude help agents write logic, Navigator provides the infrastructure to run it, offering a programmable factory where agents can spin up physics simulations to master tasks, generate synthetic data to fix edge cases, and safely iterate through thousands of failures in isolated sandboxes.

It transforms the data center from a static deployment target into a continuous verification engine, allowing agents to autonomously build and operate complex systems—from physical robotics to self-healing infrastructure—without needing a human to manage the infrastructure.

## Quickstart

### Prerequisites

- **Docker** — Docker Desktop (or a Docker daemon) must be running.
- **Python 3.12+** and [uv](https://docs.astral.sh/uv/)

### Install

```bash
uv pip install nemoclaw --upgrade --pre --index-url https://urm.nvidia.com/artifactory/api/pypi/nv-shared-pypi/simple
```

The `navigator` binary is installed into your Python environment. Use `uv run navigator` to invoke it, or activate your venv first (`source .venv/bin/activate`).

### Create a sandbox

```bash
uv run navigator sandbox create -- claude  # or opencode or codex
```

If you want to run a sandbox on a remote machine, pass `--remote [remote-ssh-host]`. This will start a sandbox on the remote host.

The sandbox container includes a minimal networking toolset by default: `ping`, `dig`, `nslookup`, `nc`, `traceroute`, and `netstat`.

It also includes common coding harnesses such as: `opencode`, `claude`, and `codex`.

## Developing

See `CONTRIBUTING.md` for building from source and contributing to Navigator.

## Architecture

See `architecture/` for detailed architecture docs and design decisions.
