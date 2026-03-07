# NemoClaw 

NemoClaw is the runtime environment for autonomous agents—the "Matrix" where they live, work, and verify.

While coding tools like Claude help agents write logic, NemoClaw provides the infrastructure to run it, offering a programmable factory where agents can spin up physics simulations to master tasks, generate synthetic data to fix edge cases, and safely iterate through thousands of failures in isolated sandboxes.

It transforms the data center from a static deployment target into a continuous verification engine, allowing agents to autonomously build and operate complex systems—from physical robotics to self-healing infrastructure—without needing a human to manage the infrastructure.

## Quickstart

### Prerequisites

- **Docker** — Docker Desktop (or a Docker daemon) must be running.
- **Python 3.12+**
- [**uv**](https://docs.astral.sh/uv/) 0.9+

### Install

```bash
uv pip install nemoclaw \
  --upgrade \
  --pre \
  --index-url https://urm.nvidia.com/artifactory/api/pypi/nv-shared-pypi/simple
```

The `nemoclaw` binary is installed into your Python environment. Use `uv run nemoclaw` to invoke it, or activate your venv first with `source .venv/bin/activate`.

### Create a sandbox

To install a Openclaw cluster and start a sandbox

```bash
nemoclaw sandbox create -- claude  # or opencode or codex
```

To run a sandbox on a remote machine, pass `--remote [remote-ssh-host]`.

For more information see `nemoclaw sandbox create --help`.

The sandbox container includes the following tools by default:

| Category   | Tools                                                    |
| ---------- | -------------------------------------------------------- |
| Agent      | `claude`, `opencode`, `codex`                            |
| Language   | `python` (3.12), `node` (22)                             |
| Developer  | `gh`, `git`, `vim`, `nano`                               |
| Networking | `ping`, `dig`, `nslookup`, `nc`, `traceroute`, `netstat` |

For additional sandbox images see the [NVIDIA/NemoClaw-Community](https://github.com/NVIDIA/NemoClaw-Community) images. You can also [build your own custom images](examples/bring-your-own-container.md).

### Deploy a cluster

**Note:** `nemoclaw sandbox create` automatically deploys a cluster if one isn't already running.

To deploy a cluster explicitly:

```bash
nemoclaw gateway start
```

For remote deployment:

```bash
nemoclaw gateway start --remote user@host
```

### Upgrading

To upgrade, redeploy your cluster to pick up the latest server and sandbox images:

```bash
nemoclaw gateway start
```

This will prompt you to recreate the cluster. Select "yes" to recreate the cluster.

## Developing

See `CONTRIBUTING.md` for building from source and contributing to NemoClaw.

## Architecture

See `architecture/` for detailed architecture docs and design decisions.
