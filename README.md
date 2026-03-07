# NemoClaw 

NemoClaw is the runtime environment for autonomous agents—the "Matrix" where they live, work, and verify.

While coding tools like Claude help agents write logic, NemoClaw provides the infrastructure to run it, offering a programmable factory where agents can spin up physics simulations to master tasks, generate synthetic data to fix edge cases, and safely iterate through thousands of failures in isolated sandboxes.

It transforms the data center from a static deployment target into a continuous verification engine, allowing agents to autonomously build and operate complex systems—from physical robotics to self-healing infrastructure—without needing a human to manage the infrastructure.

## Quickstart

### Prerequisites

<!-- referenced in docs/get-started/quickstart.md -->
<!-- quickstart-prereqs-start -->
| Requirement | Details                                                                   |
|-------------|---------------------------------------------------------------------------|
| **Docker**  | Docker Desktop or a standalone Docker Engine daemon, running.             |
| **Python**  | 3.12 or later.                                                            |
<!-- quickstart-prereqs-end -->

### Install

<!-- referenced in docs/get-started/quickstart.md -->
<!-- quickstart-install-start -->
```bash
pip install nemoclaw
```
<!-- quickstart-install-end -->

### Install from Source (Developer)

Requires [mise](https://mise.jdx.dev/), Rust 1.88+, Python 3.12+, and Docker.

```bash
git clone https://github.com/NVIDIA/NemoClaw.git
cd NemoClaw
mise trust
```

`mise` installs all remaining toolchain dependencies automatically. The local `nemoclaw` script builds and runs the debug CLI binary, so you can invoke `nemoclaw` directly from the repo. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full development workflow.

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
