# Navigator 🗺️

Navigator is the runtime environment for autonomous agents—the "Matrix" where they live, work, and verify.

While coding tools like Claude help agents write logic, Navigator provides the infrastructure to run it, offering a programmable factory where agents can spin up physics simulations to master tasks, generate synthetic data to fix edge cases, and safely iterate through thousands of failures in isolated sandboxes.

It transforms the data center from a static deployment target into a continuous verification engine, allowing agents to autonomously build and operate complex systems—from physical robotics to self-healing infrastructure—without needing a human to manage the infrastructure.

## Quickstart

🚧 Under construction 🚧

```bash
uv pip install navigator --upgrade --pre --index-url https://urm.nvidia.com/artifactory/api/pypi/nv-shared-pypi/simple 

navigator sandbox create -- claude  # or opencode or codex
```

The sandbox container includes a minimal networking toolset by default: `ping`, `dig`, `nslookup`, `nc`, `traceroute`, and `netstat`.

## Developing

See `CONTRIBUTING.md` for more information about developing and contributing to Navigator.

## Architecture

See `architecture/` for detailed architecture docs and design decisions.
