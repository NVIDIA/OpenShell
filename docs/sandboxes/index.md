<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Sandboxes

A NemoClaw sandbox is a safe, private execution environment for an AI agent. Each sandbox runs inside a Kubernetes pod with multiple layers of protection that prevent unauthorized data access, credential exposure, and network exfiltration. Protection layers include filesystem restrictions (Landlock), system call filtering (seccomp), network namespace isolation, and a privacy-enforcing HTTP CONNECT proxy.

## Sandbox Lifecycle

Every sandbox moves through a defined set of phases:

| Phase | Description |
|---|---|
| Provisioning | The runtime is setting up the sandbox environment, injecting credentials, and applying your policy. |
| Ready | The sandbox is running. The agent process is active and all isolation layers are enforced. You can connect, sync files, and view logs. |
| Error | Something went wrong during provisioning or execution. Check logs with `nemoclaw sandbox logs` for details. |
| Deleting | The sandbox is being torn down. The system releases resources and purges credentials. |

## The NemoClaw Runtime

Sandboxes run inside a lightweight runtime cluster that NemoClaw manages for
you. The cluster runs as a [k3s](https://k3s.io/) Kubernetes distribution
inside a Docker container on your machine.

You do not need to set this up manually. The first time you run a command
that needs a cluster (such as `nemoclaw sandbox create`), the CLI provisions
one automatically. This is the "Runtime ready" line you see in the output.
Subsequent commands reuse the existing cluster.

For teams or when you need more resources, you can deploy the cluster to a
remote host instead of your local machine:

```console
$ nemoclaw cluster admin deploy --remote user@host
```

Refer to [Remote Deployment](../about/architecture.md) for
details. If you have multiple clusters (local and remote), switch between them
with `nemoclaw cluster use <name>`. Refer to the
[CLI Reference](../reference/cli.md#cluster-commands) for the full command set.

## Next Steps

- [Create and Manage Sandboxes](create-and-manage.md): The full sandbox lifecycle — create, inspect, connect, monitor, and delete.
- [Providers](providers.md): Create and attach credential providers.
- [Custom Containers](custom-containers.md): Build and run your own container image.
- [Community Sandboxes](community-sandboxes.md): Use pre-built sandboxes from the community catalog.
