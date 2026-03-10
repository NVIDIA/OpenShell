<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Sandboxes

A OpenShell sandbox is a safe, private execution environment for an AI agent. Each sandbox runs inside a Kubernetes pod with multiple layers of protection that prevent unauthorized data access, credential exposure, and network exfiltration. Protection layers include filesystem restrictions (Landlock), system call filtering (seccomp), network namespace isolation, and a privacy-enforcing HTTP CONNECT proxy.

## Sandbox Lifecycle

Every sandbox moves through a defined set of phases:

| Phase | Description |
|---|---|
| Provisioning | The runtime is setting up the sandbox environment, injecting credentials, and applying your policy. |
| Ready | The sandbox is running. The agent process is active and all isolation layers are enforced. You can connect, sync files, and view logs. |
| Error | Something went wrong during provisioning or execution. Check logs with `openshell logs` for details. |
| Deleting | The sandbox is being torn down. The system releases resources and purges credentials. |

## The OpenShell Runtime

Sandboxes run inside a lightweight runtime cluster that OpenShell manages for
you. The cluster runs as a [k3s](https://k3s.io/) Kubernetes distribution
inside a Docker container on your machine.

You do not need to set this up manually. The first time you run a command
that needs a cluster (such as `openshell sandbox create`), the CLI provisions
one automatically.

## Next Steps

- {doc}`create-and-manage`: Create, inspect, connect, monitor, and delete
  sandboxes.
- {doc}`providers`: Create and attach credential providers so agents can
  authenticate with external services.
- {doc}`community-sandboxes`: Use pre-built sandboxes from the community
  catalog.
