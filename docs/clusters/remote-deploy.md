<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Remote Deployment

NemoClaw can deploy clusters on remote hosts via SSH. The same bootstrap flow that works locally also works on remote machines — Docker on the remote host is the only requirement.

## Deploying Remotely

```console
$ nemoclaw cluster admin deploy --remote user@host --ssh-key ~/.ssh/id_rsa
```

This:

1. Connects to the remote host via SSH.
2. Pulls the NemoClaw cluster image on the remote Docker daemon.
3. Provisions the k3s cluster, gateway, and all components on the remote host.
4. Extracts the kubeconfig and mTLS certificates back to your local machine.
5. Sets the remote cluster as the active cluster.

All subsequent CLI commands (sandbox create, provider management, etc.) operate against the remote cluster transparently.

## Creating Sandboxes Remotely

You can bootstrap a remote cluster and create a sandbox in a single command:

```console
$ nemoclaw sandbox create --remote user@host -- claude
```

If no cluster exists on the remote host, one is bootstrapped automatically.

## Accessing the Kubernetes API

For kubectl access to a remote cluster, use the tunnel command:

```console
$ nemoclaw cluster admin tunnel --name my-remote-cluster
```

This starts an SSH tunnel so `kubectl` can reach the Kubernetes API on the remote host.

To print the SSH command without executing it:

```console
$ nemoclaw cluster admin tunnel --name my-remote-cluster --print-command
```

## Managing Remote Clusters

All lifecycle commands accept `--remote` and `--ssh-key` flags:

```console
$ nemoclaw cluster admin stop --remote user@host --ssh-key ~/.ssh/id_rsa
$ nemoclaw cluster admin destroy --remote user@host --ssh-key ~/.ssh/id_rsa
```

## How It Works

Remote deployment uses the Docker daemon over SSH (`ssh://user@host`). All operations — image pulls, container creation, health checks, kubeconfig extraction — are executed via the Docker API on the remote daemon. No additional software needs to be installed on the remote host beyond Docker.
