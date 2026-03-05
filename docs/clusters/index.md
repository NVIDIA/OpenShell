<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Clusters

NemoClaw packages the entire platform — Kubernetes, the gateway, networking, and pre-loaded container images — into a single Docker container. Docker is the only dependency.

## Bootstrapping a Cluster

```console
$ nemoclaw cluster admin deploy
```

This provisions a local k3s cluster in Docker, pre-loaded with all required images and Helm charts. The cluster is automatically set as the active cluster.

### What Gets Created

- A Docker container running k3s (lightweight Kubernetes).
- The NemoClaw gateway (control plane) deployed as a Kubernetes service.
- Pre-loaded sandbox and gateway container images.
- mTLS certificates for secure communication.
- Cluster metadata stored in `~/.config/nemoclaw/clusters/`.

## Cluster Lifecycle

| Command | Description |
|---------|-------------|
| `nemoclaw cluster admin deploy` | Provision or restart a cluster (idempotent). |
| `nemoclaw cluster admin stop` | Stop the cluster container (preserves state). |
| `nemoclaw cluster admin destroy` | Destroy the cluster and all its state. |
| `nemoclaw cluster status` | Check gateway connectivity and version. |
| `nemoclaw cluster list` | List all provisioned clusters. |
| `nemoclaw cluster use <name>` | Set the active cluster. |

### Idempotent Deploy

Running `deploy` again is safe. It reuses existing infrastructure or recreates only what changed.

### Stop vs. Destroy

- **Stop** pauses the Docker container, preserving all state (sandboxes, providers, routes). Restarting with `deploy` brings everything back.
- **Destroy** permanently removes the container, volumes, kubeconfig, metadata, and mTLS certificates.

## Cluster Resolution

The CLI resolves which cluster to operate on through this priority chain:

1. `--cluster` flag (explicit).
2. `NEMOCLAW_CLUSTER` environment variable.
3. Active cluster set by `nemoclaw cluster use`.

## Multiple Clusters

You can manage multiple clusters simultaneously:

```console
$ nemoclaw cluster admin deploy --name dev
$ nemoclaw cluster admin deploy --name staging --port 8081
$ nemoclaw cluster list
$ nemoclaw cluster use dev
```

## Remote Deployment

Deploy NemoClaw on a remote host via SSH. See [Remote Deployment](remote-deploy.md).

## Cluster Info

View deployment details:

```console
$ nemoclaw cluster admin info
```

Shows the gateway endpoint, kubeconfig path, kube port, and remote host (if applicable).
