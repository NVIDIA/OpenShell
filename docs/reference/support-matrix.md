
<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Support Matrix

This page lists the platform, software, runtime, and kernel requirements for running OpenShell.

## Supported Platforms

OpenShell publishes multi-architecture container images for `linux/amd64` and `linux/arm64`. The CLI is supported on the following host platforms:

| Platform | Architecture | Status |
|---|---|---|
| Linux (Debian/Ubuntu) | x86_64 (amd64) | Supported |
| Linux (Debian/Ubuntu) | aarch64 (arm64) | Supported |
| macOS (Docker Desktop) | Apple Silicon (arm64) | Supported |
| macOS (Docker Desktop) | Intel (amd64) | Supported |
| Windows (WSL 2 + Docker Desktop) | x86_64 | Untested |

## Software Prerequisites

The following software must be installed on the host before using the OpenShell CLI:

| Component | Minimum Version | Notes |
|---|---|---|
| Python | 3.12 | Python 3.12 and 3.13 are supported. |
| [uv](https://docs.astral.sh/uv/) | 0.9 | Used to install the CLI (`uv pip install openshell`). |
| Docker Desktop or Docker Engine | — | Must be running before any `openshell` command. No minimum version is enforced. |

## Sandbox Runtime Versions

The base sandbox container image ships the following components. These versions apply to sandboxes created with the default image (`ghcr.io/nvidia/openshell/sandbox`).

| Component | Version |
|---|---|
| Base OS | Debian Bookworm |
| Python | 3.12.13 |
| Node.js | 22.22.1 |
| npm | 11.11.0 |
| uv | 0.10.8 |
| Claude Code | Latest (installed at image build time) |
| OpenCode | 1.2.18 |
| Codex | 0.111.0 |

## Container Images

OpenShell uses several container images that are pulled automatically during gateway startup and sandbox creation. All images are published for `linux/amd64` and `linux/arm64`.

| Image | Registry | Reference | Pulled When |
|---|---|---|---|
| Cluster | ghcr.io | `ghcr.io/nvidia/openshell/cluster:latest` | `openshell gateway start` |
| Server | ghcr.io | `ghcr.io/nvidia/openshell/server:latest` | Cluster startup (via Helm chart) |
| Sandbox | ghcr.io | `ghcr.io/nvidia/openshell/sandbox:latest` | First sandbox creation (via Helm chart) |
| Community sandboxes | GHCR | `ghcr.io/nvidia/openshell-community/sandboxes/{name}:latest` | `openshell sandbox create --from <name>` |

The cluster image is based on `rancher/k3s:v1.35.2-k3s1` and bundles the Helm charts and Kubernetes manifests required to bootstrap the control plane. The server and sandbox images are pulled separately at runtime.

To override the default image references, set the following environment variables:

| Variable | Purpose |
|---|---|
| `OPENSHELL_CLUSTER_IMAGE` | Override the cluster image reference. |
| `OPENSHELL_COMMUNITY_REGISTRY` | Override the registry for community sandbox images. |

## Kernel Requirements

OpenShell enforces sandbox isolation through two Linux kernel security modules:

| Module | Requirement | Details |
|---|---|---|
| [Landlock LSM](https://docs.kernel.org/security/landlock.html) | Recommended | Enforces filesystem access restrictions at the kernel level. The `best_effort` compatibility mode uses the highest Landlock ABI the host kernel supports. The `hard_requirement` mode fails sandbox creation if the required ABI is unavailable. |
| seccomp | Required | Filters dangerous system calls. Available on all modern Linux kernels (3.17+). |

On macOS, these kernel modules run inside the Docker Desktop Linux VM, not on the host kernel.

## Agent Compatibility

For the full list of supported agents and their default policy coverage, refer to the [Supported Agents](../sandboxes/index.md#supported-agents) table.
