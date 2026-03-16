<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Support Matrix

This page lists the platform, software, runtime, and kernel requirements for running OpenShell.

## Supported Platforms

OpenShell publishes multi-architecture container images for `linux/amd64` and `linux/arm64`. The CLI is supported on the following host platforms:

| Platform                         | Architecture          | Status    |
| -------------------------------- | --------------------- | --------- |
| Linux (Debian/Ubuntu)            | x86_64 (amd64)        | Supported |
| Linux (Debian/Ubuntu)            | aarch64 (arm64)       | Supported |
| macOS (Docker Desktop)           | Apple Silicon (arm64) | Supported |
| Windows (WSL 2 + Docker Desktop) | x86_64                | Experimental  |

## Software Prerequisites

The following software must be installed on the host before using the OpenShell CLI:

| Component                       | Minimum Version | Notes                                           |
| ------------------------------- | --------------- | ----------------------------------------------- |
| Docker Desktop or Docker Engine | 28.04           | Must be running before any `openshell` command. |

## Sandbox Runtime Versions

Sandbox container images are maintained in the [openshell-community](https://github.com/nvidia/openshell-community) repository. Refer to that repository for the current list of installed components and their versions.

## Container Images

OpenShell publishes two container images. Both are published for `linux/amd64` and `linux/arm64`.

| Image   | Reference                                 | Pulled When                      |
| ------- | ----------------------------------------- | -------------------------------- |
| Cluster | `ghcr.io/nvidia/openshell/cluster:latest` | `openshell gateway start`        |
| Gateway | `ghcr.io/nvidia/openshell/gateway:latest` | Cluster startup (via Helm chart) |

The cluster image bundles the Helm charts, Kubernetes manifests, and the `openshell-sandbox` supervisor binary required to bootstrap the control plane. The supervisor binary is side-loaded into sandbox pods at runtime through a read-only host volume mount. The gateway image is pulled at cluster startup and runs the API server.

Sandbox images are maintained separately in the [openshell-community](https://github.com/nvidia/openshell-community) repository.

To override the default image references, set the following environment variables:

| Variable                       | Purpose                                             |
| ------------------------------ | --------------------------------------------------- |
| `OPENSHELL_CLUSTER_IMAGE`      | Override the cluster image reference.               |
| `OPENSHELL_COMMUNITY_REGISTRY` | Override the registry for community sandbox images. |

## Kernel Requirements

OpenShell enforces sandbox isolation through two Linux kernel security modules:

| Module                                                         | Requirement | Details                                                                                                                                                                                                                                          |
| -------------------------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [Landlock LSM](https://docs.kernel.org/security/landlock.html) | Recommended | Enforces filesystem access restrictions at the kernel level. The `best_effort` compatibility mode uses the highest Landlock ABI the host kernel supports. The `hard_requirement` mode fails sandbox creation if the required ABI is unavailable. |
| seccomp                                                        | Required    | Filters dangerous system calls. Available on all modern Linux kernels (3.17+).                                                                                                                                                                   |

On macOS, these kernel modules run inside the Docker Desktop Linux VM, not on the host kernel.

## Agent Compatibility

For the full list of supported agents and their default policy coverage, refer to the {doc}`../about/supported-agents` page.
