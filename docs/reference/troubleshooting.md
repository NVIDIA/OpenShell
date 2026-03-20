---
title:
  page: Troubleshooting
  nav: Troubleshooting
description: Solutions for common issues when running OpenShell.
topics:
- Generative AI
- Cybersecurity
tags:
- Troubleshooting
- Podman
- Docker
content:
  type: reference
  difficulty: technical_intermediate
  audience:
  - engineer
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Troubleshooting

This page covers common issues and their solutions when running OpenShell.

## Podman on macOS

The following issues are specific to running OpenShell with Podman on macOS.

### Gateway fails with "cgroup permission denied"

The gateway container requires access to cgroup controllers that are only available in rootful mode. If you see a permission denied error related to cgroups, confirm that your Podman machine is configured for rootful mode:

```console
$ podman machine set --rootful
$ podman machine stop
$ podman machine start
```

### Image push fails with "connection closed"

Large image operations can fail when the Podman VM does not have enough memory. Increase the VM memory to at least 8 GiB and prune unused images to free space:

```console
$ podman machine stop
$ podman machine set --memory 8192
$ podman machine start
$ podman image prune -f
```

### "/dev/kmsg: operation not permitted"

Some container images attempt to read `/dev/kmsg` at startup. OpenShell handles this automatically by providing a safe fallback inside the sandbox. No action is required.
