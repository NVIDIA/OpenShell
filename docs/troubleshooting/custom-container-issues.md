<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Custom Container Issues

Troubleshoot problems with building and running custom container images in sandboxes.

## Custom Image Fails to Start

**Symptom:** Sandbox with `--image` goes to `Error` state.

**Check:**
1. Is the image pushed to the cluster? `nemoclaw sandbox image push --dockerfile ./Dockerfile --tag my-image`.
2. Does the image have glibc and `/proc`? Distroless / `FROM scratch` images are not supported.
3. For proxy mode, does the image have `iproute2`? Network namespace setup requires it.
