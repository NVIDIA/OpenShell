<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# GPU workload smoke pass

`smoke-pass` validates image publishing, sandbox image compatibility, default
entrypoint execution, and success-marker assertion plumbing.

The workload does not perform GPU-specific work. It prints
`OPENSHELL_GPU_WORKLOAD_SUCCESS` and exits `0`.

Build it with:

```shell
mise run e2e:workloads:build
```

That command also refreshes the local workload manifest at
`e2e/gpu/images/.build/workloads.yaml`.

To build only this workload locally, set:

```shell
OPENSHELL_GPU_WORKLOAD_IMAGES=smoke-pass mise run e2e:workloads:build
```

Run it directly:

```shell
source e2e/gpu/images/.build/latest.env
docker run --rm "${OPENSHELL_E2E_GPU_SMOKE_PASS_IMAGE}"
```
