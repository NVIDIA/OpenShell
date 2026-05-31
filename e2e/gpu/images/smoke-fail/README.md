<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# GPU workload smoke fail

`smoke-fail` validates negative-path diagnostics in e2e test plumbing.

The workload does not perform GPU-specific work. It prints
`OPENSHELL_GPU_WORKLOAD_FAILURE`, emits a stable diagnostic, and exits non-zero.

Build it with:

```shell
OPENSHELL_GPU_WORKLOAD_IMAGES=smoke-fail mise run e2e:gpu:images:build
```

Run it directly:

```shell
source e2e/gpu/images/.build/latest.env
docker run --rm "${OPENSHELL_E2E_GPU_SMOKE_FAIL_IMAGE}"
```

The direct run should fail.
