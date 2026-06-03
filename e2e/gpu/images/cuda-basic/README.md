<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# GPU workload CUDA basic

`cuda-basic` validates that a GPU-enabled environment can run a basic CUDA
runtime workload. It is a single image that runs two validation steps:

1. `deviceQuery` checks CUDA runtime, driver, and device discovery.
2. `vectorAdd` checks kernel launch, device memory allocation, host/device
   copies, synchronization, and result validation.

The image builds the samples from `NVIDIA/cuda-samples` tag `v12.8` with a CUDA
12.8 builder image, then copies only the compiled binaries into the OpenShell
community base final image.

The workload prints `OPENSHELL_GPU_WORKLOAD_SUCCESS` only after both samples
pass. On failure it prints `OPENSHELL_GPU_WORKLOAD_FAILURE` and exits non-zero.

Build it with:

```shell
mise run e2e:workloads:build
```

That command also refreshes the local workload manifest at
`e2e/gpu/images/.build/workloads.yaml`.

To build only this workload locally, set:

```shell
OPENSHELL_GPU_WORKLOAD_IMAGES=cuda-basic mise run e2e:workloads:build
```

Run it directly with Docker CDI:

```shell
source e2e/gpu/images/.build/latest.env
docker run --rm --device nvidia.com/gpu=all \
  "${OPENSHELL_E2E_GPU_CUDA_WORKLOAD_IMAGE}"
```

Use `podman run` with the same `--device nvidia.com/gpu=all` option when Podman
CDI is configured.

The image does not vendor GPU driver libraries such as `libcuda.so.1`. Those
libraries must be provided by the host GPU runtime or CDI injection.

The CUDA samples are redistributed under the NVIDIA CUDA samples license. The
license text is copied into the image at
`/usr/local/share/doc/openshell-gpu-workload/cuda-samples.LICENSE`.
