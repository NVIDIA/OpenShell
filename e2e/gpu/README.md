<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# GPU workload images

This directory defines GPU workload images used by OpenShell GPU e2e tests.

The image definitions live here first so the OpenShell e2e harness can iterate
against a concrete contract. The long-term image ownership should move to
`NVIDIA/OpenShell-Community`; OpenShell should then keep the contract, local
build task, and tests that consume published image refs.

## Contract

Each workload image must:

- Use the OpenShell community base image as its final-stage base.
- Install the workload at `/usr/local/bin/openshell-gpu-workload`.
- Run the same workload as the image default entrypoint for direct
  container-engine validation.
- Require no network access after the image is pulled.
- Print `OPENSHELL_GPU_WORKLOAD_SUCCESS` only when validation succeeds.
- Print `OPENSHELL_GPU_WORKLOAD_FAILURE` and exit non-zero when validation
  fails.
- Be usable as an OpenShell sandbox image with `openshell sandbox create
  --from <image>`.

OpenShell sandbox creation replaces the image entrypoint with the supervisor and
does not run the OCI image `CMD`. E2e tests that use these images through
OpenShell should run `/usr/local/bin/openshell-gpu-workload` explicitly.

## Images

| Source directory | Image name | Purpose |
| --- | --- | --- |
| `smoke-pass` | `gpu-workload-smoke-pass` | Always succeeds and prints the success marker. |
| `smoke-fail` | `gpu-workload-smoke-fail` | Always fails and prints the failure marker. |
| `cuda-basic` | `gpu-workload-cuda-basic` | Runs CUDA `deviceQuery` and `vectorAdd` validation. |

## Build

Build all workload images:

```shell
mise run e2e:gpu:images:build
```

Build a subset by source directory name:

```shell
OPENSHELL_GPU_WORKLOAD_IMAGES=smoke-pass,smoke-fail \
mise run e2e:gpu:images:build
```

The build task uses `tasks/scripts/container-engine.sh`. Set
`CONTAINER_ENGINE=docker` or `CONTAINER_ENGINE=podman` to choose an engine
explicitly. When unset, the helper uses its existing auto-detection behavior.

Local tags use the current commit short SHA. Dirty local trees append `-dirty`.
Set `OPENSHELL_GPU_WORKLOAD_IMAGE_TAG=<tag>` to override the tag.

The task writes the latest build refs to:

```text
e2e/gpu/images/.build/latest.env
```

Use it in later commands:

```shell
source e2e/gpu/images/.build/latest.env
```

## Direct Validation

Validate smoke pass:

```shell
docker run --rm "${OPENSHELL_E2E_GPU_SMOKE_PASS_IMAGE}"
```

Validate smoke fail:

```shell
docker run --rm "${OPENSHELL_E2E_GPU_SMOKE_FAIL_IMAGE}"
```

The smoke fail command should exit non-zero and print
`OPENSHELL_GPU_WORKLOAD_FAILURE`.

Validate CUDA with Docker CDI:

```shell
docker run --rm --device nvidia.com/gpu=all \
  "${OPENSHELL_E2E_GPU_CUDA_WORKLOAD_IMAGE}"
```

Use `podman run` with the same `--device nvidia.com/gpu=all` option on hosts
where Podman CDI is configured.

Direct container-engine validation catches image, CDI, CUDA, and host GPU setup
issues before OpenShell sandbox behavior is involved.

## Publish Guidance

Published tests should reference immutable image refs:

```shell
OPENSHELL_E2E_GPU_CUDA_WORKLOAD_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/gpu-workload-cuda-basic@sha256:<digest>
```

Mutable tags are acceptable for local iteration. CI should use a digest or an
immutable release tag once the images are published from OpenShell-Community.
