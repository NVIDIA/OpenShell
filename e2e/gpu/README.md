<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# GPU workload images

This directory defines workload test images currently used by the OpenShell GPU
e2e suite.

## Contract

Each workload image must:

- Use the standard OpenShell sandbox base image as its final-stage base or
  ensure that the requirements for a sandbox image are met.
- Provide a manifest command that runs the workload inside the sandbox image.
- Run the same workload as the image default entrypoint for direct
  container-engine validation.
- Require no network access after the image is pulled.
- Print `OPENSHELL_GPU_WORKLOAD_SUCCESS` only when validation succeeds.
- Print `OPENSHELL_GPU_WORKLOAD_FAILURE` and exit non-zero when validation
  fails.
- Be usable as an OpenShell sandbox image when OpenShell invokes the manifest
  command explicitly.

OpenShell sandbox creation replaces the image entrypoint with the supervisor and
does not run the OCI image `CMD`. E2e tests that use these images through
OpenShell run the command from each manifest entry explicitly.

The test harness is manifest-driven. Each workload entry carries:

- `name`
- `image`
- `command`
- `expect`
- `requirements`

## Images

| Source directory | Image name | Purpose |
| --- | --- | --- |
| `smoke-pass` | `gpu-workload-smoke-pass` | Always succeeds and prints the success marker. |
| `smoke-fail` | `gpu-workload-smoke-fail` | Always fails and prints the failure marker. |
| `cuda-basic` | `gpu-workload-cuda-basic` | Runs CUDA `deviceQuery` and `vectorAdd` validation. |

## Build

Build all workload images:

```shell
mise run e2e:workloads:build
```

Build a subset by source directory name:

```shell
OPENSHELL_GPU_WORKLOAD_IMAGES=smoke-pass,smoke-fail \
mise run e2e:workloads:build
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

The task also writes the local workload manifest used by the Rust e2e runner:

```text
e2e/gpu/images/.build/workloads.yaml
```

That local manifest is created by `mise run e2e:workloads:build`. It contains
the full image reference, command, expected outcome, and requirements for each
selected workload.

Use the env file in later commands:

```shell
source e2e/gpu/images/.build/latest.env
```

That env file exports `OPENSHELL_E2E_WORKLOAD_MANIFEST` pointing at the local
manifest. The per-image refs remain available as a convenience for direct
container-engine validation.

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

## Manifest-Driven Validation

The Rust GPU validation target is:

```shell
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-docker-gpu --test gpu -- --nocapture
```

The workload validation path reads:

```text
OPENSHELL_E2E_WORKLOAD_MANIFEST
```

When that variable is unset, the runner uses the default local manifest path:

```text
e2e/gpu/images/.build/workloads.yaml
```

If neither path exists, the workload validation test prints a clear skip
message telling you to run:

```shell
mise run e2e:workloads:build
```

or to set `OPENSHELL_E2E_WORKLOAD_MANIFEST` to an external manifest.

Each manifest entry supplies the sandbox image and command. OpenShell runs that
command through `openshell sandbox create --gpu --from <image> -- <command>`.
The test runner iterates all GPU-tagged workload entries and enforces each
entry's declared expectation:

- `expect: pass` requires `OPENSHELL_GPU_WORKLOAD_SUCCESS`
- `expect: fail` requires `OPENSHELL_GPU_WORKLOAD_FAILURE`

The current local manifest includes three workloads:

- `smoke-pass` expected to pass
- `smoke-fail` expected to fail
- `cuda-basic` expected to pass

## External Manifests

External workload catalogs can use the same schema. Point the runner at one
with:

```shell
export OPENSHELL_E2E_WORKLOAD_MANIFEST=/abs/path/to/workloads.yaml
```

That lets alternate workload manifests use the same test runner without
introducing per-workload env vars.
