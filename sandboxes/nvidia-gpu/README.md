<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# GPU Sandbox Image

GPU-enabled sandbox image for the OpenShell VM driver. Provides NVIDIA
userspace tooling (nvidia-smi, NVML, CUDA driver libraries) on top of a
minimal Ubuntu base. Kernel modules are injected separately by the VM
driver at sandbox creation time.

## Architecture

The GPU sandbox splits responsibility between the container image and the
VM driver:

| Layer | Source | Contents |
|-------|--------|----------|
| **Userspace** | This Dockerfile | nvidia-smi, libcuda.so, libnvidia-ml.so, kmod, iproute2 |
| **Kernel modules** | VM driver injection | nvidia.ko, nvidia_uvm.ko, nvidia_modeset.ko (built for guest kernel 6.12.76) |
| **GSP firmware** | `.run` installer in image OR host fallback | gsp_ga10x.bin, gsp_tu10x.bin |

The kernel modules must be compiled against the exact guest kernel version
used by libkrunfw. The VM driver injects them into each sandbox's rootfs
at creation time via `inject_gpu_modules()`.

## Prerequisites

- Linux x86_64 host with an NVIDIA GPU
- IOMMU enabled (for VFIO GPU passthrough)
- Docker (for building the sandbox image)
- Guest kernel built with `CONFIG_MODULES=y` (`mise run vm:setup`)

## Quick Start

```shell
# 1. One-time: build the VM runtime (includes guest kernel with module support)
mise run vm:setup

# 2. Build NVIDIA kernel modules for the guest kernel
mise run vm:nvidia-modules

# 3. Build the GPU sandbox image
docker build -t nvidia-gpu:latest ./sandboxes/nvidia-gpu/

# 4. Start the gateway with GPU support
sudo mise run gateway:vm -- --gpu

# 5. Create a GPU sandbox
openshell sandbox create --gpu --from nvidia-gpu:latest
```

## Version Coupling

The NVIDIA driver version must match across three components:

| Component | Variable | Default |
|-----------|----------|---------|
| Dockerfile (userspace) | `NVIDIA_DRIVER_VERSION` | `580.159.03` |
| Module build script | `NVIDIA_OPEN_VERSION` | `580.159.03` |
| Shared reference | `sandboxes/nvidia-gpu/versions.env` | `580.159.03` |

A mismatch causes `modprobe` "version magic" errors or nvidia-smi ABI
failures at sandbox boot time.

## Customization

### Changing the CUDA version

```shell
docker build \
  --build-arg CUDA_VERSION=12.6.0 \
  --build-arg UBUNTU_VERSION=22.04 \
  -t my-gpu-sandbox:latest \
  ./sandboxes/nvidia-gpu/
```

### Changing the NVIDIA driver version

Update all three locations:

1. `sandboxes/nvidia-gpu/versions.env`
2. `sandboxes/nvidia-gpu/Dockerfile` ARG `NVIDIA_DRIVER_VERSION`
3. Rebuild kernel modules: `NVIDIA_OPEN_VERSION=<version> mise run vm:nvidia-modules`

### Adding packages

Add packages to the `apt-get install` line in the Dockerfile. The image
must retain `bash`, `kmod`, `iproute2`, and `busybox-static` — the VM
driver validates these at rootfs preparation time.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "No GPU kernel modules found" | Modules not built | `mise run vm:nvidia-modules` |
| "kmod not found in rootfs" | Image missing kmod package | Add `kmod` to Dockerfile `apt-get install` |
| `modprobe nvidia` fails | Kernel version mismatch | Rebuild modules after `mise run vm:setup` |
| nvidia-smi "driver/library mismatch" | Userspace/module version mismatch | Ensure Dockerfile and module versions match |
| "kernel version mismatch: expected X, got Y" | Guest kernel was rebuilt | Rebuild modules: `mise run vm:nvidia-modules` |
