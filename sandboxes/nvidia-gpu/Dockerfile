# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# GPU-enabled sandbox image for OpenShell VM driver.
#
# Provides userspace GPU tooling (nvidia-smi, NVML, CUDA driver libs, kmod)
# on top of a minimal Ubuntu base with the full NVIDIA driver userspace
# installed via the official .run installer (no kernel modules -- those are
# injected at rootfs preparation time by the VM driver).
#
# Usage:
#   openshell sandbox create --gpu --from ./sandboxes/nvidia-gpu/Dockerfile
#   openshell sandbox create --gpu --from nvidia-gpu   # once published
#
# Build-time args:
#   CUDA_VERSION          - CUDA toolkit version (default: 12.8.1)
#   UBUNTU_VERSION        - Ubuntu release (default: 22.04)
#   NVIDIA_DRIVER_VERSION - Must match the kernel modules built by
#                           `mise run vm:nvidia-modules` (default: 580.159.03)

ARG CUDA_VERSION=12.8.1
ARG UBUNTU_VERSION=22.04

FROM nvidia/cuda:${CUDA_VERSION}-base-ubuntu${UBUNTU_VERSION}

# Must match NVIDIA_DRIVER_VERSION in sandboxes/nvidia-gpu/versions.env
# and NVIDIA_OPEN_VERSION in tasks/scripts/vm/build-nvidia-modules.sh
ARG NVIDIA_DRIVER_VERSION=580.159.03

# ── System packages required by the sandbox init script ──────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        busybox-static \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        kmod \
        pciutils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/share/udhcpc && ln -sf /bin/busybox /sbin/udhcpc

# ── NVIDIA driver userspace ──────────────────────────────────────────
# The nvidia/cuda base image does NOT include the driver (nvidia-smi,
# libcuda.so, libnvidia-ml.so). It relies on the NVIDIA Container
# Runtime to mount them from the host. In a VM there is no container
# runtime, so we install the driver userspace via the .run installer
# with --no-kernel-module (kernel modules are injected separately).
# TODO(gpu): Pin SHA-256 checksum for reproducible builds. Compute with:
#   curl -fsSL <url> | sha256sum
RUN curl -fsSL \
        "https://us.download.nvidia.com/XFree86/Linux-x86_64/${NVIDIA_DRIVER_VERSION}/NVIDIA-Linux-x86_64-${NVIDIA_DRIVER_VERSION}.run" \
        -o /tmp/nvidia.run \
    && chmod +x /tmp/nvidia.run \
    && /tmp/nvidia.run \
        --silent \
        --no-kernel-module \
        --no-drm \
        --no-x-check \
        --no-systemd \
        --no-nvidia-modprobe \
        --no-distro-scripts \
    && rm -f /tmp/nvidia.run

# Ensure library paths are indexed for dlopen.
RUN mkdir -p /etc/ld.so.conf.d \
    && echo "/usr/local/cuda/lib64" > /etc/ld.so.conf.d/cuda.conf \
    && echo "/usr/lib/x86_64-linux-gnu" >> /etc/ld.so.conf.d/cuda.conf \
    && ldconfig 2>/dev/null || true

# ── Kernel modules ───────────────────────────────────────────────────
# NVIDIA kernel modules (.ko) must match the guest VM kernel (libkrunfw).
# They are NOT in this image -- the VM driver injects them at rootfs
# preparation time via `inject_gpu_modules`.
#
# GSP firmware (.bin) IS provided by the .run installer above. The VM
# driver detects its presence and skips firmware injection, avoiding
# version mismatches when the host driver differs from this image's.
RUN mkdir -p /lib/modules

LABEL org.opencontainers.image.title="OpenShell GPU Sandbox" \
      org.opencontainers.image.description="GPU-enabled sandbox for OpenShell VM driver with CUDA support" \
      io.openshell.sandbox.gpu="true"
