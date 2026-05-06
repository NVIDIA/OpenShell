# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Architecture: GPU sandbox images are currently x86_64-only (both host and
# guest). The .run installer and lib paths target Linux-x86_64 exclusively.
# ARM/aarch64 GPU passthrough is not yet supported.
#
# GPU-enabled sandbox image for OpenShell VM driver.
#
# Provides userspace GPU tooling (nvidia-smi, NVML, CUDA driver libs, kmod)
# on top of a minimal Ubuntu base with the full NVIDIA driver userspace
# installed via the official .run installer (no kernel modules -- those are
# injected at rootfs preparation time by the VM driver).
#
# Usage:
#   ./build.sh                         # recommended — sources versions.env
#   ./build.sh -t my-registry/gpu:v1   # custom tag
#   openshell sandbox create --gpu --from ./sandboxes/nvidia-gpu/Dockerfile
#
# Build-time args:
#   NVIDIA_DRIVER_VERSION - **Required** (no default). Must match the kernel
#                           modules built by `mise run vm:nvidia-modules`.
#                           Use ./build.sh which sources versions.env, or pass
#                           --build-arg NVIDIA_DRIVER_VERSION=<ver> manually.

FROM ubuntu:latest

# Must match NVIDIA_DRIVER_VERSION in sandboxes/nvidia-gpu/versions.env.
# The module build script also uses this version for the open-gpu-kernel-modules tag.
# No default — use ./build.sh or pass --build-arg explicitly.
ARG NVIDIA_DRIVER_VERSION

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
# We install the full driver userspace via the official .run installer
# with --no-kernel-module (kernel modules are injected separately by
# the VM driver at rootfs preparation time).
# TODO(gpu): Pin SHA-256 checksum for reproducible builds. Compute with:
#   curl -fsSL <url> | sha256sum
RUN test -n "${NVIDIA_DRIVER_VERSION}" || \
      { echo "ERROR: NVIDIA_DRIVER_VERSION not set. Use ./build.sh or pass --build-arg NVIDIA_DRIVER_VERSION=<ver>"; exit 1; } \
    && curl -fsSL \
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

RUN echo "${NVIDIA_DRIVER_VERSION}" > /etc/openshell-gpu-driver-version

# The .run installer places libs in standard paths (/usr/lib/x86_64-linux-gnu).
# Run ldconfig to update the linker cache for dlopen resolution.
RUN ldconfig 2>/dev/null || true

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
