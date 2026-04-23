#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build NVIDIA open kernel modules against the VM kernel source tree.
#
# Clones the NVIDIA open-gpu-kernel-modules repo at a pinned driver tag
# and compiles the kernel modules against the kernel built by
# build-libkrun.sh.  The resulting .ko files are placed in the output
# directory for injection into the GPU rootfs by build-rootfs.sh.
#
# Prerequisites:
#   - Kernel source tree built by build-libkrun.sh
#     (target/libkrun-build/libkrunfw/linux-<version>/)
#   - Build tools: make, gcc
#
# Usage:
#   ./build-nvidia-modules.sh [--output-dir <DIR>]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

source "${ROOT}/crates/openshell-vm/pins.env" 2>/dev/null || true

NVIDIA_DRIVER_VERSION="${NVIDIA_DRIVER_VERSION:-570}"

BUILD_DIR="${ROOT}/target/libkrun-build"
OUTPUT_DIR="${BUILD_DIR}/nvidia-modules"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ "$(uname -s)" != "Linux" ]; then
  echo "Error: NVIDIA GPU module build is Linux-only" >&2
  exit 1
fi

HOST_ARCH="$(uname -m)"
if [ "$HOST_ARCH" != "x86_64" ]; then
  echo "Error: NVIDIA GPU passthrough is only supported on x86_64 (got: ${HOST_ARCH})" >&2
  exit 1
fi

# ── Locate the kernel source tree ────────────────────────────────────────

LIBKRUNFW_DIR="${BUILD_DIR}/libkrunfw"
if [ ! -f "${LIBKRUNFW_DIR}/Makefile" ]; then
  echo "ERROR: libkrunfw not found at ${LIBKRUNFW_DIR}" >&2
  echo "       The GPU module build requires the kernel source tree." >&2
  echo "       Run: FROM_SOURCE=1 mise run vm:setup" >&2
  exit 1
fi

KERNEL_DIR_NAME="$(grep '^KERNEL_VERSION' "${LIBKRUNFW_DIR}/Makefile" | head -1 | awk '{print $3}')"
KERNEL_SOURCES="${LIBKRUNFW_DIR}/${KERNEL_DIR_NAME}"

if [ ! -f "${KERNEL_SOURCES}/.config" ]; then
  echo "ERROR: Kernel source tree not found at ${KERNEL_SOURCES}" >&2
  echo "       Run: FROM_SOURCE=1 mise run vm:setup" >&2
  exit 1
fi

if [ ! -f "${KERNEL_SOURCES}/Module.symvers" ]; then
  echo "ERROR: Kernel tree at ${KERNEL_SOURCES} is missing Module.symvers." >&2
  echo "       The kernel must have been fully built." >&2
  echo "       Run: FROM_SOURCE=1 mise run vm:setup" >&2
  exit 1
fi

# Use kernelrelease to get the full version string (includes CONFIG_LOCALVERSION).
KERNEL_VERSION="$(make -s -C "${KERNEL_SOURCES}" kernelrelease)"
echo "==> Building NVIDIA ${NVIDIA_DRIVER_VERSION} kernel modules for kernel ${KERNEL_VERSION}"
echo "    Kernel source: ${KERNEL_SOURCES}"
echo "    Output:        ${OUTPUT_DIR}"
echo ""

# ── Prepare kernel tree for out-of-tree module builds ────────────────────

echo "==> Preparing kernel tree for external module builds..."
make -C "${KERNEL_SOURCES}" modules_prepare -j"$(nproc)"

# ── Clone or reuse NVIDIA open-gpu-kernel-modules ────────────────────────

NVIDIA_DRIVER_TAG="${NVIDIA_DRIVER_TAG:-}"
if [ -z "${NVIDIA_DRIVER_TAG}" ]; then
  echo "ERROR: NVIDIA_DRIVER_TAG not set in pins.env or environment." >&2
  echo "       This must be the exact driver version tag matching the" >&2
  echo "       nvidia-headless-${NVIDIA_DRIVER_VERSION}-open APT package." >&2
  echo "       Find it:  apt-cache show nvidia-headless-${NVIDIA_DRIVER_VERSION}-open | grep Version" >&2
  echo "       Example:  NVIDIA_DRIVER_TAG=570.86.16" >&2
  exit 1
fi

NVIDIA_SRC="${BUILD_DIR}/open-gpu-kernel-modules"

if [ -d "${NVIDIA_SRC}" ]; then
  EXISTING_TAG="$(git -C "${NVIDIA_SRC}" describe --tags --exact-match HEAD 2>/dev/null || true)"
  if [ "${EXISTING_TAG}" = "${NVIDIA_DRIVER_TAG}" ]; then
    echo "==> Using cached NVIDIA source (tag ${NVIDIA_DRIVER_TAG})"
  else
    echo "==> NVIDIA source tag mismatch (have: ${EXISTING_TAG:-unknown}, want: ${NVIDIA_DRIVER_TAG}), re-cloning..."
    rm -rf "${NVIDIA_SRC}"
  fi
fi

if [ ! -d "${NVIDIA_SRC}" ]; then
  echo "==> Cloning NVIDIA open-gpu-kernel-modules (tag ${NVIDIA_DRIVER_TAG})..."
  git clone --depth 1 --branch "${NVIDIA_DRIVER_TAG}" \
    https://github.com/NVIDIA/open-gpu-kernel-modules.git "${NVIDIA_SRC}"
fi

# ── Build the kernel modules ─────────────────────────────────────────────

echo ""
echo "==> Compiling NVIDIA kernel modules (this may take 2-5 minutes)..."
make -C "${NVIDIA_SRC}" -j"$(nproc)" modules \
  SYSSRC="${KERNEL_SOURCES}" \
  KERNEL_UNAME="${KERNEL_VERSION}"

# ── Collect built modules ────────────────────────────────────────────────

mkdir -p "${OUTPUT_DIR}"

# The NVIDIA kbuild produces modules at deterministic paths under kernel-open/.
declare -A MODULE_PATHS=(
  [nvidia.ko]="kernel-open/nvidia.ko"
  [nvidia-uvm.ko]="kernel-open/nvidia-uvm.ko"
  [nvidia-modeset.ko]="kernel-open/nvidia-modeset.ko"
  [nvidia-drm.ko]="kernel-open/nvidia-drm.ko"
  [nvidia-peermem.ko]="kernel-open/nvidia-peermem.ko"
)

EXPECTED_MODULES=(nvidia.ko nvidia-uvm.ko nvidia-modeset.ko nvidia-drm.ko nvidia-peermem.ko)

for mod in "${EXPECTED_MODULES[@]}"; do
  src_path="${NVIDIA_SRC}/${MODULE_PATHS[$mod]}"
  if [ -f "$src_path" ]; then
    cp "$src_path" "${OUTPUT_DIR}/"
    echo "    Built: $mod ($(du -h "$src_path" | cut -f1))"
  fi
done

# Normalize permissions.
chmod 644 "${OUTPUT_DIR}"/*.ko 2>/dev/null || true

# nvidia-peermem.ko is optional (GPUDirect RDMA); the other four are required.
REQUIRED_MODULES=(nvidia.ko nvidia-uvm.ko nvidia-modeset.ko nvidia-drm.ko)
for mod in "${REQUIRED_MODULES[@]}"; do
  if [ ! -f "${OUTPUT_DIR}/${mod}" ]; then
    echo "ERROR: Required module ${mod} was not produced by the build." >&2
    echo "       Check build output above for compilation errors." >&2
    exit 1
  fi
done

echo ""
echo "==> NVIDIA modules ready at ${OUTPUT_DIR}"
ls -lah "${OUTPUT_DIR}/"*.ko

# Verify module vermagic matches the kernel.
echo ""
echo "==> Verifying module compatibility..."
if command -v modinfo &>/dev/null; then
  VERMAGIC="$(modinfo -F vermagic "${OUTPUT_DIR}/nvidia.ko" 2>/dev/null || true)"
  if [ -n "$VERMAGIC" ]; then
    echo "    vermagic: ${VERMAGIC}"
    if echo "$VERMAGIC" | grep -q "^${KERNEL_VERSION} "; then
      echo "    OK: modules match kernel ${KERNEL_VERSION}"
    else
      echo "    ERROR: vermagic does not start with ${KERNEL_VERSION}" >&2
      echo "           Modules will fail to load in the VM." >&2
      exit 1
    fi
  fi
fi
