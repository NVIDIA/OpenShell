#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build NVIDIA kernel modules against the libkrunfw guest kernel.
#
# Uses the NVIDIA DKMS source already installed on the host (from the
# nvidia-dkms-* or nvidia-kernel-source-* package) and compiles it
# against the guest kernel tree produced by build-libkrun.sh.
#
# Prerequisites:
#   - NVIDIA kernel source in /usr/src/nvidia-*/
#   - Guest kernel built with CONFIG_MODULES=y (mise run vm:setup)
#
# Output:
#   target/libkrun-build/nvidia-modules/*.ko
#   target/libkrun-build/nvidia-firmware/<version>/*.bin (if available)
#
# Usage:
#   ./build-nvidia-modules.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUILD_DIR="${ROOT}/target/libkrun-build"
OUTPUT_DIR="${BUILD_DIR}/nvidia-modules"

# Guest kernel version — keep in sync with GUEST_KERNEL_VERSION in
# crates/openshell-driver-vm/src/rootfs.rs and the init script.
KERNEL_TREE="${BUILD_DIR}/libkrunfw/linux-6.12.76"
if [ ! -d "${KERNEL_TREE}" ]; then
    echo "ERROR: Guest kernel tree not found at ${KERNEL_TREE}" >&2
    echo "       Run: mise run vm:setup" >&2
    exit 1
fi

if ! grep -q 'CONFIG_MODULES=y' "${KERNEL_TREE}/.config" 2>/dev/null; then
    echo "ERROR: Guest kernel was built without CONFIG_MODULES=y" >&2
    echo "       Ensure openshell.kconfig includes CONFIG_MODULES=y and rebuild:" >&2
    echo "       mise run vm:setup" >&2
    exit 1
fi

if [ ! -f "${KERNEL_TREE}/Module.symvers" ]; then
    echo "ERROR: Module.symvers not found — the kernel needs to be rebuilt" >&2
    echo "       with CONFIG_MODULES=y so the build produces Module.symvers." >&2
    echo "       Run: mise run vm:setup" >&2
    exit 1
fi

# Detect the host NVIDIA driver version to pick a compatible module source.
HOST_DRIVER_VERSION="${NVIDIA_DRIVER_VERSION:-}"
if [ -z "${HOST_DRIVER_VERSION}" ]; then
    HOST_DRIVER_VERSION="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null || true)"
fi
if [ -z "${HOST_DRIVER_VERSION}" ]; then
    HOST_DRIVER_VERSION="$(modinfo -F version /lib/modules/$(uname -r)/updates/dkms/nvidia.ko 2>/dev/null || true)"
fi

# Use the open-gpu-kernel-modules release matching the host driver major
# version. The open modules support newer kernels better than the
# proprietary DKMS source shipped in /usr/src/.
# Must match NVIDIA_DRIVER_VERSION in sandboxes/nvidia-gpu/versions.env
# and sandboxes/nvidia-gpu/Dockerfile ARG NVIDIA_DRIVER_VERSION
NVIDIA_OPEN_VERSION="${NVIDIA_OPEN_VERSION:-580.159.03}"
NVIDIA_SRC_DIR="${BUILD_DIR}/open-gpu-kernel-modules-${NVIDIA_OPEN_VERSION}"

if [ ! -d "${NVIDIA_SRC_DIR}/kernel-open" ]; then
    echo "==> Downloading NVIDIA open kernel modules ${NVIDIA_OPEN_VERSION}"
    TARBALL="${BUILD_DIR}/nvidia-open-${NVIDIA_OPEN_VERSION}.tar.gz"
    if [ ! -f "${TARBALL}" ]; then
        curl -fSL \
            "https://github.com/NVIDIA/open-gpu-kernel-modules/archive/refs/tags/${NVIDIA_OPEN_VERSION}.tar.gz" \
            -o "${TARBALL}"
        # TODO(gpu): Add SHA-256 verification for supply chain integrity.
        # echo "<expected-hash>  ${TARBALL}" | sha256sum -c -
    fi
    echo "    Extracting..."
    tar -xzf "${TARBALL}" -C "${BUILD_DIR}"
    echo "    Source: ${NVIDIA_SRC_DIR}"
fi

NVIDIA_SRC="${NVIDIA_SRC_DIR}"

# Patch API incompatibilities with newer kernels.
# __flush_tlb() was removed in kernel 6.12; use __flush_tlb_all() instead.
NV_PAT="${NVIDIA_SRC}/kernel-open/nvidia/nv-pat.c"
if [ -f "${NV_PAT}" ] && grep -q '__flush_tlb()' "${NV_PAT}"; then
    echo "==> Patching nv-pat.c (__flush_tlb -> __flush_tlb_all)"
    sed -i 's/__flush_tlb()/__flush_tlb_all()/g' "${NV_PAT}"
fi

echo "==> Building NVIDIA ${NVIDIA_OPEN_VERSION} open kernel modules for guest kernel 6.12.76"
echo "    NVIDIA source: ${NVIDIA_SRC}"
echo "    Kernel tree:   ${KERNEL_TREE}"
echo "    Output:        ${OUTPUT_DIR}"
if [ -n "${HOST_DRIVER_VERSION}" ]; then
    echo "    Host driver:   ${HOST_DRIVER_VERSION}"
fi
echo ""

mkdir -p "${OUTPUT_DIR}"

NPROC="$(nproc 2>/dev/null || echo 4)"
IGNORE_CC_MISMATCH=1 make -C "${NVIDIA_SRC}" \
    SYSSRC="${KERNEL_TREE}" \
    SYSOUT="${KERNEL_TREE}" \
    -j"${NPROC}" \
    modules 2>&1 | tail -30

echo ""
echo "==> Collecting .ko files"

# Open modules build into kernel-open/<subdir>/
for subdir in nvidia nvidia-uvm nvidia-modeset nvidia-drm nvidia-peermem; do
    for search in "${NVIDIA_SRC}/kernel-open/${subdir}" "${NVIDIA_SRC}/${subdir}"; do
        ko_file="${search}/${subdir//-/_}.ko"
        if [ -f "${ko_file}" ]; then
            cp "${ko_file}" "${OUTPUT_DIR}/"
            echo "    $(basename "${ko_file}") ($(du -h "${ko_file}" | cut -f1))"
            break
        fi
    done
done

# Also check for flat layouts.
for ko in "${NVIDIA_SRC}"/*.ko "${NVIDIA_SRC}"/kernel-open/*.ko; do
    [ -f "${ko}" ] || continue
    base="$(basename "${ko}")"
    [ -f "${OUTPUT_DIR}/${base}" ] && continue
    cp "${ko}" "${OUTPUT_DIR}/"
    echo "    ${base} ($(du -h "${ko}" | cut -f1))"
done

KO_COUNT=$(find "${OUTPUT_DIR}" -name '*.ko' | wc -l)
if [ "${KO_COUNT}" -eq 0 ]; then
    echo "ERROR: No .ko files produced. Check build output above." >&2
    exit 1
fi

echo ""
echo "==> Collecting firmware"

# GSP firmware is included in the open-gpu-kernel-modules source tree.
FW_SRC="${NVIDIA_SRC}/src/nvidia/firmware"
FW_OUTPUT="${BUILD_DIR}/nvidia-firmware/${NVIDIA_OPEN_VERSION}"
if [ -d "${FW_SRC}" ] && ls "${FW_SRC}"/*.bin >/dev/null 2>&1; then
    mkdir -p "${FW_OUTPUT}"
    cp "${FW_SRC}"/*.bin "${FW_OUTPUT}/"
    FW_COUNT=$(find "${FW_OUTPUT}" -name '*.bin' 2>/dev/null | wc -l)
    echo "    Copied ${FW_COUNT} firmware files from source tree"
else
    # Fall back to host firmware.
    HOST_FW=""
    for candidate in "/lib/firmware/nvidia/${HOST_DRIVER_VERSION}" /lib/firmware/nvidia; do
        if [ -d "${candidate}" ] && ls "${candidate}"/*.bin >/dev/null 2>&1; then
            HOST_FW="${candidate}"
            break
        fi
    done
    if [ -n "${HOST_FW}" ]; then
        mkdir -p "${FW_OUTPUT}"
        cp -r "${HOST_FW}"/* "${FW_OUTPUT}/" 2>/dev/null || true
        FW_COUNT=$(find "${FW_OUTPUT}" -name '*.bin' 2>/dev/null | wc -l)
        echo "    Copied ${FW_COUNT} firmware files from host ${HOST_FW}"
    else
        echo "    WARNING: No firmware found. GPU guests may fail without GSP firmware."
    fi
fi

echo ""
echo "==> Done! ${KO_COUNT} kernel modules built for guest kernel 6.12.76."
echo "    The VM driver will auto-discover them at:"
echo "    ${OUTPUT_DIR}"
echo ""
echo "    Next: mise run gateway:vm -- --gpu"
