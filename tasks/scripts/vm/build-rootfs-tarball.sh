#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build rootfs and compress to tarball for embedding in openshell-vm binary.
#
# This script:
# 1. Builds the rootfs using build-rootfs.sh
# 2. Compresses it to a zstd tarball for embedding
#
# Usage:
#   ./build-rootfs-tarball.sh [--base|--gpu|--gpu-cuda]
#
# Options:
#   --base      Build a base rootfs (~200-300MB) without pre-loaded images.
#               First boot will be slower but binary size is much smaller.
#               Default: full rootfs with pre-loaded images (~2GB+).
#   --gpu       Build a GPU-augmented rootfs that layers kmod, nvidia kernel
#               modules, and nvidia firmware on top of the base rootfs.
#               Output: target/vm-runtime-compressed/rootfs-gpu.tar.zst
#   --gpu-cuda  Like --gpu but also includes CUDA driver libraries
#               (libcuda.so, libnvidia-ptxjitcompiler.so) for CUDA workloads.
#
# The resulting tarball is placed at target/vm-runtime-compressed/rootfs.tar.zst
# (or rootfs-gpu.tar.zst for --gpu) for inclusion in the embedded binary build.

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/container-engine.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROOTFS_BUILD_DIR="${ROOT}/target/rootfs-build"
OUTPUT_DIR="${ROOT}/target/vm-runtime-compressed"
OUTPUT="${OUTPUT_DIR}/rootfs.tar.zst"

KERNEL_VERSION="6.12.76"
NVIDIA_MODULES_DIR="${ROOT}/target/libkrun-build/nvidia-modules"
NVIDIA_USERSPACE_DIR="${ROOT}/target/libkrun-build/nvidia-userspace"

# Parse arguments
BASE_ONLY=false
GPU_BUILD=false
GPU_CUDA=false
for arg in "$@"; do
    case "$arg" in
        --base)
            BASE_ONLY=true
            ;;
        --gpu)
            GPU_BUILD=true
            ;;
        --gpu-cuda)
            GPU_CUDA=true
            GPU_BUILD=true
            ;;
        --help|-h)
            echo "Usage: $0 [--base|--gpu|--gpu-cuda]"
            echo ""
            echo "Options:"
            echo "  --base       Build base rootfs (~200-300MB) without pre-loaded images"
            echo "               First boot will be slower but binary size is much smaller"
            echo "  --gpu        Build GPU rootfs with kmod, nvidia modules, and firmware"
            echo "               Layers on top of base rootfs, output: rootfs-gpu.tar.zst"
            echo "  --gpu-cuda   Like --gpu but also includes CUDA driver libraries"
            echo "               (libcuda.so, libnvidia-ptxjitcompiler.so)"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

if [ "$GPU_BUILD" = true ]; then
    GPU_OUTPUT="${OUTPUT_DIR}/rootfs-gpu.tar.zst"
    GPU_ROOTFS_DIR="${ROOT}/target/rootfs-gpu-build"
    trap 'echo "ERROR: GPU rootfs build failed; cleaning up ${GPU_ROOTFS_DIR}" >&2; rm -rf "${GPU_ROOTFS_DIR}"' ERR

    echo "==> Building GPU rootfs for embedding"
    echo "    Build dir: ${GPU_ROOTFS_DIR}"
    echo "    Output:    ${GPU_OUTPUT}"
    echo ""

    # Build base rootfs first if it doesn't exist
    if [ ! -d "${ROOTFS_BUILD_DIR}" ]; then
        echo "==> Step 1/3: Base rootfs not found, building it first..."
        "${ROOT}/crates/openshell-vm/scripts/build-rootfs.sh" --base "${ROOTFS_BUILD_DIR}"
        echo ""
    fi

    echo "==> Step 2/3: Layering GPU tools onto base rootfs..."

    rm -rf "${GPU_ROOTFS_DIR}"
    cp -a "${ROOTFS_BUILD_DIR}" "${GPU_ROOTFS_DIR}"

    # --- kmod ---
    KMOD_BIN="$(command -v kmod 2>/dev/null || true)"
    if [ -z "${KMOD_BIN}" ]; then
        echo "WARNING: kmod not found on host; skipping kmod installation"
    else
        echo "    Installing kmod from ${KMOD_BIN}"
        mkdir -p "${GPU_ROOTFS_DIR}/bin"
        cp "${KMOD_BIN}" "${GPU_ROOTFS_DIR}/bin/kmod"
        chmod 755 "${GPU_ROOTFS_DIR}/bin/kmod"

        # Copy shared libraries required by kmod (host and guest must share compatible glibc)
        if command -v ldd &>/dev/null; then
            mkdir -p "${GPU_ROOTFS_DIR}/lib" "${GPU_ROOTFS_DIR}/lib64"
            ldd "${KMOD_BIN}" 2>/dev/null | while read -r line; do
                lib_path="$(echo "${line}" | sed -n 's/.* => \(\/[^ ]*\).*/\1/p')"
                if [ -n "${lib_path}" ] && [ -f "${lib_path}" ]; then
                    # Skip core system libraries that already exist in the base rootfs.
                    # The host glibc may be older and overwriting breaks rootfs binaries.
                    lib_basename="$(basename "${lib_path}")"
                    case "${lib_basename}" in
                        libc.so*|libm.so*|libpthread.so*|libdl.so*|librt.so*|ld-linux*) continue ;;
                    esac
                    lib_dir="$(dirname "${lib_path}")"
                    mkdir -p "${GPU_ROOTFS_DIR}${lib_dir}"
                    cp -Lf "${lib_path}" "${GPU_ROOTFS_DIR}${lib_path}" 2>/dev/null || true
                fi
            done
        fi

        # Fix broken .so symlinks left by Docker export (e.g. libzstd.so.1.5.5 -> itself).
        # These cause ELOOP when the dynamic linker resolves the SONAME chain.
        # Use -xtype l to find symlinks whose targets are missing or circular.
        find "${GPU_ROOTFS_DIR}" -xtype l -name '*.so*' 2>/dev/null | while read -r broken; do
            sobase="$(basename "$broken" | sed 's/\.so.*/\.so/')"
            host_real="$(find /usr/lib /lib -name "${sobase}*" -type f 2>/dev/null | head -1)"
            if [ -n "$host_real" ]; then
                rm -f "$broken"
                cp -L "$host_real" "$broken" 2>/dev/null || true
            fi
        done || true

        mkdir -p "${GPU_ROOTFS_DIR}/usr/sbin"
        for tool in modprobe insmod rmmod lsmod depmod; do
            ln -sf ../../bin/kmod "${GPU_ROOTFS_DIR}/usr/sbin/${tool}"
        done
        echo "    Created symlinks: modprobe insmod rmmod lsmod depmod -> ../../bin/kmod"
    fi

    # --- nvidia kernel modules ---
    MODULES_DST="${GPU_ROOTFS_DIR}/lib/modules/${KERNEL_VERSION}/kernel/drivers/video"
    if [ -d "${NVIDIA_MODULES_DIR}" ]; then
        ko_files=("${NVIDIA_MODULES_DIR}"/*.ko)
        if [ -e "${ko_files[0]}" ]; then
            mkdir -p "${MODULES_DST}"
            cp "${NVIDIA_MODULES_DIR}"/*.ko "${MODULES_DST}/"
            echo "    Installed nvidia kernel modules into lib/modules/${KERNEL_VERSION}/kernel/drivers/video/"
            ls -1 "${MODULES_DST}"/*.ko | xargs -I{} basename {} | sed 's/^/      /'
            if command -v depmod &>/dev/null; then
                depmod -b "${GPU_ROOTFS_DIR}" "${KERNEL_VERSION}" 2>/dev/null || true
                echo "    Generated modules.dep"
            fi
        else
            echo "WARNING: ${NVIDIA_MODULES_DIR} exists but contains no .ko files"
        fi
    else
        echo "WARNING: nvidia kernel modules not found at ${NVIDIA_MODULES_DIR}"
        echo "         GPU rootfs will not contain nvidia drivers"
    fi

    # Determine the kernel module driver version so we can match firmware + userspace.
    NV_DRIVER_VERSION=""
    if command -v modinfo &>/dev/null && [ -f "${NVIDIA_MODULES_DIR}/nvidia.ko" ]; then
        NV_DRIVER_VERSION="$(modinfo -F version "${NVIDIA_MODULES_DIR}/nvidia.ko" 2>/dev/null || true)"
    fi
    if [ -n "${NV_DRIVER_VERSION}" ]; then
        echo "    Kernel module driver version: ${NV_DRIVER_VERSION}"
    fi

    # --- nvidia firmware (GSP) ---
    # Prefer version-matched firmware from nvidia-firmware/ directory.
    # Fall back to host /lib/firmware/nvidia if version-matched is unavailable.
    rm -rf "${GPU_ROOTFS_DIR}/lib/firmware/nvidia" 2>/dev/null || true
    NVIDIA_FW_MATCHED_DIR="${ROOT}/target/libkrun-build/nvidia-firmware/${NV_DRIVER_VERSION}"
    FW_DST="${GPU_ROOTFS_DIR}/lib/firmware/nvidia/${NV_DRIVER_VERSION}"
    if [ -n "${NV_DRIVER_VERSION}" ] && [ -d "${NVIDIA_FW_MATCHED_DIR}" ]; then
        mkdir -p "${FW_DST}"
        cp "${NVIDIA_FW_MATCHED_DIR}"/*.bin "${FW_DST}/" 2>/dev/null || true
        echo "    Installed nvidia firmware from ${NVIDIA_FW_MATCHED_DIR} (version-matched)"
    else
        HOST_FW_DIR=""
        for candidate in /lib/firmware/nvidia /usr/lib/firmware/nvidia; do
            if [ -d "${candidate}" ]; then
                HOST_FW_DIR="${candidate}"
                break
            fi
        done
        if [ -n "${HOST_FW_DIR}" ]; then
            mkdir -p "${GPU_ROOTFS_DIR}/lib/firmware/nvidia"
            cp -r "${HOST_FW_DIR}"/* "${GPU_ROOTFS_DIR}/lib/firmware/nvidia/" 2>/dev/null || true
            echo "    Installed nvidia firmware from ${HOST_FW_DIR}"
            if [ -n "${NV_DRIVER_VERSION}" ]; then
                echo "    WARNING: host firmware version may not match kernel module version ${NV_DRIVER_VERSION}"
            fi
        else
            echo "WARNING: nvidia firmware not found"
            echo "         GPU guests may fail to initialize the GPU without GSP firmware"
        fi
    fi

    # --- nvidia userspace (nvidia-smi + NVML) ---

    # Remove any pre-existing nvidia userspace from the base rootfs to avoid
    # version conflicts. The base image may ship nvidia-smi and libs from a
    # different driver version than the kernel modules we're installing.
    for search_dir in "${GPU_ROOTFS_DIR}/usr/lib/x86_64-linux-gnu" \
                      "${GPU_ROOTFS_DIR}/usr/lib64" \
                      "${GPU_ROOTFS_DIR}/usr/lib"; do
        rm -f "${search_dir}"/libnvidia-ml.so* 2>/dev/null || true
        rm -f "${search_dir}"/libcuda.so* 2>/dev/null || true
        rm -f "${search_dir}"/libnvidia-ptxjitcompiler.so* 2>/dev/null || true
    done
    rm -f "${GPU_ROOTFS_DIR}/usr/bin/nvidia-smi" 2>/dev/null || true
    echo "    Cleaned pre-existing nvidia userspace from base rootfs"

    # Prefer pre-extracted version-matched userspace from nvidia-userspace/.
    # Fall back to host binaries only if the pre-extracted ones don't exist.
    if [ -f "${NVIDIA_USERSPACE_DIR}/nvidia-smi" ]; then
        mkdir -p "${GPU_ROOTFS_DIR}/usr/bin"
        cp "${NVIDIA_USERSPACE_DIR}/nvidia-smi" "${GPU_ROOTFS_DIR}/usr/bin/nvidia-smi"
        chmod 755 "${GPU_ROOTFS_DIR}/usr/bin/nvidia-smi"
        echo "    Installed nvidia-smi from ${NVIDIA_USERSPACE_DIR} (version-matched)"
    else
        NV_SMI="$(command -v nvidia-smi 2>/dev/null || true)"
        if [ -n "${NV_SMI}" ]; then
            mkdir -p "${GPU_ROOTFS_DIR}/usr/bin"
            cp "${NV_SMI}" "${GPU_ROOTFS_DIR}/usr/bin/nvidia-smi"
            chmod 755 "${GPU_ROOTFS_DIR}/usr/bin/nvidia-smi"
            echo "    Installed nvidia-smi from host: ${NV_SMI}"
            echo "    WARNING: host nvidia-smi version may not match kernel module version ${NV_DRIVER_VERSION}"
        else
            echo "WARNING: nvidia-smi not found; GPU rootfs will use mknod fallback"
        fi
    fi

    # libnvidia-ml.so — required by nvidia-smi (dlopen'd at runtime)
    if [ -f "${NVIDIA_USERSPACE_DIR}/libnvidia-ml.so.${NV_DRIVER_VERSION}" ]; then
        NV_ML_REAL="${NVIDIA_USERSPACE_DIR}/libnvidia-ml.so.${NV_DRIVER_VERSION}"
        NV_LIB_DEST="${GPU_ROOTFS_DIR}/usr/lib/x86_64-linux-gnu"
        mkdir -p "${NV_LIB_DEST}"
        cp "${NV_ML_REAL}" "${NV_LIB_DEST}/libnvidia-ml.so.${NV_DRIVER_VERSION}"
        ln -sf "libnvidia-ml.so.${NV_DRIVER_VERSION}" "${NV_LIB_DEST}/libnvidia-ml.so.1"
        ln -sf libnvidia-ml.so.1 "${NV_LIB_DEST}/libnvidia-ml.so"
        echo "    Installed libnvidia-ml.so.${NV_DRIVER_VERSION} (version-matched)"
    else
        NV_ML_REAL=""
        for search_dir in /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib; do
            NV_ML_REAL="$(find "${search_dir}" -maxdepth 1 -name 'libnvidia-ml.so.*.*.*' -type f 2>/dev/null | head -1)"
            [ -n "${NV_ML_REAL}" ] && break
        done
        if [ -n "${NV_ML_REAL}" ]; then
            NV_LIB_DIR="$(dirname "${NV_ML_REAL}")"
            mkdir -p "${GPU_ROOTFS_DIR}${NV_LIB_DIR}"
            cp "${NV_ML_REAL}" "${GPU_ROOTFS_DIR}${NV_ML_REAL}"
            ln -sf "$(basename "${NV_ML_REAL}")" "${GPU_ROOTFS_DIR}${NV_LIB_DIR}/libnvidia-ml.so.1"
            ln -sf libnvidia-ml.so.1 "${GPU_ROOTFS_DIR}${NV_LIB_DIR}/libnvidia-ml.so"
            echo "    Installed libnvidia-ml.so from host: ${NV_ML_REAL}"
            echo "    WARNING: host library version may not match kernel module version ${NV_DRIVER_VERSION}"
        else
            echo "WARNING: libnvidia-ml.so not found; nvidia-smi may not work at runtime"
        fi
    fi

    # --- CUDA driver libraries (optional, via --gpu-cuda) ---
    if [ "${GPU_CUDA}" = true ]; then
        echo "    Installing CUDA driver libraries..."

        # libcuda.so
        if [ -f "${NVIDIA_USERSPACE_DIR}/libcuda.so.${NV_DRIVER_VERSION}" ]; then
            NV_LIB_DEST="${GPU_ROOTFS_DIR}/usr/lib/x86_64-linux-gnu"
            mkdir -p "${NV_LIB_DEST}"
            cp "${NVIDIA_USERSPACE_DIR}/libcuda.so.${NV_DRIVER_VERSION}" "${NV_LIB_DEST}/"
            ln -sf "libcuda.so.${NV_DRIVER_VERSION}" "${NV_LIB_DEST}/libcuda.so.1"
            ln -sf libcuda.so.1 "${NV_LIB_DEST}/libcuda.so"
            echo "    Installed libcuda.so.${NV_DRIVER_VERSION} (version-matched)"
        else
            CUDA_REAL=""
            for search_dir in /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib; do
                CUDA_REAL="$(find "${search_dir}" -maxdepth 1 -name 'libcuda.so.*.*.*' -type f 2>/dev/null | head -1)"
                [ -n "${CUDA_REAL}" ] && break
            done
            if [ -n "${CUDA_REAL}" ]; then
                CUDA_LIB_DIR="$(dirname "${CUDA_REAL}")"
                mkdir -p "${GPU_ROOTFS_DIR}${CUDA_LIB_DIR}"
                cp "${CUDA_REAL}" "${GPU_ROOTFS_DIR}${CUDA_REAL}"
                ln -sf "$(basename "${CUDA_REAL}")" "${GPU_ROOTFS_DIR}${CUDA_LIB_DIR}/libcuda.so.1"
                ln -sf libcuda.so.1 "${GPU_ROOTFS_DIR}${CUDA_LIB_DIR}/libcuda.so"
                echo "    Installed libcuda.so from host: ${CUDA_REAL}"
                echo "    WARNING: host library version may not match kernel module version ${NV_DRIVER_VERSION}"
            else
                echo "WARNING: libcuda.so not found; CUDA workloads will not work"
            fi
        fi

        # libnvidia-ptxjitcompiler.so
        if [ -f "${NVIDIA_USERSPACE_DIR}/libnvidia-ptxjitcompiler.so.${NV_DRIVER_VERSION}" ]; then
            NV_LIB_DEST="${GPU_ROOTFS_DIR}/usr/lib/x86_64-linux-gnu"
            mkdir -p "${NV_LIB_DEST}"
            cp "${NVIDIA_USERSPACE_DIR}/libnvidia-ptxjitcompiler.so.${NV_DRIVER_VERSION}" "${NV_LIB_DEST}/"
            ln -sf "libnvidia-ptxjitcompiler.so.${NV_DRIVER_VERSION}" "${NV_LIB_DEST}/libnvidia-ptxjitcompiler.so.1"
            ln -sf libnvidia-ptxjitcompiler.so.1 "${NV_LIB_DEST}/libnvidia-ptxjitcompiler.so"
            echo "    Installed libnvidia-ptxjitcompiler.so.${NV_DRIVER_VERSION} (version-matched)"
        else
            PTX_REAL=""
            for search_dir in /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib; do
                PTX_REAL="$(find "${search_dir}" -maxdepth 1 -name 'libnvidia-ptxjitcompiler.so.*.*.*' -type f 2>/dev/null | head -1)"
                [ -n "${PTX_REAL}" ] && break
            done
            if [ -n "${PTX_REAL}" ]; then
                PTX_LIB_DIR="$(dirname "${PTX_REAL}")"
                mkdir -p "${GPU_ROOTFS_DIR}${PTX_LIB_DIR}"
                cp "${PTX_REAL}" "${GPU_ROOTFS_DIR}${PTX_REAL}"
                ln -sf "$(basename "${PTX_REAL}")" "${GPU_ROOTFS_DIR}${PTX_LIB_DIR}/libnvidia-ptxjitcompiler.so.1"
                ln -sf libnvidia-ptxjitcompiler.so.1 "${GPU_ROOTFS_DIR}${PTX_LIB_DIR}/libnvidia-ptxjitcompiler.so"
                echo "    Installed libnvidia-ptxjitcompiler.so from host: ${PTX_REAL}"
                echo "    WARNING: host library version may not match kernel module version ${NV_DRIVER_VERSION}"
            else
                echo "WARNING: libnvidia-ptxjitcompiler.so not found; PTX JIT may not work"
            fi
        fi
    fi

    # Ensure nvidia library path is in ld.so.conf for dlopen resolution
    mkdir -p "${GPU_ROOTFS_DIR}/etc/ld.so.conf.d"
    echo "/usr/lib/x86_64-linux-gnu" > "${GPU_ROOTFS_DIR}/etc/ld.so.conf.d/nvidia.conf"
    if command -v ldconfig &>/dev/null; then
        ldconfig -r "${GPU_ROOTFS_DIR}" 2>/dev/null || true
    fi

    echo ""
    echo "==> Step 3/3: Compressing GPU rootfs to tarball..."
    mkdir -p "${OUTPUT_DIR}"
    rm -f "${GPU_OUTPUT}"

    echo "    Uncompressed size: $(du -sh "${GPU_ROOTFS_DIR}" | cut -f1)"
    echo "    Compressing with zstd (level 3)..."
    tar -C "${GPU_ROOTFS_DIR}" -cf - . | zstd -3 -T0 -o "${GPU_OUTPUT}"

    echo ""
    echo "==> GPU rootfs tarball created successfully!"
    echo "    Output:     ${GPU_OUTPUT}"
    echo "    Compressed: $(du -sh "${GPU_OUTPUT}" | cut -f1)"
    echo "    Type:       gpu (kmod + nvidia modules + firmware)"
    echo ""
    echo "Next step: mise run vm:build"
    trap - ERR
    exit 0
fi

# Check if container engine is running
if ! ce info &>/dev/null; then
    echo "Error: container engine is not running" >&2
    echo "Please start your container engine and try again" >&2
    exit 1
fi

if [ "$BASE_ONLY" = true ]; then
    echo "==> Building BASE rootfs for embedding"
    echo "    Build dir: ${ROOTFS_BUILD_DIR}"
    echo "    Output:    ${OUTPUT}"
    echo "    Mode:      base (no pre-loaded images, ~200-300MB)"
    echo ""
    
    echo "==> Step 1/2: Building base rootfs..."
    "${ROOT}/crates/openshell-vm/scripts/build-rootfs.sh" --base "${ROOTFS_BUILD_DIR}"
else
    echo "==> Building FULL rootfs for embedding"
    echo "    Build dir: ${ROOTFS_BUILD_DIR}"
    echo "    Output:    ${OUTPUT}"
    echo "    Mode:      full (pre-loaded images, pre-initialized, ~2GB+)"
    echo ""
    
    echo "==> Step 1/2: Building full rootfs (this may take 10-15 minutes)..."
    "${ROOT}/crates/openshell-vm/scripts/build-rootfs.sh" "${ROOTFS_BUILD_DIR}"
fi

echo ""
echo "==> Step 2/2: Compressing rootfs to tarball..."
mkdir -p "${OUTPUT_DIR}"

rm -f "${OUTPUT}"

echo "    Uncompressed size: $(du -sh "${ROOTFS_BUILD_DIR}" | cut -f1)"

# -19 = high compression (slower but smaller)
# -T0 = use all available threads
echo "    Compressing with zstd (level 19, this may take a few minutes)..."
tar -C "${ROOTFS_BUILD_DIR}" -cf - . | zstd -19 -T0 -o "${OUTPUT}"

echo ""
echo "==> Rootfs tarball created successfully!"
echo "    Output:     ${OUTPUT}"
echo "    Compressed: $(du -sh "${OUTPUT}" | cut -f1)"
if [ "$BASE_ONLY" = true ]; then
    echo "    Type:       base (first boot ~30-60s, images pulled on demand)"
else
    echo "    Type:       full (first boot ~3-5s, images pre-loaded)"
fi
echo ""
echo "Next step: mise run vm:build"
