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
#   ./build-rootfs-tarball.sh [--base] [--gpu]
#
# Options:
#   --base      Build a base rootfs (~200-300MB) without pre-loaded images.
#               First boot will be slower but binary size is much smaller.
#               Default: full rootfs with pre-loaded images (~2GB+).
#   --gpu       Include NVIDIA drivers and nvidia-container-toolkit for GPU
#               passthrough. Only supported on x86_64.
#
# The resulting tarball is placed at:
#   target/vm-runtime-compressed/rootfs.tar.zst      (standard)
#   target/vm-runtime-compressed/rootfs-gpu.tar.zst   (--gpu)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROOTFS_BUILD_DIR="${ROOT}/target/rootfs-build"
OUTPUT_DIR="${ROOT}/target/vm-runtime-compressed"

# Parse arguments
BASE_ONLY=false
GPU=false
for arg in "$@"; do
    case "$arg" in
        --base)
            BASE_ONLY=true
            ;;
        --gpu)
            GPU=true
            ;;
        --help|-h)
            echo "Usage: $0 [--base] [--gpu]"
            echo ""
            echo "Options:"
            echo "  --base   Build base rootfs (~200-300MB) without pre-loaded images"
            echo "           First boot will be slower but binary size is much smaller"
            echo "  --gpu    Include NVIDIA drivers for GPU passthrough (x86_64 only)"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check for Docker
if ! command -v docker &>/dev/null; then
    echo "Error: Docker is required to build the rootfs" >&2
    echo "Please install Docker and try again" >&2
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &>/dev/null; then
    echo "Error: Docker daemon is not running" >&2
    echo "Please start Docker and try again" >&2
    exit 1
fi

ROOTFS_ARGS=()
MODE_DESC="full (pre-loaded images, pre-initialized, ~2GB+)"
if [ "$BASE_ONLY" = true ]; then
    ROOTFS_ARGS+=(--base)
    MODE_DESC="base (no pre-loaded images, ~200-300MB)"
fi
if [ "$GPU" = true ]; then
    ROOTFS_ARGS+=(--gpu)
    MODE_DESC="${MODE_DESC}, GPU (NVIDIA drivers included)"
fi

# GPU rootfs gets a distinct tarball name so both can coexist in the output dir
if [ "$GPU" = true ]; then
    OUTPUT="${OUTPUT_DIR}/rootfs-gpu.tar.zst"
else
    OUTPUT="${OUTPUT_DIR}/rootfs.tar.zst"
fi

echo "==> Building rootfs for embedding"
echo "    Build dir: ${ROOTFS_BUILD_DIR}"
echo "    Output:    ${OUTPUT}"
echo "    Mode:      ${MODE_DESC}"
echo ""

echo "==> Step 1/2: Building rootfs..."
"${ROOT}/crates/openshell-vm/scripts/build-rootfs.sh" "${ROOTFS_ARGS[@]}" "${ROOTFS_BUILD_DIR}"

# Compress to tarball
echo ""
echo "==> Step 2/2: Compressing rootfs to tarball..."
mkdir -p "${OUTPUT_DIR}"

# Remove existing tarball if present
rm -f "${OUTPUT}"

# Get uncompressed size for display
echo "    Uncompressed size: $(du -sh "${ROOTFS_BUILD_DIR}" | cut -f1)"

# Create tarball with zstd compression
# -19 = high compression (slower but smaller)
# -T0 = use all available threads
echo "    Compressing with zstd (level 19, this may take a few minutes)..."
tar -C "${ROOTFS_BUILD_DIR}" -cf - . | zstd -19 -T0 -o "${OUTPUT}"

# Report results
echo ""
echo "==> Rootfs tarball created successfully!"
echo "    Output:     ${OUTPUT}"
echo "    Compressed: $(du -sh "${OUTPUT}" | cut -f1)"
TYPE_DESC="full (first boot ~3-5s, images pre-loaded)"
if [ "$BASE_ONLY" = true ]; then
    TYPE_DESC="base (first boot ~30-60s, images pulled on demand)"
fi
if [ "$GPU" = true ]; then
    TYPE_DESC="${TYPE_DESC}, GPU"
fi
echo "    Type:       ${TYPE_DESC}"
echo ""
echo "Next step: mise run vm:build"
