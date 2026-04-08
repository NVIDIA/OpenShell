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
#   ./build-rootfs-tarball.sh [--base]
#
# Options:
#   --base      Build a base rootfs (~200-300MB) without pre-loaded images.
#               First boot will be slower but binary size is much smaller.
#               Default: full rootfs with pre-loaded images (~2GB+).
#
# The resulting tarball is placed at target/vm-runtime-compressed/rootfs.tar.zst
# for inclusion in the embedded binary build.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROOTFS_BUILD_DIR="${ROOT}/target/rootfs-build"
OUTPUT_DIR="${ROOT}/target/vm-runtime-compressed"
OUTPUT="${OUTPUT_DIR}/rootfs.tar.zst"

# Parse arguments
BASE_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --base)
            BASE_ONLY=true
            ;;
        --help|-h)
            echo "Usage: $0 [--base]"
            echo ""
            echo "Options:"
            echo "  --base   Build base rootfs (~200-300MB) without pre-loaded images"
            echo "           First boot will be slower but binary size is much smaller"
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

if [ "$BASE_ONLY" = true ]; then
    echo "==> Building BASE rootfs for embedding"
    echo "    Build dir: ${ROOTFS_BUILD_DIR}"
    echo "    Output:    ${OUTPUT}"
    echo "    Mode:      base (no pre-loaded images, ~200-300MB)"
    echo ""
    
    # Build base rootfs
    echo "==> Step 1/2: Building base rootfs..."
    "${ROOT}/crates/openshell-vm/scripts/build-rootfs.sh" --base "${ROOTFS_BUILD_DIR}"
else
    echo "==> Building FULL rootfs for embedding"
    echo "    Build dir: ${ROOTFS_BUILD_DIR}"
    echo "    Output:    ${OUTPUT}"
    echo "    Mode:      full (pre-loaded images, pre-initialized, ~2GB+)"
    echo ""
    
    # Build full rootfs
    echo "==> Step 1/2: Building full rootfs (this may take 10-15 minutes)..."
    "${ROOT}/crates/openshell-vm/scripts/build-rootfs.sh" "${ROOTFS_BUILD_DIR}"
fi

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
if [ "$BASE_ONLY" = true ]; then
    echo "    Type:       base (first boot ~30-60s, images pulled on demand)"
else
    echo "    Type:       full (first boot ~3-5s, images pre-loaded)"
fi
echo ""
echo "Next step: mise run vm:build"
