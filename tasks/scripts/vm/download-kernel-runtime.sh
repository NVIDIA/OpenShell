#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Download pre-built VM kernel runtime artifacts from the vm-dev GitHub Release
# and stage them for the openshell-vm cargo build.
#
# This script is used by CI (release-vm-dev.yml) and can also be used locally
# to avoid building libkrun/libkrunfw from source.
#
# Usage:
#   ./download-kernel-runtime.sh [--platform PLATFORM]
#
# Environment:
#   VM_RUNTIME_RELEASE_TAG  - GitHub Release tag (default: vm-dev)
#   GITHUB_REPOSITORY       - owner/repo (default: NVIDIA/OpenShell)
#   OPENSHELL_VM_RUNTIME_COMPRESSED_DIR - Output directory (default: target/vm-runtime-compressed)
#
# Platforms: linux-aarch64, linux-x86_64, darwin-aarch64

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

RELEASE_TAG="${VM_RUNTIME_RELEASE_TAG:-vm-dev}"
REPO="${GITHUB_REPOSITORY:-NVIDIA/OpenShell}"
OUTPUT_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${ROOT}/target/vm-runtime-compressed}"

# ── Auto-detect platform ────────────────────────────────────────────────

detect_platform() {
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64)   echo "darwin-aarch64" ;;
        Linux-aarch64)  echo "linux-aarch64" ;;
        Linux-x86_64)   echo "linux-x86_64" ;;
        *)
            echo "Error: Unsupported platform: $(uname -s)-$(uname -m)" >&2
            exit 1
            ;;
    esac
}

PLATFORM=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform)
            PLATFORM="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--platform PLATFORM]"
            echo ""
            echo "Download pre-built VM kernel runtime from the vm-dev GitHub Release."
            echo ""
            echo "Platforms: linux-aarch64, linux-x86_64, darwin-aarch64"
            echo ""
            echo "Environment:"
            echo "  VM_RUNTIME_RELEASE_TAG              Release tag (default: vm-dev)"
            echo "  GITHUB_REPOSITORY                   owner/repo (default: NVIDIA/OpenShell)"
            echo "  OPENSHELL_VM_RUNTIME_COMPRESSED_DIR Output directory"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$PLATFORM" ]; then
    PLATFORM="$(detect_platform)"
fi

TARBALL_NAME="vm-runtime-${PLATFORM}.tar.zst"

echo "==> Downloading VM kernel runtime"
echo "    Repository: ${REPO}"
echo "    Release:    ${RELEASE_TAG}"
echo "    Platform:   ${PLATFORM}"
echo "    Artifact:   ${TARBALL_NAME}"
echo "    Output:     ${OUTPUT_DIR}"
echo ""

# ── Check for gh CLI ────────────────────────────────────────────────────

if ! command -v gh &>/dev/null; then
    echo "Error: GitHub CLI (gh) is required." >&2
    echo "  Install: https://cli.github.com/" >&2
    exit 1
fi

# ── Download the runtime tarball ────────────────────────────────────────

DOWNLOAD_DIR="${ROOT}/target/vm-runtime-download"
mkdir -p "$DOWNLOAD_DIR" "$OUTPUT_DIR"

echo "==> Downloading ${TARBALL_NAME} from ${RELEASE_TAG}..."
gh release download "${RELEASE_TAG}" \
    --repo "${REPO}" \
    --pattern "${TARBALL_NAME}" \
    --dir "${DOWNLOAD_DIR}" \
    --clobber

if [ ! -f "${DOWNLOAD_DIR}/${TARBALL_NAME}" ]; then
    echo "Error: Download failed — ${TARBALL_NAME} not found." >&2
    echo "" >&2
    echo "The vm-dev release may not have kernel runtime artifacts yet." >&2
    echo "Run the 'Release VM Kernel' workflow first:" >&2
    echo "  gh workflow run release-vm-kernel.yml" >&2
    exit 1
fi

echo "    Downloaded: $(du -sh "${DOWNLOAD_DIR}/${TARBALL_NAME}" | cut -f1)"

# ── Extract and stage for cargo build ───────────────────────────────────

echo ""
echo "==> Extracting runtime artifacts..."

EXTRACT_DIR="${ROOT}/target/vm-runtime-extracted"
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"

zstd -d "${DOWNLOAD_DIR}/${TARBALL_NAME}" --stdout | tar -xf - -C "$EXTRACT_DIR"

echo "    Extracted files:"
ls -lah "$EXTRACT_DIR"

# ── Compress individual files for embedding ─────────────────────────────
# The cargo build expects individual .zst files (libkrun.so.zst, etc.)
# in OPENSHELL_VM_RUNTIME_COMPRESSED_DIR. The downloaded tarball contains
# the raw libraries, so we re-compress each one.

echo ""
echo "==> Compressing artifacts for embedding..."

for file in "$EXTRACT_DIR"/*; do
    [ -f "$file" ] || continue
    name=$(basename "$file")
    # Skip provenance.json — not embedded
    if [ "$name" = "provenance.json" ]; then
        cp "$file" "${OUTPUT_DIR}/"
        continue
    fi
    original_size=$(du -h "$file" | cut -f1)
    zstd -19 -f -q -T0 -o "${OUTPUT_DIR}/${name}.zst" "$file"
    chmod 644 "${OUTPUT_DIR}/${name}.zst"
    compressed_size=$(du -h "${OUTPUT_DIR}/${name}.zst" | cut -f1)
    echo "    ${name}: ${original_size} -> ${compressed_size}"
done

# ── Check for rootfs (may already be present from a separate build step) ──

if [ -f "${OUTPUT_DIR}/rootfs.tar.zst" ]; then
    echo ""
    echo "    rootfs.tar.zst: $(du -h "${OUTPUT_DIR}/rootfs.tar.zst" | cut -f1) (pre-existing)"
else
    echo ""
    echo "Note: rootfs.tar.zst not found in ${OUTPUT_DIR}."
    echo "      Build it with: mise run vm:build:rootfs-tarball"
fi

echo ""
echo "==> Staged artifacts in ${OUTPUT_DIR}:"
ls -lah "$OUTPUT_DIR"

echo ""
echo "==> Done. Set for cargo build:"
echo "  export OPENSHELL_VM_RUNTIME_COMPRESSED_DIR=${OUTPUT_DIR}"
