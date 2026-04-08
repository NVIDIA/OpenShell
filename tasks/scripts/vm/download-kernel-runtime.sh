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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

RELEASE_TAG="${VM_RUNTIME_RELEASE_TAG:-vm-dev}"
REPO="${GITHUB_REPOSITORY:-NVIDIA/OpenShell}"
OUTPUT_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${ROOT}/target/vm-runtime-compressed}"

# ── Auto-detect platform (detect_platform from _lib.sh) ─────────────────

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
compress_dir "$EXTRACT_DIR" "$OUTPUT_DIR"

# ── Check for rootfs (may already be present from a separate build step) ──

if [ -f "${OUTPUT_DIR}/rootfs.tar.zst" ]; then
    echo ""
    echo "    rootfs.tar.zst: $(du -h "${OUTPUT_DIR}/rootfs.tar.zst" | cut -f1) (pre-existing)"
else
    echo ""
    echo "Note: rootfs.tar.zst not found in ${OUTPUT_DIR}."
    echo "      Build it with: mise run vm:rootfs -- --base"
fi

echo ""
echo "==> Staged artifacts in ${OUTPUT_DIR}:"
ls -lah "$OUTPUT_DIR"

echo ""
echo "==> Done."
echo ""
echo "Next step: mise run vm:build"
