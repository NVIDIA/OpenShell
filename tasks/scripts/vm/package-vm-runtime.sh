#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Package VM runtime artifacts into a release tarball.
#
# Used by CI (release-vm-kernel.yml) to bundle libkrun, libkrunfw, and gvproxy
# into a platform-specific tarball for the vm-dev GitHub Release. Handles
# gvproxy download, provenance metadata generation, and tarball creation.
#
# Usage:
#   ./package-vm-runtime.sh --platform <PLATFORM> --build-dir <DIR> --output <FILE>
#
# Arguments:
#   --platform    One of: linux-aarch64, linux-x86_64, darwin-aarch64
#   --build-dir   Directory containing built libkrun and libkrunfw artifacts
#   --output      Path for the output .tar.zst file
#
# Environment (optional, for provenance):
#   GITHUB_SHA      - Git commit SHA
#   GITHUB_RUN_ID   - GitHub Actions run ID
#   CUSTOM_PROVENANCE_DIR - Directory containing provenance.json from custom
#                           libkrunfw build (macOS only)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

# Source pins for gvproxy version
source "${ROOT}/crates/openshell-vm/pins.env" 2>/dev/null || true
GVPROXY_VERSION="${GVPROXY_VERSION:-v0.8.8}"

PLATFORM=""
BUILD_DIR=""
OUTPUT=""
CUSTOM_PROVENANCE_DIR="${CUSTOM_PROVENANCE_DIR:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform)     PLATFORM="$2"; shift 2 ;;
        --build-dir)    BUILD_DIR="$2"; shift 2 ;;
        --output)       OUTPUT="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 --platform <PLATFORM> --build-dir <DIR> --output <FILE>"
            echo ""
            echo "Package VM runtime artifacts into a release tarball."
            echo ""
            echo "Platforms: linux-aarch64, linux-x86_64, darwin-aarch64"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$PLATFORM" ] || [ -z "$BUILD_DIR" ] || [ -z "$OUTPUT" ]; then
    echo "Error: --platform, --build-dir, and --output are all required" >&2
    exit 1
fi

echo "==> Packaging VM runtime"
echo "    Platform:  ${PLATFORM}"
echo "    Build dir: ${BUILD_DIR}"
echo "    Output:    ${OUTPUT}"
echo ""

# ── Create staging directory ────────────────────────────────────────────

PACKAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$PACKAGE_DIR"' EXIT

# ── Copy runtime libraries ──────────────────────────────────────────────

case "$PLATFORM" in
    linux-*)
        cp "${BUILD_DIR}/libkrun.so" "${PACKAGE_DIR}/"
        # Copy libkrunfw — find versioned .so and create soname symlink
        for f in "${BUILD_DIR}"/libkrunfw.so*; do
            [ -f "$f" ] && cp "$f" "${PACKAGE_DIR}/"
        done
        if [ ! -f "${PACKAGE_DIR}/libkrunfw.so.5" ]; then
            versioned="$(ls "${PACKAGE_DIR}"/libkrunfw.so.5.* 2>/dev/null | head -n1 || true)"
            [ -n "$versioned" ] && cp "$versioned" "${PACKAGE_DIR}/libkrunfw.so.5"
        fi
        ;;
    darwin-aarch64)
        cp "${BUILD_DIR}/libkrun.dylib" "${PACKAGE_DIR}/"
        # libkrunfw — prefer build dir, fall back to custom runtime dir
        candidates=("${BUILD_DIR}/libkrunfw.dylib" "${BUILD_DIR}/libkrunfw.5.dylib")
        if [ -n "$CUSTOM_PROVENANCE_DIR" ]; then
            candidates+=("${CUSTOM_PROVENANCE_DIR}/libkrunfw.dylib" "${CUSTOM_PROVENANCE_DIR}/libkrunfw.5.dylib")
        fi
        for candidate in "${candidates[@]}"; do
            if [ -f "$candidate" ]; then
                cp "$candidate" "${PACKAGE_DIR}/"
            fi
        done
        ;;
    *)
        echo "Error: Unknown platform: ${PLATFORM}" >&2
        exit 1
        ;;
esac

# ── Download gvproxy ────────────────────────────────────────────────────

echo "==> Downloading gvproxy ${GVPROXY_VERSION} for ${PLATFORM}..."
case "$PLATFORM" in
    linux-aarch64)  GVPROXY_SUFFIX="linux-arm64" ;;
    linux-x86_64)   GVPROXY_SUFFIX="linux-amd64" ;;
    darwin-aarch64)  GVPROXY_SUFFIX="darwin" ;;
esac

curl -fsSL -o "${PACKAGE_DIR}/gvproxy" \
    "https://github.com/containers/gvisor-tap-vsock/releases/download/${GVPROXY_VERSION}/gvproxy-${GVPROXY_SUFFIX}"
chmod +x "${PACKAGE_DIR}/gvproxy"

# ── Write provenance metadata ───────────────────────────────────────────

echo "==> Writing provenance metadata..."

LIBKRUNFW_COMMIT="unknown"
KERNEL_VERSION="unknown"

# Try custom provenance first (macOS builds produce this)
if [ -n "$CUSTOM_PROVENANCE_DIR" ] && [ -f "${CUSTOM_PROVENANCE_DIR}/provenance.json" ]; then
    LIBKRUNFW_COMMIT="$(jq -r '.libkrunfw_commit // "unknown"' "${CUSTOM_PROVENANCE_DIR}/provenance.json" 2>/dev/null || echo unknown)"
    KERNEL_VERSION="$(jq -r '.kernel_version // "unknown"' "${CUSTOM_PROVENANCE_DIR}/provenance.json" 2>/dev/null || echo unknown)"
fi

# Fall back to inspecting the build directory (Linux builds)
if [ "$LIBKRUNFW_COMMIT" = "unknown" ] && [ -d "${BUILD_DIR}/libkrunfw/.git" ]; then
    LIBKRUNFW_COMMIT="$(git -C "${BUILD_DIR}/libkrunfw" rev-parse HEAD 2>/dev/null || echo unknown)"
fi
if [ "$KERNEL_VERSION" = "unknown" ] && [ -f "${BUILD_DIR}/libkrunfw/Makefile" ]; then
    KERNEL_VERSION="$(grep -oE 'KERNEL_VERSION\s*=\s*linux-[^\s]+' "${BUILD_DIR}/libkrunfw/Makefile" | head -1 | sed 's/.*= *//' || echo unknown)"
fi

if ! command -v jq &>/dev/null; then
    echo "Error: jq is required for provenance generation" >&2
    exit 1
fi

jq -n \
    --arg artifact "vm-runtime" \
    --arg platform "$PLATFORM" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg kfw_commit "$LIBKRUNFW_COMMIT" \
    --arg kver "$KERNEL_VERSION" \
    --arg sha "${GITHUB_SHA:-unknown}" \
    --arg run "${GITHUB_RUN_ID:-unknown}" \
    '{artifact: $artifact, platform: $platform, build_timestamp: $ts, libkrunfw_commit: $kfw_commit, kernel_version: $kver, github_sha: $sha, github_run_id: $run}' \
    > "${PACKAGE_DIR}/provenance.json"

# ── Create tarball ──────────────────────────────────────────────────────

echo "==> Creating tarball..."
mkdir -p "$(dirname "$OUTPUT")"
tar -C "${PACKAGE_DIR}" -cf - . | zstd -19 -T0 -o "$OUTPUT"

echo ""
echo "==> Packaged ${OUTPUT} ($(du -sh "$OUTPUT" | cut -f1))"
echo "    Contents:"
ls -lah "${PACKAGE_DIR}"
