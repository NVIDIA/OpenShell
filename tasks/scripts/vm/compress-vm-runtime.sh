#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Gather VM runtime artifacts from local sources and compress for embedding.
#
# This script collects libkrun, libkrunfw, and gvproxy from local sources
# (Homebrew on macOS, built from source on Linux) and compresses them with
# zstd for embedding into the openshell-vm binary.
#
# Usage:
#   ./compress-vm-runtime.sh
#
# Environment:
#   OPENSHELL_VM_RUNTIME_COMPRESSED_DIR - Output directory (default: target/vm-runtime-compressed)
#   VM_RUNTIME_TARBALL - Path to a pre-built vm-runtime-*.tar.zst tarball.
#                        When set, the script extracts and re-compresses
#                        artifacts from this tarball instead of looking for
#                        local builds.  Used by CI and download-kernel-runtime.sh.
#
# The script sets OPENSHELL_VM_RUNTIME_COMPRESSED_DIR for use by build.rs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

# Source pins for gvproxy version
source "${ROOT}/crates/openshell-vm/pins.env" 2>/dev/null || true
GVPROXY_VERSION="${GVPROXY_VERSION:-v0.8.8}"

# ── macOS dylib portability helpers ─────────────────────────────────────

# Make a dylib portable by rewriting paths to use @loader_path
make_dylib_portable() {
    local dylib="$1"
    local dylib_name
    dylib_name="$(basename "$dylib")"
    
    # Rewrite install name
    install_name_tool -id "@loader_path/${dylib_name}" "$dylib" 2>/dev/null || true
    
    # Rewrite libkrunfw reference if present
    local krunfw_path
    krunfw_path=$(otool -L "$dylib" 2>/dev/null | grep libkrunfw | awk '{print $1}' || true)
    if [ -n "$krunfw_path" ] && [[ "$krunfw_path" != @* ]]; then
        install_name_tool -change "$krunfw_path" "@loader_path/libkrunfw.dylib" "$dylib"
    fi
    
    # Re-codesign
    codesign -f -s - "$dylib" 2>/dev/null || true
}

WORK_DIR="${ROOT}/target/vm-runtime"
OUTPUT_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${ROOT}/target/vm-runtime-compressed}"

mkdir -p "$OUTPUT_DIR"

# ── Fast path: compressed artifacts already present (e.g. from vm:setup) ──

_check_compressed_artifacts() {
    local dir="$1"
    local platform
    platform="$(uname -s)-$(uname -m)"
    case "$platform" in
        Darwin-arm64)
            for f in libkrun.dylib.zst libkrunfw.5.dylib.zst gvproxy.zst; do
                [ -f "${dir}/${f}" ] || return 1
            done
            ;;
        Linux-*)
            for f in libkrun.so.zst libkrunfw.so.5.zst gvproxy.zst; do
                [ -f "${dir}/${f}" ] || return 1
            done
            ;;
        *) return 1 ;;
    esac
    return 0
}

if [ -z "${VM_RUNTIME_TARBALL:-}" ] && _check_compressed_artifacts "$OUTPUT_DIR"; then
    echo "==> Compressed artifacts already present in ${OUTPUT_DIR} — skipping compression."
    ls -lah "$OUTPUT_DIR"

    # Decompress artifacts into WORK_DIR so bundle-vm-runtime.sh can find them.
    echo ""
    echo "==> Decompressing artifacts into ${WORK_DIR} for runtime bundle..."
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"
    for f in "${OUTPUT_DIR}"/*.zst; do
        [ -f "$f" ] || continue
        [ -s "$f" ] || continue
        name="$(basename "${f%.zst}")"
        [[ "$name" == rootfs*.tar ]] && continue
        zstd -d "$f" -o "${WORK_DIR}/${name}" -f -q
        chmod 0755 "${WORK_DIR}/${name}"
    done
    echo "    Decompressed files:"
    ls -lah "$WORK_DIR"

    echo ""
    echo "Next step: cargo build -p openshell-vm"
    exit 0
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

# ── Fast path: pre-built tarball from CI or download-kernel-runtime.sh ──

if [ -n "${VM_RUNTIME_TARBALL:-}" ]; then
    echo "==> Using pre-built runtime tarball: ${VM_RUNTIME_TARBALL}"

    if [ ! -f "${VM_RUNTIME_TARBALL}" ]; then
        echo "Error: VM_RUNTIME_TARBALL not found: ${VM_RUNTIME_TARBALL}" >&2
        exit 1
    fi

    # Extract tarball contents
    zstd -d "${VM_RUNTIME_TARBALL}" --stdout | tar -xf - -C "$WORK_DIR"

    echo "    Extracted files:"
    ls -lah "$WORK_DIR"

    echo ""
    compress_dir "$WORK_DIR" "$OUTPUT_DIR"

    # Check for rootfs tarball (built separately)
    ROOTFS_TARBALL="${OUTPUT_DIR}/rootfs.tar.zst"
    if [ -f "$ROOTFS_TARBALL" ]; then
        echo "    rootfs.tar.zst: $(du -h "$ROOTFS_TARBALL" | cut -f1) (pre-built)"
    else
        echo ""
        echo "Note: rootfs.tar.zst not found."
        echo "      To build one, run: mise run vm:rootfs -- --base"
    fi

    echo ""
    echo "==> Compressed artifacts in ${OUTPUT_DIR}:"
    ls -lah "$OUTPUT_DIR"
    TOTAL=$(du -sh "$OUTPUT_DIR" | cut -f1)
    echo ""
    echo "==> Total compressed size: ${TOTAL}"
    echo ""
    echo "Next step: mise run vm:build"
    exit 0
fi

echo "==> Detecting platform..."

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    PLATFORM="darwin-aarch64"
    echo "    Platform: macOS ARM64"
    
    # Source priority for libkrun:
    # 1. Custom build from build-libkrun-macos.sh (portable, no GPU deps)
    # 2. Custom runtime with custom libkrunfw
    LIBKRUN_BUILD_DIR="${ROOT}/target/libkrun-build"
    CUSTOM_DIR="${ROOT}/target/custom-runtime"
    BREW_PREFIX="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
    
    if [ -f "${LIBKRUN_BUILD_DIR}/libkrun.dylib" ]; then
      echo "    Using portable libkrun from ${LIBKRUN_BUILD_DIR}"
      cp "${LIBKRUN_BUILD_DIR}/libkrun.dylib" "$WORK_DIR/"
      cp "${LIBKRUN_BUILD_DIR}/libkrunfw.dylib" "$WORK_DIR/"
      
      # Verify portability
      if otool -L "${LIBKRUN_BUILD_DIR}/libkrun.dylib" | grep -q "/opt/homebrew"; then
        echo "    Warning: libkrun has hardcoded Homebrew paths - may not be portable"
      else
        echo "    ✓ libkrun is portable (no hardcoded paths)"
      fi
    elif [ -f "${CUSTOM_DIR}/provenance.json" ]; then
      echo "    Using custom runtime from ${CUSTOM_DIR}"
      
      # libkrun from Homebrew (needs path rewriting for portability)
      if [ -f "${CUSTOM_DIR}/libkrun.dylib" ]; then
        cp "${CUSTOM_DIR}/libkrun.dylib" "$WORK_DIR/"
      else
        cp "${BREW_PREFIX}/lib/libkrun.dylib" "$WORK_DIR/"
        make_dylib_portable "$WORK_DIR/libkrun.dylib"
      fi
      
      # libkrunfw from custom build
      cp "${CUSTOM_DIR}/libkrunfw.dylib" "$WORK_DIR/"
    else
      echo "Error: No portable libkrun build found." >&2
      echo "       Run: FROM_SOURCE=1 mise run vm:setup" >&2
      exit 1
    fi
    
    # Normalize libkrunfw naming - ensure both names exist for build.rs
    # build.rs expects libkrunfw.5.dylib.zst; some builds produce libkrunfw.dylib
    if [ ! -f "$WORK_DIR/libkrunfw.dylib" ] && [ -f "$WORK_DIR/libkrunfw.5.dylib" ]; then
      cp "$WORK_DIR/libkrunfw.5.dylib" "$WORK_DIR/libkrunfw.dylib"
    fi
    if [ ! -f "$WORK_DIR/libkrunfw.5.dylib" ] && [ -f "$WORK_DIR/libkrunfw.dylib" ]; then
      cp "$WORK_DIR/libkrunfw.dylib" "$WORK_DIR/libkrunfw.5.dylib"
    fi
    
    # gvproxy - prefer Podman, fall back to Homebrew
    if [ -x /opt/podman/bin/gvproxy ]; then
      cp /opt/podman/bin/gvproxy "$WORK_DIR/"
      echo "    Using gvproxy from Podman"
    elif [ -x "${BREW_PREFIX}/bin/gvproxy" ]; then
      cp "${BREW_PREFIX}/bin/gvproxy" "$WORK_DIR/"
      echo "    Using gvproxy from Homebrew"
    else
      echo "Error: gvproxy not found. Install Podman Desktop or run: brew install gvproxy" >&2
      exit 1
    fi
    ;;
    
  Linux-*)
    ARCH="$(uname -m)"
    case "$ARCH" in
      aarch64) GVPROXY_ARCH="arm64" ;;
      x86_64)  GVPROXY_ARCH="amd64" ;;
      *)
        echo "Error: Unsupported Linux architecture: ${ARCH}" >&2
        exit 1
        ;;
    esac
    PLATFORM="linux-${ARCH}"
    echo "    Platform: Linux ${ARCH}"
    
    BUILD_DIR="${ROOT}/target/libkrun-build"
    if [ ! -f "${BUILD_DIR}/libkrun.so" ]; then
      echo "Error: libkrun not found. Run: FROM_SOURCE=1 mise run vm:setup" >&2
      exit 1
    fi
    
    cp "${BUILD_DIR}/libkrun.so" "$WORK_DIR/"
    
    # Copy libkrunfw - find the versioned .so file
    for krunfw in "${BUILD_DIR}"/libkrunfw.so*; do
      [ -f "$krunfw" ] || continue
      cp "$krunfw" "$WORK_DIR/"
    done
    
    # Ensure the soname symlink (libkrunfw.so.5) exists alongside the fully
    # versioned file (libkrunfw.so.5.x.y). libloading loads by soname.
    if [ ! -f "$WORK_DIR/libkrunfw.so.5" ]; then
      versioned=$(ls "$WORK_DIR"/libkrunfw.so.5.* 2>/dev/null | head -n1)
      if [ -n "$versioned" ]; then
        cp "$versioned" "$WORK_DIR/libkrunfw.so.5"
      fi
    fi

    # Download gvproxy if not present
    if [ ! -f "$WORK_DIR/gvproxy" ]; then
      echo "    Downloading gvproxy for linux-${GVPROXY_ARCH}..."
      curl -fsSL -o "$WORK_DIR/gvproxy" \
        "https://github.com/containers/gvisor-tap-vsock/releases/download/${GVPROXY_VERSION}/gvproxy-linux-${GVPROXY_ARCH}"
      chmod +x "$WORK_DIR/gvproxy"
    fi
    ;;
    
  *)
    echo "Error: Unsupported platform: $(uname -s)-$(uname -m)" >&2
    echo "Supported platforms: Darwin-arm64, Linux-aarch64, Linux-x86_64" >&2
    exit 1
    ;;
esac

echo ""
echo "==> Collected artifacts:"
ls -lah "$WORK_DIR"

echo ""
compress_dir "$WORK_DIR" "$OUTPUT_DIR"

# Check for rootfs tarball (built separately by build-rootfs-tarball.sh)
ROOTFS_TARBALL="${OUTPUT_DIR}/rootfs.tar.zst"
if [ -f "$ROOTFS_TARBALL" ]; then
    echo "    rootfs.tar.zst: $(du -h "$ROOTFS_TARBALL" | cut -f1) (pre-built)"
else
    echo ""
    echo "Note: rootfs.tar.zst not found."
      echo "      To build one, run: mise run vm:rootfs -- --base"
      echo "      Without it, the binary will still work but require the rootfs"
      echo "      to be built separately on first run."
fi

echo ""
echo "==> Compressed artifacts in ${OUTPUT_DIR}:"
ls -lah "$OUTPUT_DIR"

TOTAL=$(du -sh "$OUTPUT_DIR" | cut -f1)
echo ""
echo "==> Total compressed size: ${TOTAL}"
echo ""
echo "Next step: mise run vm:build"
