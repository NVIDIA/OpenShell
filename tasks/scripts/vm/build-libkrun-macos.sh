#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build libkrun from source on macOS with portable rpath.
#
# This script builds libkrun WITHOUT GPU support (no virglrenderer/libepoxy/MoltenVK
# dependencies), making the resulting binary fully portable and self-contained.
#
# For openshell-vm, we run headless k3s clusters, so GPU passthrough is not needed.
#
# Prerequisites:
#   - macOS ARM64 (Apple Silicon)
#   - Xcode Command Line Tools
#   - Homebrew: brew install rust lld dtc xz libkrunfw
#
# Usage:
#   ./build-libkrun-macos.sh
#
# Output:
#   target/libkrun-build/libkrun.dylib - portable dylib with @loader_path rpath

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUILD_DIR="${ROOT}/target/libkrun-build"
OUTPUT_DIR="${BUILD_DIR}"
BREW_PREFIX="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
CUSTOM_RUNTIME="${ROOT}/target/custom-runtime"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "Error: This script only runs on macOS" >&2
    exit 1
fi

if [ "$(uname -m)" != "arm64" ]; then
    echo "Error: libkrun on macOS only supports ARM64 (Apple Silicon)" >&2
    exit 1
fi

ARCH="$(uname -m)"
echo "==> Building libkrun for macOS ${ARCH} (no GPU support)"
echo "    Build directory: ${BUILD_DIR}"
echo ""

# ── Check dependencies ──────────────────────────────────────────────────

check_deps() {
    echo "==> Checking build dependencies..."
    
    MISSING=""
    
    # Check for Rust
    if ! command -v cargo &>/dev/null; then
        MISSING="$MISSING rust"
    fi
    
    # Check for lld (LLVM linker)
    if ! command -v ld.lld &>/dev/null && ! [ -x "${BREW_PREFIX}/opt/llvm/bin/ld.lld" ]; then
        MISSING="$MISSING lld"
    fi
    
    # Check for dtc (device tree compiler)
    if ! command -v dtc &>/dev/null; then
        MISSING="$MISSING dtc"
    fi
    
    # Check for libkrunfw
    if [ ! -f "${BREW_PREFIX}/lib/libkrunfw.dylib" ] && \
       [ ! -f "${BREW_PREFIX}/lib/libkrunfw.5.dylib" ] && \
       [ ! -f "${CUSTOM_RUNTIME}/libkrunfw.dylib" ]; then
        MISSING="$MISSING libkrunfw"
    fi
    
    if [ -n "$MISSING" ]; then
        echo "Error: Missing dependencies:$MISSING" >&2
        echo "" >&2
        echo "Install with: brew install$MISSING" >&2
        exit 1
    fi
    
    echo "    All dependencies found"
}

check_deps

# ── Setup build directory ───────────────────────────────────────────────

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# ── Clone libkrun ───────────────────────────────────────────────────────

LIBKRUN_REF="${LIBKRUN_REF:-e5922f6}"

if [ ! -d libkrun ]; then
    echo "==> Cloning libkrun..."
    git clone https://github.com/containers/libkrun.git
fi

echo "==> Checking out ${LIBKRUN_REF}..."
cd libkrun
git fetch origin --tags
git checkout "${LIBKRUN_REF}" 2>/dev/null || git checkout "tags/${LIBKRUN_REF}" 2>/dev/null || {
    echo "Error: Could not checkout ${LIBKRUN_REF}" >&2
    exit 1
}
cd ..

LIBKRUN_COMMIT=$(git -C libkrun rev-parse HEAD)
echo "    Commit: ${LIBKRUN_COMMIT}"

cd libkrun

# ── Build libkrun ───────────────────────────────────────────────────────

echo ""
echo "==> Building libkrun with NET=1 BLK=1 (no GPU)..."

# Find libkrunfw - prefer custom build with bridge support
if [ -f "${CUSTOM_RUNTIME}/provenance.json" ] && [ -f "${CUSTOM_RUNTIME}/libkrunfw.dylib" ]; then
    LIBKRUNFW_DIR="${CUSTOM_RUNTIME}"
    echo "    Using custom libkrunfw from ${LIBKRUNFW_DIR}"
else
    LIBKRUNFW_DIR="${BREW_PREFIX}/lib"
    echo "    Using Homebrew libkrunfw from ${LIBKRUNFW_DIR}"
fi

# Set library search paths for build
export LIBRARY_PATH="${LIBKRUNFW_DIR}:${BREW_PREFIX}/lib:${LIBRARY_PATH:-}"
export DYLD_LIBRARY_PATH="${LIBKRUNFW_DIR}:${BREW_PREFIX}/lib:${DYLD_LIBRARY_PATH:-}"

# Set up LLVM/clang for bindgen (required by krun_display/krun_input if they get compiled)
# Note: DYLD_LIBRARY_PATH is needed at runtime for the build scripts that use libclang
LLVM_PREFIX="${BREW_PREFIX}/opt/llvm"
if [ -d "$LLVM_PREFIX" ]; then
    export LIBCLANG_PATH="${LLVM_PREFIX}/lib"
    export DYLD_LIBRARY_PATH="${LLVM_PREFIX}/lib:${DYLD_LIBRARY_PATH:-}"
fi

# Build with BLK and NET features only (no GPU)
# This avoids the virglrenderer → libepoxy → MoltenVK dependency chain
make clean 2>/dev/null || true
make BLK=1 NET=1 -j"$(sysctl -n hw.ncpu)"

# ── Rewrite dylib paths for portability ─────────────────────────────────

echo ""
echo "==> Making dylib portable with @loader_path..."

DYLIB="target/release/libkrun.dylib"
if [ ! -f "$DYLIB" ]; then
    echo "Error: Build did not produce $DYLIB" >&2
    exit 1
fi

# Copy to output
cp "$DYLIB" "${OUTPUT_DIR}/libkrun.dylib"
DYLIB="${OUTPUT_DIR}/libkrun.dylib"

# Show current dependencies
echo "    Original dependencies:"
otool -L "$DYLIB" | grep -v "^/" | sed 's/^/      /'

# Rewrite the install name to use @loader_path (makes it relocatable)
install_name_tool -id "@loader_path/libkrun.dylib" "$DYLIB"

# Rewrite libkrunfw path to @loader_path (will be bundled alongside)
# Find what libkrunfw path is currently referenced
# Note: grep may not find anything (libkrunfw is loaded via dlopen), so we use || true
KRUNFW_PATH=$(otool -L "$DYLIB" | grep libkrunfw | awk '{print $1}' || true)
if [ -n "$KRUNFW_PATH" ]; then
    install_name_tool -change "$KRUNFW_PATH" "@loader_path/libkrunfw.dylib" "$DYLIB"
    echo "    Rewrote: $KRUNFW_PATH → @loader_path/libkrunfw.dylib"
fi

# Re-codesign after modifications (required on macOS)
codesign -f -s - "$DYLIB"

# Show final dependencies
echo ""
echo "    Final dependencies:"
otool -L "$DYLIB" | grep -v "^/" | sed 's/^/      /'

# Verify no hardcoded homebrew paths remain
if otool -L "$DYLIB" | grep -q "/opt/homebrew"; then
    echo ""
    echo "Warning: Homebrew paths still present in dylib!" >&2
    otool -L "$DYLIB" | grep "/opt/homebrew" | sed 's/^/      /'
else
    echo ""
    echo "    ✓ No hardcoded Homebrew paths"
fi

# ── Copy libkrunfw to output ────────────────────────────────────────────

echo ""
echo "==> Bundling libkrunfw..."

# Find and copy libkrunfw
KRUNFW_SRC=""
for candidate in \
    "${CUSTOM_RUNTIME}/libkrunfw.dylib" \
    "${CUSTOM_RUNTIME}/libkrunfw.5.dylib" \
    "${BREW_PREFIX}/lib/libkrunfw.dylib" \
    "${BREW_PREFIX}/lib/libkrunfw.5.dylib"; do
    if [ -f "$candidate" ]; then
        # Resolve symlinks
        if [ -L "$candidate" ]; then
            KRUNFW_SRC=$(readlink -f "$candidate" 2>/dev/null || readlink "$candidate")
            if [[ "$KRUNFW_SRC" != /* ]]; then
                KRUNFW_SRC="$(dirname "$candidate")/${KRUNFW_SRC}"
            fi
        else
            KRUNFW_SRC="$candidate"
        fi
        break
    fi
done

if [ -z "$KRUNFW_SRC" ]; then
    echo "Error: Could not find libkrunfw.dylib" >&2
    exit 1
fi

cp "$KRUNFW_SRC" "${OUTPUT_DIR}/libkrunfw.dylib"
echo "    Copied: $KRUNFW_SRC"

# Make libkrunfw portable too
install_name_tool -id "@loader_path/libkrunfw.dylib" "${OUTPUT_DIR}/libkrunfw.dylib"
codesign -f -s - "${OUTPUT_DIR}/libkrunfw.dylib"

# Check libkrunfw dependencies
echo "    libkrunfw dependencies:"
otool -L "${OUTPUT_DIR}/libkrunfw.dylib" | grep -v "^/" | sed 's/^/      /'

# ── Summary ─────────────────────────────────────────────────────────────

cd "$BUILD_DIR"

echo ""
echo "==> Build complete!"
echo "    Output directory: ${OUTPUT_DIR}"
echo ""
echo "    Artifacts:"
ls -lah "${OUTPUT_DIR}"/*.dylib

# Verify portability
echo ""
echo "==> Verifying portability..."
ALL_GOOD=true

for lib in "${OUTPUT_DIR}"/*.dylib; do
    if otool -L "$lib" | grep -q "/opt/homebrew"; then
        echo "    ✗ $(basename "$lib") has hardcoded paths"
        ALL_GOOD=false
    else
        echo "    ✓ $(basename "$lib") is portable"
    fi
done

if $ALL_GOOD; then
    echo ""
    echo "All libraries are portable!"
    echo ""
    echo "Next step: mise run vm:build"
else
    echo ""
    echo "Warning: Some libraries have non-portable paths"
    echo "They may not work on machines without Homebrew"
fi
