#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build libkrun and libkrunfw from source on Linux.
#
# This script builds libkrun (VMM) and libkrunfw (kernel firmware) from source
# with OpenShell's custom kernel configuration for bridge/netfilter support.
#
# Prerequisites:
#   - Linux (aarch64 or x86_64)
#   - Build tools: make, git, gcc, flex, bison, bc
#   - Python 3 with pyelftools
#   - Rust toolchain
#
# Usage:
#   ./build-libkrun.sh
#
# The script will install missing dependencies on Debian/Ubuntu and Fedora.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

# Source pinned dependency versions
source "${ROOT}/crates/openshell-vm/pins.env" 2>/dev/null || true

BUILD_DIR="${ROOT}/target/libkrun-build"
OUTPUT_DIR="${BUILD_DIR}"
KERNEL_CONFIG="${ROOT}/crates/openshell-vm/runtime/kernel/openshell.kconfig"

if [ "$(uname -s)" != "Linux" ]; then
  echo "Error: This script only runs on Linux" >&2
  exit 1
fi

ARCH="$(uname -m)"
echo "==> Building libkrun for Linux ${ARCH}"
echo "    Build directory: ${BUILD_DIR}"
echo "    Kernel config: ${KERNEL_CONFIG}"
echo ""

# ── Install dependencies ────────────────────────────────────────────────

install_deps() {
  echo "==> Checking/installing build dependencies..."
  
  if command -v apt-get &>/dev/null; then
    # Debian/Ubuntu
    DEPS="build-essential git python3 python3-pyelftools flex bison libelf-dev libssl-dev bc curl libclang-dev"
    MISSING=""
    for dep in $DEPS; do
      if ! dpkg -s "$dep" &>/dev/null; then
        MISSING="$MISSING $dep"
      fi
    done
    if [ -n "$MISSING" ]; then
      echo "    Installing:$MISSING"
      sudo apt-get update
      sudo apt-get install -y $MISSING
    else
      echo "    All dependencies installed"
    fi
    
  elif command -v dnf &>/dev/null; then
    # Fedora/RHEL
    DEPS="make git python3 python3-pyelftools gcc flex bison elfutils-libelf-devel openssl-devel bc glibc-static curl clang-devel"
    echo "    Installing dependencies via dnf..."
    sudo dnf install -y $DEPS
    
  else
    echo "Warning: Unknown package manager. Please install manually:" >&2
    echo "  build-essential git python3 python3-pyelftools flex bison" >&2
    echo "  libelf-dev libssl-dev bc curl" >&2
  fi
}

install_deps

# ── Setup build directory ───────────────────────────────────────────────

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# ── Build libkrunfw (kernel firmware) ───────────────────────────────────

echo ""
echo "==> Building libkrunfw with custom kernel config..."

if [ ! -d libkrunfw ]; then
  echo "    Cloning libkrunfw (pinned: ${LIBKRUNFW_REF:-HEAD})..."
  git clone https://github.com/containers/libkrunfw.git
fi

cd libkrunfw

# Ensure we're on the pinned commit for reproducible builds
if [ -n "${LIBKRUNFW_REF:-}" ]; then
  echo "    Checking out pinned ref: ${LIBKRUNFW_REF}"
  git fetch origin
  git checkout "${LIBKRUNFW_REF}"
fi

# Copy custom kernel config fragment
if [ -f "$KERNEL_CONFIG" ]; then
  cp "$KERNEL_CONFIG" openshell.kconfig
  echo "    Applied custom kernel config fragment: openshell.kconfig"
else
  echo "Warning: Custom kernel config not found at ${KERNEL_CONFIG}" >&2
  echo "    Building with default config (k3s networking may not work)" >&2
fi

echo "    Building kernel and libkrunfw (this may take 15-20 minutes)..."

# The libkrunfw Makefile does not support a config fragment — it copies the
# base config and runs olddefconfig, then builds the kernel image in one
# make invocation.  We cannot inject the fragment mid-build via make flags.
#
# Instead we drive the build in two phases:
#
#   Phase 1: Run the Makefile's $(KERNEL_SOURCES) target, which:
#              - downloads and extracts the kernel tarball (if needed)
#              - applies patches
#              - copies config-libkrunfw_aarch64 to $(KERNEL_SOURCES)/.config
#              - runs olddefconfig
#
#   Phase 2: Merge our fragment on top of the .config produced by Phase 1
#            using the kernel's own merge_config.sh, then re-run olddefconfig
#            to resolve new dependency chains (e.g. CONFIG_BRIDGE pulls in
#            CONFIG_BRIDGE_NETFILTER which needs CONFIG_NETFILTER etc).
#
#   Phase 3: Let the Makefile build everything (kernel + kernel.c + .so),
#            skipping the $(KERNEL_SOURCES) target since it already exists.

KERNEL_VERSION="$(grep '^KERNEL_VERSION' Makefile | head -1 | awk '{print $3}')"
KERNEL_SOURCES="${KERNEL_VERSION}"

# Phase 1: prepare kernel source tree + base .config.
# Run the Makefile's $(KERNEL_SOURCES) target whenever the .config is absent
# (either because the tree was never extracted, or because it was cleaned).
# The target is idempotent: if the directory already exists make skips the
# tarball extraction but still copies the base config and runs olddefconfig.
if [ ! -f "${KERNEL_SOURCES}/.config" ]; then
  echo "    Phase 1: preparing kernel source tree and base .config..."
  # Remove the directory so make re-runs the full $(KERNEL_SOURCES) recipe
  # (extract + patch + config copy + olddefconfig).
  rm -rf "${KERNEL_SOURCES}"
  make "${KERNEL_SOURCES}"
else
  echo "    Phase 1: kernel source tree and .config already present, skipping"
fi

# Phase 2: merge the openshell fragment on top
if [ -f openshell.kconfig ]; then
  echo "    Phase 2: merging openshell.kconfig fragment..."

  # merge_config.sh must be called with ARCH set so it finds the right Kconfig
  # entry points. -m means "merge into existing .config" (vs starting fresh).
  ARCH=arm64 KCONFIG_CONFIG="${KERNEL_SOURCES}/.config" \
    "${KERNEL_SOURCES}/scripts/kconfig/merge_config.sh" \
    -m -O "${KERNEL_SOURCES}" \
    "${KERNEL_SOURCES}/.config" \
    openshell.kconfig

  # Re-run olddefconfig to fill in any new symbols introduced by the fragment.
  make -C "${KERNEL_SOURCES}" ARCH=arm64 olddefconfig

  # Verify that the key options were actually applied.
  all_ok=true
  for opt in CONFIG_BRIDGE CONFIG_NETFILTER CONFIG_NF_NAT; do
    val="$(grep "^${opt}=" "${KERNEL_SOURCES}/.config" 2>/dev/null || true)"
    if [ -n "$val" ]; then
      echo "    ${opt}: ${val#*=}"
    else
      echo "    WARNING: ${opt} not set after merge!" >&2
      all_ok=false
    fi
  done
  if [ "$all_ok" = false ]; then
    echo "ERROR: kernel config fragment merge failed — required options missing" >&2
    exit 1
  fi

  # The kernel binary and kernel.c from the previous (bad) build must be
  # removed so make rebuilds them with the updated .config.
  rm -f kernel.c "${KERNEL_SOURCES}/arch/arm64/boot/Image" \
        "${KERNEL_SOURCES}/vmlinux" libkrunfw.so*
fi

# Phase 3: build kernel image, kernel.c bundle, and the shared library
make -j"$(nproc)"

# Copy output
cp libkrunfw.so* "$OUTPUT_DIR/"
echo "    Built: $(ls "$OUTPUT_DIR"/libkrunfw.so* | xargs -n1 basename | tr '\n' ' ')"

cd "$BUILD_DIR"

# ── Build libkrun (VMM) ─────────────────────────────────────────────────

echo ""
echo "==> Building libkrun..."

if [ ! -d libkrun ]; then
  echo "    Cloning libkrun..."
  git clone --depth 1 https://github.com/containers/libkrun.git
fi

cd libkrun

# Build with NET support for gvproxy networking and BLK support for the
# host-backed state disk.
echo "    Building libkrun with NET=1 BLK=1..."

# Locate libclang for clang-sys if LIBCLANG_PATH isn't already set.
# clang-sys looks for libclang.so or libclang-*.so; on Debian/Ubuntu the
# versioned file (e.g. libclang-18.so.18) lives under the LLVM lib dir.
if [ -z "${LIBCLANG_PATH:-}" ]; then
  for llvm_lib in /usr/lib/llvm-*/lib; do
    if ls "$llvm_lib"/libclang*.so* &>/dev/null; then
      export LIBCLANG_PATH="$llvm_lib"
      echo "    LIBCLANG_PATH=$LIBCLANG_PATH"
      break
    fi
  done
fi

make NET=1 BLK=1 -j"$(nproc)"

# Copy output
cp target/release/libkrun.so "$OUTPUT_DIR/"
echo "    Built: libkrun.so"

cd "$BUILD_DIR"

# ── Summary ─────────────────────────────────────────────────────────────

echo ""
echo "==> Build complete!"
echo "    Output directory: ${OUTPUT_DIR}"
echo ""
echo "    Artifacts:"
ls -lah "$OUTPUT_DIR"/*.so*

echo ""
echo "Next step: mise run vm:build"
