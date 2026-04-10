#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build libkrun and libkrunfw from source on Linux.
#
# This script builds libkrun (VMM) and libkrunfw (kernel firmware) from source
# with OpenShell's custom kernel configuration for bridge/netfilter support.
#
# In addition to the platform's native .so artifacts, this script exports
# kernel.c and ABI_VERSION metadata so that other platforms (e.g. macOS) can
# compile their own libkrunfw wrapper without rebuilding the kernel.
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

HOST_ARCH="$(uname -m)"
echo "==> Building libkrun for Linux ${HOST_ARCH}"
echo "    Build directory: ${BUILD_DIR}"
echo "    Kernel config: ${KERNEL_CONFIG}"
echo ""

# Map host arch to kernel ARCH value
case "$HOST_ARCH" in
  aarch64) KARCH="arm64"; KERNEL_IMAGE_PATH="arch/arm64/boot/Image" ;;
  x86_64)  KARCH="x86"; KERNEL_IMAGE_PATH="arch/x86/boot/bzImage" ;;
  *)       echo "Error: Unsupported architecture: ${HOST_ARCH}" >&2; exit 1 ;;
esac

# ── Install dependencies ────────────────────────────────────────────────

# Use sudo only when not already running as root (e.g. inside CI containers).
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

install_deps() {
  echo "==> Checking/installing build dependencies..."
  
  if command -v apt-get &>/dev/null; then
    # Debian/Ubuntu
    DEPS="build-essential git python3 python3-pip python3-pyelftools flex bison libelf-dev libssl-dev bc curl libclang-dev cpio zstd jq"
    MISSING=""
    for dep in $DEPS; do
      if ! dpkg -s "$dep" &>/dev/null; then
        MISSING="$MISSING $dep"
      fi
    done
    if [ -n "$MISSING" ]; then
      echo "    Installing:$MISSING"
      $SUDO apt-get update
      $SUDO apt-get install -y $MISSING
    else
      echo "    All dependencies installed"
    fi
    
  elif command -v dnf &>/dev/null; then
    # Fedora/RHEL
    DEPS="make git python3 python3-pyelftools gcc flex bison elfutils-libelf-devel openssl-devel bc glibc-static curl clang-devel cpio zstd jq"
    echo "    Installing dependencies via dnf..."
    $SUDO dnf install -y $DEPS
    
  else
    echo "Warning: Unknown package manager. Please install manually:" >&2
    echo "  build-essential git python3 python3-pyelftools flex bison" >&2
    echo "  libelf-dev libssl-dev bc curl cpio" >&2
  fi

}

install_deps

# libkrunfw's Makefile invokes `python3` from PATH for bin2cbundle.py. A mise shim,
# project venv, or other early PATH entry often shadows /usr/bin/python3 and does
# not ship pyelftools even when python3-pyelftools is installed for the distro.
ensure_python3_with_pyelftools_for_libkrunfw() {
  echo "    Checking Python 3 + pyelftools (libkrunfw bin2cbundle.py)..."
  if python3 -c 'from elftools.elf.elffile import ELFFile' 2>/dev/null; then
    echo "       OK ($(command -v python3))"
    return 0
  fi
  if [ -x /usr/bin/python3 ] && /usr/bin/python3 -c 'from elftools.elf.elffile import ELFFile' 2>/dev/null; then
    export PATH="/usr/bin:${PATH}"
    echo "       Using /usr/bin/python3 (PATH python3 lacked pyelftools; system Python has it)."
    return 0
  fi
  echo "ERROR: Python 3 with pyelftools is required to build libkrunfw (kernel.c generation)." >&2
  echo "       Install:  Debian/Ubuntu: sudo apt-get install -y python3-pyelftools" >&2
  echo "                Fedora/RHEL:   sudo dnf install -y python3-pyelftools" >&2
  echo "                pip:         python3 -m pip install --user pyelftools" >&2
  echo "       If the package is installed but this still fails, PATH may point at another python3 (mise, venv)." >&2
  echo "       Try:  PATH=/usr/bin:\$PATH mise run vm:setup" >&2
  exit 1
}

# ── Setup build directory ───────────────────────────────────────────────

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# ── Build libkrunfw (kernel firmware) ───────────────────────────────────

echo ""
echo "==> Building libkrunfw with custom kernel config..."

ensure_python3_with_pyelftools_for_libkrunfw

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
#              - copies config-libkrunfw_{arch} to $(KERNEL_SOURCES)/.config
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
  ARCH="${KARCH}" KCONFIG_CONFIG="${KERNEL_SOURCES}/.config" \
    "${KERNEL_SOURCES}/scripts/kconfig/merge_config.sh" \
    -m -O "${KERNEL_SOURCES}" \
    "${KERNEL_SOURCES}/.config" \
    openshell.kconfig

  # Re-run olddefconfig to fill in any new symbols introduced by the fragment.
  make -C "${KERNEL_SOURCES}" ARCH="${KARCH}" olddefconfig

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
  rm -f kernel.c "${KERNEL_SOURCES}/${KERNEL_IMAGE_PATH}" \
        "${KERNEL_SOURCES}/vmlinux" libkrunfw.so*
fi

# Phase 3: build kernel image, kernel.c bundle, and the shared library
make -j"$(nproc)"

# Copy output
cp libkrunfw.so* "$OUTPUT_DIR/"
echo "    Built: $(ls "$OUTPUT_DIR"/libkrunfw.so* | xargs -n1 basename | tr '\n' ' ')"

cd "$BUILD_DIR"

# ── Build libkrun (VMM) ─────────────────────────────────────────────────

# libkrun's Makefile invokes plain `cargo`. Ubuntu/Debian often put /usr/bin/cargo
# (e.g. 1.75) ahead of mise/rustup; upstream requires edition 2024 (Cargo >= 1.85).
ensure_cargo_for_libkrun() {
  local min_ver="${LIBKRUN_MIN_CARGO_VERSION:-1.85}"
  local have ver_line bindir candidates_mise candidates_home

  cargo_meets_min() {
    local bin="$1"
    local v
    [ -x "$bin" ] || return 1
    v="$("$bin" --version 2>/dev/null | awk '{print $2}')"
    [ -n "$v" ] || return 1
    [ "$(printf '%s\n' "${min_ver}" "$v" | sort -V | head -n1)" = "${min_ver}" ]
  }

  echo "    Checking Cargo (libkrun needs >= ${min_ver}, edition 2024)..."
  if cargo_meets_min "$(command -v cargo 2>/dev/null || true)"; then
    echo "       OK ($(command -v cargo) — $(cargo --version))"
    return 0
  fi

  candidates_mise=""
  if command -v mise &>/dev/null; then
    if ver_line="$(mise which cargo 2>/dev/null)" && [ -n "${ver_line}" ]; then
      candidates_mise="$(dirname "${ver_line}")"
    fi
  fi
  candidates_home="${HOME}/.cargo/bin"

  for bindir in "${candidates_mise}" "${candidates_home}"; do
    [ -n "${bindir}" ] || continue
    if cargo_meets_min "${bindir}/cargo"; then
      export PATH="${bindir}:${PATH}"
      echo "       Using ${bindir}/cargo ($("${bindir}/cargo" --version))"
      return 0
    fi
  done

  echo "ERROR: Cargo >= ${min_ver} is required to build libkrun (Rust edition 2024)." >&2
  echo "       Current: $(command -v cargo 2>/dev/null || echo '(no cargo in PATH)') $(cargo --version 2>/dev/null || true)" >&2
  echo "       Typical fix: run vm:setup via mise from the repo so Rust stable is on PATH," >&2
  echo "       or:  rustup update stable && export PATH=\"\$HOME/.cargo/bin:\$PATH\"" >&2
  echo "       Override minimum: LIBKRUN_MIN_CARGO_VERSION=…" >&2
  exit 1
}

# Directory must contain libclang.so or libclang-<ver>.so (what clang-sys expects
# for linking; bare .so.N sonames alone are not enough).
_libclang_dir_usable() {
  local d="$1"
  [ -n "$d" ] && [ -d "$d" ] || return 1
  if [ -e "$d/libclang.so" ]; then
    return 0
  fi
  local f base
  for f in "$d"/libclang-*.so; do
    [ -e "$f" ] || continue
    base="$(basename "$f")"
    case "$base" in
      *-cpp.so*) continue ;;
    esac
    if [[ "$base" == libclang-*.so ]] && [[ "$base" != *.so.[0-9]* ]]; then
      return 0
    fi
  done
  return 1
}

ensure_libclang_for_libkrun() {
  local user_libclang="${LIBCLANG_PATH:-}"

  if [ -n "$user_libclang" ] && _libclang_dir_usable "$user_libclang"; then
    export LIBCLANG_PATH="$user_libclang"
    echo "    LIBCLANG_PATH=$LIBCLANG_PATH (from environment)"
    return 0
  fi

  if [ -n "$user_libclang" ]; then
    echo "    Warning: LIBCLANG_PATH='$user_libclang' has no libclang.so or libclang-*.so symlink;" >&2
    echo "             those are required for clang-sys. Searching other system locations..." >&2
  fi
  unset LIBCLANG_PATH

  local llvm_lib
  if command -v llvm-config &>/dev/null; then
    llvm_lib="$(llvm-config --libdir 2>/dev/null)" || true
    if [ -n "${llvm_lib}" ] && _libclang_dir_usable "$llvm_lib"; then
      export LIBCLANG_PATH="$llvm_lib"
      echo "    LIBCLANG_PATH=$LIBCLANG_PATH (from llvm-config --libdir)"
      return 0
    fi
  fi

  shopt -s nullglob
  local candidates=(/usr/lib/llvm-*/lib)
  shopt -u nullglob
  while IFS= read -r llvm_lib; do
    [ -n "$llvm_lib" ] || continue
    if _libclang_dir_usable "$llvm_lib"; then
      export LIBCLANG_PATH="$llvm_lib"
      echo "    LIBCLANG_PATH=$LIBCLANG_PATH (from /usr/lib/llvm-*/lib)"
      return 0
    fi
  done < <(printf '%s\n' "${candidates[@]}" | sort -rV)

  local multi
  multi="$(gcc -print-multiarch 2>/dev/null || true)"
  if [ -n "$multi" ] && _libclang_dir_usable "/usr/lib/${multi}"; then
    export LIBCLANG_PATH="/usr/lib/${multi}"
    echo "    LIBCLANG_PATH=$LIBCLANG_PATH (from gcc multiarch /usr/lib/${multi})"
    return 0
  fi

  if _libclang_dir_usable "/usr/lib64"; then
    export LIBCLANG_PATH="/usr/lib64"
    echo "    LIBCLANG_PATH=$LIBCLANG_PATH (from /usr/lib64)"
    return 0
  fi

  echo "ERROR: libclang is required to build libkrun (Rust bindgen / clang-sys) but was not found." >&2
  if [ -n "$user_libclang" ]; then
    echo "       You had LIBCLANG_PATH='$user_libclang' (ignored after search failed)." >&2
  fi
  echo "       Install LLVM/Clang development packages, then re-run vm:setup:" >&2
  echo "         Debian/Ubuntu: sudo apt-get install -y libclang-dev" >&2
  echo "         Fedora/RHEL:   sudo dnf install -y clang-devel" >&2
  echo "       Then unset LIBCLANG_PATH or set it to a directory that contains libclang.so." >&2
  exit 1
}

echo ""
echo "==> Building libkrun..."

ensure_cargo_for_libkrun
ensure_libclang_for_libkrun

LIBKRUN_REF="${LIBKRUN_REF:-v1.17.4}"

if [ ! -d libkrun ]; then
  echo "    Cloning libkrun..."
  git clone https://github.com/containers/libkrun.git
fi

cd libkrun

if [ -n "${LIBKRUN_REF:-}" ]; then
  echo "    Checking out pinned ref: ${LIBKRUN_REF}"
  git fetch origin "${LIBKRUN_REF}" 2>/dev/null || git fetch origin
  git checkout "${LIBKRUN_REF}" 2>/dev/null || git checkout "origin/${LIBKRUN_REF}" 2>/dev/null || true
fi

if [ -f init/Makefile ] || grep -q 'init/init' Makefile 2>/dev/null; then
  echo "    Building init/init binary..."
  make init/init
fi

echo "    Building libkrun with NET=1 BLK=1..."
cargo build --release --features blk --features net --target-dir="$(pwd)/target"

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
