#!/bin/sh

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared Rust cross-compilation helpers for multi-arch Docker builds.
#
# Source this script in Dockerfile RUN layers:
#   COPY deploy/docker/cross-build.sh /usr/local/bin/
#   RUN . cross-build.sh && install_cross_toolchain && add_rust_target
#   RUN . cross-build.sh && cargo_cross_build --release -p my-crate
#
# Requires TARGETARCH and BUILDARCH (set automatically by docker buildx).

: "${TARGETARCH:?TARGETARCH must be set}"
: "${BUILDARCH:?BUILDARCH must be set}"

SCCACHE_VERSION="${SCCACHE_VERSION:-0.14.0}"

# True when the build host and target differ.
is_cross() { [ "$TARGETARCH" != "$BUILDARCH" ]; }

# Install sccache binary for the build host architecture.
# Uses SCCACHE_VERSION (default: 0.14.0).
install_sccache() {
  case "$BUILDARCH" in
    amd64) sccache_arch=x86_64-unknown-linux-musl ;;
    arm64) sccache_arch=aarch64-unknown-linux-musl ;;
    *)     echo "unsupported BUILDARCH for sccache: $BUILDARCH" >&2; return 1 ;;
  esac
  local url="https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/sccache-v${SCCACHE_VERSION}-${sccache_arch}.tar.gz"
  curl -fsSL "$url" | tar xz --strip-components=1 -C /usr/local/bin \
    "sccache-v${SCCACHE_VERSION}-${sccache_arch}/sccache"
  chmod +x /usr/local/bin/sccache
}

# Map Docker arch name to Rust target triple.
rust_target() {
  case "$TARGETARCH" in
    arm64) echo "aarch64-unknown-linux-gnu" ;;
    amd64) echo "x86_64-unknown-linux-gnu" ;;
    *)     echo "unsupported TARGETARCH: $TARGETARCH" >&2; return 1 ;;
  esac
}

# Install the gcc cross-linker and target libc. No-op for native builds.
install_cross_toolchain() {
  is_cross || return 0
  case "$TARGETARCH" in
    arm64)
      dpkg --add-architecture arm64
      apt-get update && apt-get install -y --no-install-recommends \
        gcc-aarch64-linux-gnu libc6-dev-arm64-cross ;;
    amd64)
      dpkg --add-architecture amd64
      apt-get update && apt-get install -y --no-install-recommends \
        gcc-x86-64-linux-gnu libc6-dev-amd64-cross ;;
  esac
  rm -rf /var/lib/apt/lists/*
}

# Add the Rust compilation target. No-op for native builds.
add_rust_target() {
  is_cross || return 0
  rustup target add "$(rust_target)"
}

# Export CC / CXX / linker env vars for the target. No-op for native builds.
export_cross_env() {
  is_cross || return 0
  case "$TARGETARCH" in
    arm64)
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
      export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
      export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ ;;
    amd64)
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
      export CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
      export CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++ ;;
  esac
}

# Run cargo build with the correct --target flag and env vars.
# All extra arguments are forwarded to cargo (e.g. --release -p my-crate).
# Automatically wraps with sccache when available.
cargo_cross_build() {
  export_cross_env
  # Unset empty SCCACHE_MEMCACHED_ENDPOINT so sccache falls back to the
  # local disk cache instead of erroring on an empty endpoint string.
  if [ -z "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]; then
    unset SCCACHE_MEMCACHED_ENDPOINT 2>/dev/null || true
  fi
  # When CARGO_CODEGEN_UNITS is set (e.g. CI=1), override the Cargo.toml
  # release profile to use that many codegen units.
  if [ -n "${CARGO_CODEGEN_UNITS:-}" ]; then
    export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${CARGO_CODEGEN_UNITS}"
  fi
  # Default sccache local disk cache to /tmp/sccache (matches BuildKit
  # cache mount target in Dockerfiles) when no dir is explicitly set.
  export SCCACHE_DIR="${SCCACHE_DIR:-/tmp/sccache}"
  if command -v sccache >/dev/null 2>&1; then
    export RUSTC_WRAPPER=sccache
  fi
  local target_flag=""
  if is_cross; then target_flag="--target $(rust_target)"; fi
  # Detect profile from args: use "release" if --release is present, else "debug".
  local profile="debug"
  for arg in "$@"; do
    case "$arg" in --release) profile="release" ;; esac
  done
  # Ensure the target deps directory exists. BuildKit cache mounts keyed by
  # CARGO_TARGET_CACHE_SCOPE start empty on first use, and rustc fails with
  # "No such file or directory" writing .d files if deps/ is missing.
  mkdir -p "$(cross_output_dir "$profile")/deps"
  # Retry once after cleaning if the build fails. BuildKit cargo-target cache
  # mounts can retain stale .rmeta/.rlib files from prior builds with different
  # dependency versions or profiles. We wipe the entire target directory
  # (rm -rf is more thorough than cargo clean, which relies on its own stale
  # metadata) and disable sccache for the retry — a corrupt sccache cache
  # entry can cause "extern location does not exist" errors even on a
  # freshly-cleaned target dir, so falling back to raw rustc is safer.
  if ! cargo build $target_flag "$@"; then
    echo "cargo build failed; cleaning stale target cache and retrying without sccache..." >&2
    rm -rf /build/target/*
    mkdir -p "$(cross_output_dir "$profile")/deps"
    unset RUSTC_WRAPPER 2>/dev/null || true
    cargo build $target_flag "$@"
  fi
}

# ---------------------------------------------------------------------------
# Musl (static) build helpers
# ---------------------------------------------------------------------------

# Map Docker arch name to musl Rust target triple.
rust_target_musl() {
  case "$TARGETARCH" in
    arm64) echo "aarch64-unknown-linux-musl" ;;
    amd64) echo "x86_64-unknown-linux-musl" ;;
    *)     echo "unsupported TARGETARCH for musl: $TARGETARCH" >&2; return 1 ;;
  esac
}

# Install musl toolchain packages.  Native builds only need musl-tools;
# cross builds also need the GNU cross-compiler (used as linker for the
# foreign arch — Rust handles the musl libc linking).
install_musl_toolchain() {
  apt-get update
  apt-get install -y --no-install-recommends musl-tools cmake
  if is_cross; then
    case "$TARGETARCH" in
      arm64)
        dpkg --add-architecture arm64
        apt-get install -y --no-install-recommends \
          gcc-aarch64-linux-gnu g++-aarch64-linux-gnu ;;
      amd64)
        dpkg --add-architecture amd64
        apt-get install -y --no-install-recommends \
          gcc-x86-64-linux-gnu g++-x86-64-linux-gnu ;;
    esac
  fi
  rm -rf /var/lib/apt/lists/*
}

# Add the musl Rust compilation target.
add_musl_target() {
  rustup target add "$(rust_target_musl)"
}

# Export CC / CXX / linker env vars for a musl target.
export_musl_cross_env() {
  # For native musl builds, musl-gcc is provided by musl-tools and
  # handles everything — no extra env vars needed.
  is_cross || return 0
  case "$TARGETARCH" in
    arm64)
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc
      export CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc
      export CXX_aarch64_unknown_linux_musl=aarch64-linux-gnu-g++ ;;
    amd64)
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-gnu-gcc
      export CC_x86_64_unknown_linux_musl=x86_64-linux-gnu-gcc
      export CXX_x86_64_unknown_linux_musl=x86_64-linux-gnu-g++ ;;
  esac
}

# Run cargo build targeting musl with the correct --target and env vars.
# All extra arguments are forwarded to cargo.
cargo_musl_build() {
  export_musl_cross_env
  if [ -z "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]; then
    unset SCCACHE_MEMCACHED_ENDPOINT 2>/dev/null || true
  fi
  export SCCACHE_DIR="${SCCACHE_DIR:-/tmp/sccache}"
  if command -v sccache >/dev/null 2>&1; then
    export RUSTC_WRAPPER=sccache
  fi
  local target
  target="$(rust_target_musl)"
  local profile="debug"
  for arg in "$@"; do
    case "$arg" in --release) profile="release" ;; esac
  done
  local out_dir="/build/target/${target}/${profile}"
  mkdir -p "${out_dir}/deps"
  if ! cargo build --target "$target" "$@"; then
    echo "cargo musl build failed; cleaning and retrying without sccache..." >&2
    rm -rf /build/target/*
    mkdir -p "${out_dir}/deps"
    unset RUSTC_WRAPPER 2>/dev/null || true
    cargo build --target "$target" "$@"
  fi
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

# Print the directory containing the compiled binary.
# Usage: cp "$(cross_output_dir release)/my-binary" /out/
cross_output_dir() {
  local profile="${1:-release}"
  if is_cross; then
    echo "/build/target/$(rust_target)/$profile"
  else
    echo "/build/target/$profile"
  fi
}

# Print the musl build output directory.
# Usage: cp "$(musl_output_dir release)/my-binary" /out/
musl_output_dir() {
  local profile="${1:-release}"
  echo "/build/target/$(rust_target_musl)/$profile"
}
