#!/bin/sh
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

# True when the build host and target differ.
is_cross() { [ "$TARGETARCH" != "$BUILDARCH" ]; }

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
cargo_cross_build() {
  export_cross_env
  local target_flag=""
  if is_cross; then target_flag="--target $(rust_target)"; fi
  cargo build $target_flag "$@"
}

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
