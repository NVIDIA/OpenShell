#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=tasks/scripts/build-env.sh
source "${SCRIPT_DIR}/build-env.sh"

usage() {
  echo "Usage: stage-prebuilt-binaries.sh <gateway|sandbox|supervisor|supervisor-output|all>" >&2
}

normalize_arch() {
  case "$1" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "$1" ;;
  esac
}

target_triple() {
  local libc=${2:-gnu}
  local suffix
  case "$libc" in
    musl) suffix=musl ;;
    # gnu-static builds the GNU target with +crt-static, so it shares the
    # gnu triple.
    gnu|gnu-static) suffix=gnu ;;
    *)
      echo "unsupported libc: $libc" >&2
      exit 1
      ;;
  esac
  case "$1" in
    amd64) echo "x86_64-unknown-linux-${suffix}" ;;
    arm64) echo "aarch64-unknown-linux-${suffix}" ;;
    *)
      echo "unsupported architecture: $1" >&2
      exit 1
      ;;
  esac
}

# Resolve the supervisor libc variant. Both options produce a fully static
# binary because the supervisor is executed from inside arbitrary sandbox
# images; see verify-static-binary.sh.
#
# Scope: this selects the libc for the supervisor *image* binary. The VM driver
# bundles its own supervisor build (tasks/scripts/vm/build-supervisor-bundle.sh)
# and is not affected by this setting.
supervisor_libc() {
  local selection=${SUPERVISOR_LIBC:-musl}
  case "$selection" in
    musl) echo "musl" ;;
    glibc-static) echo "gnu-static" ;;
    *)
      echo "unsupported SUPERVISOR_LIBC: ${selection} (expected musl or glibc-static)" >&2
      exit 1
      ;;
  esac
}

host_arch() {
  normalize_arch "$(uname -m)"
}

host_os() {
  uname -s
}

has_cargo_zigbuild() {
  command -v cargo-zigbuild >/dev/null 2>&1 || mise which cargo-zigbuild >/dev/null 2>&1
}

detect_arches() {
  if [[ -n "${PREBUILT_ARCH:-}" ]]; then
    normalize_arch "${PREBUILT_ARCH}"
    return
  fi

  if [[ -n "${DOCKER_PLATFORM:-}" ]]; then
    local raw_platforms=${DOCKER_PLATFORM//[[:space:]]/}
    local platform
    IFS=',' read -r -a platforms <<< "$raw_platforms"
    for platform in "${platforms[@]}"; do
      case "$platform" in
        linux/amd64) echo "amd64" ;;
        linux/arm64) echo "arm64" ;;
        *)
          echo "unsupported Docker platform for prebuilt binaries: $platform" >&2
          exit 1
          ;;
      esac
    done
    return
  fi

  host_arch
}

components_for_target() {
  case "$1" in
    gateway)
      echo "gateway"
      ;;
    sandbox|supervisor|supervisor-output)
      echo "supervisor"
      ;;
    all)
      echo "gateway supervisor"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

resolve_component() {
  case "$1" in
    gateway)
      crate=openshell-gateway
      binary=openshell-gateway
      target_libc=gnu
      ;;
    supervisor)
      crate=openshell-sandbox
      binary=openshell-sandbox
      target_libc=$(supervisor_libc)
      ;;
    *)
      echo "unsupported binary component: $1" >&2
      exit 1
      ;;
  esac
}

patch_workspace_version() {
  if [[ -z "${OPENSHELL_CARGO_VERSION:-}" ]]; then
    return
  fi

  cargo_toml="${ROOT}/Cargo.toml"
  cargo_toml_backup="$(mktemp)"
  cp "$cargo_toml" "$cargo_toml_backup"
  restore_cargo_toml=1
  sed -i -E '/^\[workspace\.package\]/,/^\[/{s/^version[[:space:]]*=[[:space:]]*".*"/version = "'"${OPENSHELL_CARGO_VERSION}"'"/}' "$cargo_toml"
}

restore_workspace_version() {
  if [[ "${restore_cargo_toml:-0}" == "1" ]]; then
    cp "$cargo_toml_backup" "$cargo_toml"
    rm -f "$cargo_toml_backup"
  fi
}

build_component_for_arch() {
  local component=$1
  local arch=$2
  local target
  local stage
  local features
  local -a cargo_subcommand
  local -a cargo_env
  local build_target
  local current_host_os
  local current_host_arch
  local binary_path
  local build_rustflags

  resolve_component "$component"
  target="$(target_triple "$arch" "$target_libc")"
  stage="${ROOT}/deploy/docker/.build/prebuilt-binaries/${arch}"
  features="${EXTRA_CARGO_FEATURES:-}"
  if [[ "$component" == "gateway" && " ${features} " != *" bundled-z3 "* ]]; then
    features="${features} bundled-z3"
  fi
  current_host_os="$(host_os)"
  current_host_arch="$(host_arch)"

  cargo_subcommand=(cargo build)
  cargo_env=()
  build_target="$target"
  build_rustflags="${RUSTFLAGS:-}"

  if [[ "$component" == "gateway" ]]; then
    if has_cargo_zigbuild; then
      cargo_subcommand=(cargo zigbuild)
      build_target="${target}.2.28"
    else
      echo "Error: cargo-zigbuild + zig are required to build ${binary} with the glibc 2.28 floor." >&2
      exit 1
    fi
  elif [[ "$target_libc" == "gnu-static" ]]; then
    # `zig cc` accepts `-static` for *-linux-gnu and emits a dynamically linked
    # binary anyway, so cargo-zigbuild cannot produce this variant and there is
    # no cross-compile fallback. Require a native toolchain that can link glibc
    # statically (Fedora/RHEL: glibc-static, Debian/Ubuntu: libc6-dev).
    build_rustflags="${build_rustflags} -C target-feature=+crt-static"
    if [[ "$current_host_os" != "Linux" || "$current_host_arch" != "$arch" ]]; then
      echo "Error: SUPERVISOR_LIBC=glibc-static cannot build ${binary} for linux/${arch} on ${current_host_os}/${current_host_arch}." >&2
      echo "cargo-zigbuild cannot statically link glibc, so this variant has no cross-compile path." >&2
      echo "Build on a linux/${arch} host with glibc static libraries installed, use SUPERVISOR_LIBC=musl," >&2
      echo "or provide prebuilt binaries in:" >&2
      echo "  deploy/docker/.build/prebuilt-binaries/${arch}/" >&2
      exit 1
    fi
  elif [[ "$target_libc" == "musl" ]] && has_cargo_zigbuild; then
    cargo_subcommand=(cargo zigbuild)
  elif [[ "$current_host_os" != "Linux" || "$current_host_arch" != "$arch" ]]; then
    if has_cargo_zigbuild; then
      cargo_subcommand=(cargo zigbuild)
    else
      echo "Error: cannot build ${binary} for linux/${arch} on ${current_host_os}/${current_host_arch}." >&2
      echo "Install cargo-zigbuild + zig, build on a matching Linux host, or provide prebuilt binaries in:" >&2
      echo "  deploy/docker/.build/prebuilt-binaries/${arch}/" >&2
      exit 1
    fi
  fi

  if [[ "${OPENSHELL_AUDITABLE:-0}" == "1" ]]; then
    cargo_subcommand=("${cargo_subcommand[0]}" auditable "${cargo_subcommand[@]:1}")
    # mise.toml injects RUSTC_WRAPPER=sccache. Unset it after mise constructs
    # the environment so it cannot wrap cargo-auditable's workspace wrapper.
    cargo_env=(env -u RUSTC_WRAPPER)
  fi

  echo "Building ${binary} for linux/${arch} (${build_target}, libc: ${target_libc})..."
  mise x -- rustup target add "$target" >/dev/null 2>&1 || true

  args=(
    --release
    --target "$build_target"
    -p "$crate"
    --bin "$binary"
  )
  if [[ -n "$features" ]]; then
    args+=(--features "$features")
  fi

  (
    cd "$ROOT"
    if [[ "$component" == "gateway" ]]; then
      eval "$("$SCRIPT_DIR/setup-zig-cc-wrapper.sh" "$build_target" "$build_target" "$ROOT/target/zig-gnu-wrapper/$arch")"
    fi
    if [[ -n "${OPENSHELL_CARGO_VERSION:-}" ]]; then
      export GIT_DIR=/nonexistent
    fi
    if [[ -n "$build_rustflags" ]]; then
      export RUSTFLAGS="$build_rustflags"
    fi
    CARGO_INCREMENTAL=0 mise x -- "${cargo_env[@]}" "${cargo_subcommand[@]}" "${args[@]}"
  )

  binary_path="${ROOT}/target/${target}/release/${binary}"
  if [[ "$component" == "gateway" ]]; then
    "$SCRIPT_DIR/verify-glibc-symbols.sh" 2.28 "$binary_path"
  elif [[ "$component" == "supervisor" ]]; then
    "$SCRIPT_DIR/verify-static-binary.sh" "$binary_path"
  fi

  mkdir -p "$stage"
  install -m 0755 "$binary_path" "${stage}/${binary}"
  ls -lh "${stage}/${binary}"
}

target=${1:-all}
if [[ "$#" -gt 0 ]]; then
  shift
fi
if [[ "$#" -gt 0 ]]; then
  usage
  exit 1
fi

case "${OPENSHELL_AUDITABLE:-0}" in
  0|1) ;;
  *)
    echo "unsupported OPENSHELL_AUDITABLE: ${OPENSHELL_AUDITABLE} (expected 0 or 1)" >&2
    exit 1
    ;;
esac

restore_cargo_toml=0
trap restore_workspace_version EXIT

# Raise the open-file limit before any host cargo-zigbuild cross-compile. This
# single chokepoint covers the docker, podman, and all docker:*/multiarch host
# staging paths. No-op on Linux and when cargo-zigbuild is absent.
ensure_build_nofile_limit

patch_workspace_version

arches=()
while IFS= read -r _a; do arches+=("$_a"); done < <(detect_arches)
read -r -a components <<< "$(components_for_target "$target")"

for arch in "${arches[@]}"; do
  for component in "${components[@]}"; do
    build_component_for_arch "$component" "$arch"
  done
done
