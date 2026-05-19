#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

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
  case "$1" in
    amd64)
      if [[ "$libc" == "musl" ]]; then
        echo "x86_64-unknown-linux-musl"
      else
        echo "x86_64-unknown-linux-gnu"
      fi
      ;;
    arm64)
      if [[ "$libc" == "musl" ]]; then
        echo "aarch64-unknown-linux-musl"
      else
        echo "aarch64-unknown-linux-gnu"
      fi
      ;;
    *)
      echo "unsupported architecture: $1" >&2
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

target_env_suffix() {
  echo "${1//-/_}" | tr '[:lower:]' '[:upper:]'
}

zig_target() {
  case "$1" in
    amd64) echo "x86_64-linux-musl" ;;
    arm64) echo "aarch64-linux-musl" ;;
    *)
      echo "unsupported architecture for Zig musl wrapper: $1" >&2
      exit 1
      ;;
  esac
}

find_zig() {
  if command -v zig >/dev/null 2>&1; then
    command -v zig
    return
  fi

  if command -v mise >/dev/null 2>&1; then
    mise which zig 2>/dev/null || true
  fi
}

zig_musl_wrapper() {
  local name=$1
  local tool=$2
  local target=$3
  local zig_bin
  local wrapper_dir
  local wrapper

  zig_bin="$(find_zig)"
  if [[ -z "$zig_bin" ]]; then
    echo "Error: building musl binaries requires Zig when no target C linker is configured." >&2
    echo "Run 'mise install --locked' or set the CARGO_TARGET_*_LINKER and CC_* env vars for the musl target." >&2
    exit 1
  fi

  wrapper_dir="${ROOT}/target/toolchain-wrappers"
  wrapper="${wrapper_dir}/${name}"
  mkdir -p "$wrapper_dir"
  cat >"$wrapper" <<EOF
#!/usr/bin/env bash
set -euo pipefail

args=()
for arg in "\$@"; do
  case "\$arg" in
    --target=*) ;;
    *) args+=("\$arg") ;;
  esac
done

exec "${zig_bin}" "${tool}" --target="${target}" "\${args[@]}"
EOF
  chmod +x "$wrapper"
  echo "$wrapper"
}

append_rustflag_if_missing() {
  local var=$1
  local flag=$2
  local current=${!var:-}

  case " ${current} " in
    *" ${flag} "*) ;;
    *) export "$var=${current:+$current }$flag" ;;
  esac
}

configure_musl_toolchain() {
  local arch=$1
  local target=$2
  local env_suffix
  local cc_var
  local cxx_var
  local linker_var
  local rustflags_var
  local ztarget
  local cc_wrapper=""
  local cxx_wrapper=""
  local configured=0

  if [[ "$target_libc" != "musl" ]]; then
    return
  fi

  env_suffix="$(target_env_suffix "$target")"
  cc_var="CC_${target//-/_}"
  cxx_var="CXX_${target//-/_}"
  linker_var="CARGO_TARGET_${env_suffix}_LINKER"
  rustflags_var="CARGO_TARGET_${env_suffix}_RUSTFLAGS"
  ztarget="$(zig_target "$arch")"

  if [[ -z "${!cc_var:-}" ]]; then
    cc_wrapper="$(zig_musl_wrapper "openshell-zig-${ztarget}-cc" "cc" "$ztarget")"
    export "$cc_var=$cc_wrapper"
    configured=1
  fi

  if [[ -z "${!cxx_var:-}" ]]; then
    cxx_wrapper="$(zig_musl_wrapper "openshell-zig-${ztarget}-cxx" "c++" "$ztarget")"
    export "$cxx_var=$cxx_wrapper"
    configured=1
  fi

  if [[ -z "${!linker_var:-}" ]]; then
    if [[ -z "$cc_wrapper" ]]; then
      cc_wrapper="$(zig_musl_wrapper "openshell-zig-${ztarget}-cc" "cc" "$ztarget")"
    fi
    export "$linker_var=$cc_wrapper"
    append_rustflag_if_missing "$rustflags_var" "-Clink-self-contained=no"
    configured=1
  fi

  if [[ "$configured" == "1" ]]; then
    echo "Using Zig musl toolchain wrappers for ${target}"
  fi
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
      crate=openshell-server
      binary=openshell-gateway
      target_libc=gnu
      ;;
    supervisor)
      crate=openshell-sandbox
      binary=openshell-sandbox
      target_libc=musl
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
  local cargo_subcommand
  local current_host_os
  local current_host_arch

  resolve_component "$component"
  target="$(target_triple "$arch" "$target_libc")"
  stage="${ROOT}/deploy/docker/.build/prebuilt-binaries/${arch}"
  features="${EXTRA_CARGO_FEATURES:-openshell-core/dev-settings}"
  current_host_os="$(host_os)"
  current_host_arch="$(host_arch)"

  cargo_subcommand=(cargo build)
  if [[ "$current_host_os" != "Linux" || "$current_host_arch" != "$arch" ]]; then
    if command -v cargo-zigbuild >/dev/null 2>&1 || mise which cargo-zigbuild >/dev/null 2>&1; then
      cargo_subcommand=(cargo zigbuild)
    else
      echo "Error: cannot build ${binary} for linux/${arch} on ${current_host_os}/${current_host_arch}." >&2
      echo "Install cargo-zigbuild + zig, build on a matching Linux host, or provide prebuilt binaries in:" >&2
      echo "  deploy/docker/.build/prebuilt-binaries/${arch}/" >&2
      exit 1
    fi
  fi

  echo "Building ${binary} for linux/${arch} (${target})..."
  mise x -- rustup target add "$target" >/dev/null 2>&1 || true
  configure_musl_toolchain "$arch" "$target"

  args=(
    --release
    --target "$target"
    -p "$crate"
    --bin "$binary"
  )
  if [[ -n "$features" ]]; then
    args+=(--features "$features")
  fi

  (
    cd "$ROOT"
    if [[ -n "${OPENSHELL_CARGO_VERSION:-}" ]]; then
      export GIT_DIR=/nonexistent
    fi
    CARGO_INCREMENTAL=0 mise x -- "${cargo_subcommand[@]}" "${args[@]}"
  )

  mkdir -p "$stage"
  install -m 0755 "${ROOT}/target/${target}/release/${binary}" "${stage}/${binary}"
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

restore_cargo_toml=0
trap restore_workspace_version EXIT

patch_workspace_version

arches=()
while IFS= read -r _a; do arches+=("$_a"); done < <(detect_arches)
read -r -a components <<< "$(components_for_target "$target")"

for arch in "${arches[@]}"; do
  for component in "${components[@]}"; do
    build_component_for_arch "$component" "$arch"
  done
done
