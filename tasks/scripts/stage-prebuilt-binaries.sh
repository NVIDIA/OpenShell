#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

usage() {
  echo "Usage: stage-prebuilt-binaries.sh <gateway|sandbox|supervisor|cluster|supervisor-output|all>" >&2
}

normalize_arch() {
  case "$1" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "$1" ;;
  esac
}

target_triple() {
  case "$1" in
    amd64) echo "x86_64-unknown-linux-gnu" ;;
    arm64) echo "aarch64-unknown-linux-gnu" ;;
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
    sandbox|supervisor|cluster|supervisor-output)
      echo "sandbox"
      ;;
    all)
      echo "gateway sandbox"
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
      ;;
    sandbox)
      crate=openshell-sandbox
      binary=openshell-sandbox
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
  target="$(target_triple "$arch")"
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

mapfile -t arches < <(detect_arches)
read -r -a components <<< "$(components_for_target "$target")"

for arch in "${arches[@]}"; do
  for component in "${components[@]}"; do
    build_component_for_arch "$component" "$arch"
  done
done
