#!/bin/sh

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

z3_asset_name_for_target() {
  case "${1:-}" in
    x86_64-unknown-linux-musl|aarch64-unknown-linux-musl|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|aarch64-apple-darwin)
      printf 'z3-%s.tar.gz\n' "$1"
      ;;
    *)
      echo "unsupported Z3 target: ${1:-<missing>}" >&2
      return 1
      ;;
  esac
}

z3_package_dir_name() {
  case "${1:-}" in
    x86_64-unknown-linux-musl|aarch64-unknown-linux-musl|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|aarch64-apple-darwin)
      printf 'z3-%s\n' "$1"
      ;;
    *)
      echo "unsupported Z3 target: ${1:-<missing>}" >&2
      return 1
      ;;
  esac
}

z3_release_url() {
  repo="${1:?repo is required}"
  tag="${2:?tag is required}"
  asset="${3:?asset is required}"
  printf 'https://github.com/%s/releases/download/%s/%s\n' "$repo" "$tag" "$asset"
}

z3_cpu_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu
  else
    echo 4
  fi
}
