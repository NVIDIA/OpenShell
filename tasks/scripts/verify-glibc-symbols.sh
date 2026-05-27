#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "Usage: verify-glibc-symbols.sh <max-glibc-version> <binary> [binary ...]" >&2
}

version_gt() {
  local left=$1
  local right=$2
  local left_major=${left%%.*}
  local left_minor=${left#*.}
  local right_major=${right%%.*}
  local right_minor=${right#*.}

  left_minor=${left_minor%%.*}
  right_minor=${right_minor%%.*}

  [[ $left_major =~ ^[0-9]+$ && $left_minor =~ ^[0-9]+$ ]] || return 1
  [[ $right_major =~ ^[0-9]+$ && $right_minor =~ ^[0-9]+$ ]] || return 1

  (( left_major > right_major )) && return 0
  (( left_major < right_major )) && return 1
  (( left_minor > right_minor ))
}

extract_glibc_versions() {
  local binary=$1

  if command -v readelf >/dev/null 2>&1; then
    readelf --version-info "$binary" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' || true
  elif command -v objdump >/dev/null 2>&1; then
    objdump -T "$binary" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' || true
  fi
}

if [[ $# -lt 2 ]]; then
  usage
  exit 2
fi

max_version=$1
shift
failed=0

if ! command -v readelf >/dev/null 2>&1 && ! command -v objdump >/dev/null 2>&1; then
  echo "error: readelf or objdump is required to inspect GLIBC symbol versions" >&2
  exit 2
fi

for binary in "$@"; do
  if [[ ! -f $binary ]]; then
    echo "error: binary not found: $binary" >&2
    failed=1
    continue
  fi

  echo "==> Inspecting $binary"
  if command -v file >/dev/null 2>&1; then
    file "$binary" || true
  else
    echo "file: not available"
  fi

  if command -v ldd >/dev/null 2>&1; then
    ldd "$binary" || true
  else
    echo "ldd: not available"
  fi

  highest=
  found=0
  while IFS= read -r version; do
    version=${version#GLIBC_}
    found=1

    if [[ -z $highest ]] || version_gt "$version" "$highest"; then
      highest=$version
    fi

    if version_gt "$version" "$max_version"; then
      echo "error: $binary references GLIBC_${version}, above allowed GLIBC_${max_version}" >&2
      failed=1
    fi
  done < <(extract_glibc_versions "$binary")

  if [[ $found -eq 0 ]]; then
    echo "highest GLIBC symbol: none"
    continue
  fi

  echo "highest GLIBC symbol: GLIBC_${highest}"
done

exit "$failed"
