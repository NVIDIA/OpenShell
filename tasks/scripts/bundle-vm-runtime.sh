#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "vm:bundle-runtime currently supports macOS only" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB_DIR="${OPENSHELL_VM_RUNTIME_SOURCE_DIR:-}"
GVPROXY_BIN="${OPENSHELL_VM_GVPROXY:-}"

if [ -z "$LIB_DIR" ]; then
  BREW_PREFIX="$(brew --prefix 2>/dev/null || true)"
  if [ -n "$BREW_PREFIX" ]; then
    LIB_DIR="${BREW_PREFIX}/lib"
  else
    LIB_DIR="/opt/homebrew/lib"
  fi
fi

if [ -z "$GVPROXY_BIN" ]; then
  if command -v gvproxy >/dev/null 2>&1; then
    GVPROXY_BIN="$(command -v gvproxy)"
  elif [ -x /opt/homebrew/bin/gvproxy ]; then
    GVPROXY_BIN="/opt/homebrew/bin/gvproxy"
  elif [ -x /opt/podman/bin/gvproxy ]; then
    GVPROXY_BIN="/opt/podman/bin/gvproxy"
  else
    echo "gvproxy not found; set OPENSHELL_VM_GVPROXY or install gvproxy" >&2
    exit 1
  fi
fi

LIBKRUN="${LIB_DIR}/libkrun.dylib"
if [ ! -e "$LIBKRUN" ]; then
  echo "libkrun not found at ${LIBKRUN}; set OPENSHELL_VM_RUNTIME_SOURCE_DIR" >&2
  exit 1
fi

KRUNFW_FILES=()
while IFS= read -r line; do
  KRUNFW_FILES+=("$line")
done < <(find "$LIB_DIR" -maxdepth 1 \( -type f -o -type l \) \( -name 'libkrunfw.dylib' -o -name 'libkrunfw.*.dylib' \) | sort -u)

if [ "${#KRUNFW_FILES[@]}" -eq 0 ]; then
  echo "libkrunfw not found under ${LIB_DIR}; set OPENSHELL_VM_RUNTIME_SOURCE_DIR" >&2
  exit 1
fi

TARGETS=(
  "${ROOT}/target/debug"
  "${ROOT}/target/release"
  "${ROOT}/target/aarch64-apple-darwin/debug"
  "${ROOT}/target/aarch64-apple-darwin/release"
)

for target_dir in "${TARGETS[@]}"; do
  runtime_dir="${target_dir}/gateway.runtime"
  mkdir -p "$runtime_dir"

  install -m 0644 "$LIBKRUN" "${runtime_dir}/libkrun.dylib"
  install -m 0755 "$GVPROXY_BIN" "${runtime_dir}/gvproxy"
  for krunfw in "${KRUNFW_FILES[@]}"; do
    install -m 0644 "$krunfw" "${runtime_dir}/$(basename "$krunfw")"
  done

  manifest_entries=()
  manifest_entries+=('    "libkrun.dylib"')
  manifest_entries+=('    "gvproxy"')
  for krunfw in "${KRUNFW_FILES[@]}"; do
    manifest_entries+=("    \"$(basename "$krunfw")\"")
  done

  cat > "${runtime_dir}/manifest.json" <<EOF
{
  "target": "aarch64-apple-darwin",
  "files": [
$(IFS=$',\n'; printf '%s\n' "${manifest_entries[*]}")
  ]
}
EOF

  echo "staged runtime bundle in ${runtime_dir}"
done
