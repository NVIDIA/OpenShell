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
  # Prefer the custom runtime (has bridge/netfilter kernel support) over
  # the stock Homebrew libkrunfw which lacks these capabilities.
  CUSTOM_RUNTIME_DIR="${ROOT}/target/custom-runtime"
  if [ -f "${CUSTOM_RUNTIME_DIR}/provenance.json" ] && [ -e "${CUSTOM_RUNTIME_DIR}/libkrunfw.dylib" ]; then
    LIB_DIR="${CUSTOM_RUNTIME_DIR}"
    echo "using custom runtime at ${LIB_DIR}"
  else
    BREW_PREFIX="$(brew --prefix 2>/dev/null || true)"
    if [ -n "$BREW_PREFIX" ]; then
      LIB_DIR="${BREW_PREFIX}/lib"
    else
      LIB_DIR="/opt/homebrew/lib"
    fi
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

# libkrun.dylib: prefer the custom runtime dir, fall back to Homebrew.
# libkrun is the VMM and does not need a custom build; only libkrunfw
# carries the custom kernel.
LIBKRUN="${LIB_DIR}/libkrun.dylib"
if [ ! -e "$LIBKRUN" ]; then
  BREW_PREFIX="${BREW_PREFIX:-$(brew --prefix 2>/dev/null || true)}"
  if [ -n "$BREW_PREFIX" ] && [ -e "${BREW_PREFIX}/lib/libkrun.dylib" ]; then
    LIBKRUN="${BREW_PREFIX}/lib/libkrun.dylib"
    echo "using Homebrew libkrun at ${LIBKRUN}"
  else
    echo "libkrun not found at ${LIB_DIR}/libkrun.dylib or Homebrew; install libkrun or set OPENSHELL_VM_RUNTIME_SOURCE_DIR" >&2
    exit 1
  fi
fi

KRUNFW_FILES=()
while IFS= read -r line; do
  KRUNFW_FILES+=("$line")
done < <(find "$LIB_DIR" -maxdepth 1 \( -type f -o -type l \) \( -name 'libkrunfw.dylib' -o -name 'libkrunfw.*.dylib' \) | sort -u)

if [ "${#KRUNFW_FILES[@]}" -eq 0 ]; then
  echo "libkrunfw not found under ${LIB_DIR}; set OPENSHELL_VM_RUNTIME_SOURCE_DIR" >&2
  exit 1
fi

# Check for provenance.json (custom runtime indicator)
PROVENANCE_FILE="${LIB_DIR}/provenance.json"
IS_CUSTOM="false"
if [ -f "$PROVENANCE_FILE" ]; then
  IS_CUSTOM="true"
  echo "custom runtime detected (provenance.json present)"
fi

TARGETS=(
  "${ROOT}/target/debug"
  "${ROOT}/target/release"
  "${ROOT}/target/aarch64-apple-darwin/debug"
  "${ROOT}/target/aarch64-apple-darwin/release"
)

for target_dir in "${TARGETS[@]}"; do
  runtime_dir="${target_dir}/openshell-vm.runtime"
  mkdir -p "$runtime_dir"

  install -m 0644 "$LIBKRUN" "${runtime_dir}/libkrun.dylib"
  install -m 0755 "$GVPROXY_BIN" "${runtime_dir}/gvproxy"
  for krunfw in "${KRUNFW_FILES[@]}"; do
    install -m 0644 "$krunfw" "${runtime_dir}/$(basename "$krunfw")"
  done

  # Copy provenance.json if this is a custom runtime.
  if [ "$IS_CUSTOM" = "true" ] && [ -f "$PROVENANCE_FILE" ]; then
    install -m 0644 "$PROVENANCE_FILE" "${runtime_dir}/provenance.json"
  fi

  manifest_entries=()
  manifest_entries+=('    "libkrun.dylib"')
  manifest_entries+=('    "gvproxy"')
  for krunfw in "${KRUNFW_FILES[@]}"; do
    manifest_entries+=("    \"$(basename "$krunfw")\"")
  done
  if [ "$IS_CUSTOM" = "true" ]; then
    manifest_entries+=('    "provenance.json"')
  fi

  cat > "${runtime_dir}/manifest.json" <<EOF
{
  "target": "aarch64-apple-darwin",
  "custom": ${IS_CUSTOM},
  "files": [
$(IFS=$',\n'; printf '%s\n' "${manifest_entries[*]}")
  ]
}
EOF

  echo "staged runtime bundle in ${runtime_dir}"
done
