#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GATEWAY_BIN="${ROOT}/target/debug/openshell-vm"

NAME="default"
ROOTFS_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      NAME="$2"
      shift 2
      ;;
    --name=*)
      NAME="${1#--name=}"
      shift
      ;;
    --rootfs)
      ROOTFS_ARGS=("$1" "$2")
      shift 2
      ;;
    --rootfs=*)
      ROOTFS_ARGS=("$1")
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [ ! -x "${GATEWAY_BIN}" ]; then
  echo "ERROR: openshell-vm binary not found at ${GATEWAY_BIN}" >&2
  echo "       Run: mise run vm:build" >&2
  exit 1
fi

prepare_args=(--name "${NAME}")
if [ "${#ROOTFS_ARGS[@]}" -gt 0 ]; then
  prepare_args=("${ROOTFS_ARGS[@]}" "${prepare_args[@]}")
fi
if [ "${OPENSHELL_VM_FORCE_ROOTFS_REBUILD:-}" = "1" ]; then
  prepare_args+=(prepare-rootfs --force)
else
  prepare_args+=(prepare-rootfs)
fi

if ROOTFS_PATH="$("${GATEWAY_BIN}" "${prepare_args[@]}" 2>/dev/null)"; then
  echo "using openshell-vm rootfs at ${ROOTFS_PATH}"
  exit 0
fi

# prepare-rootfs failed — no embedded rootfs in the binary.
# Fall back to target/rootfs-build if it exists (rootfs was built separately
# but not yet compressed for embedding via mise run vm:rootfs).
if [ "${#ROOTFS_ARGS[@]}" -eq 0 ]; then
  FALLBACK_ROOTFS="${ROOT}/target/rootfs-build"
  if [ -d "${FALLBACK_ROOTFS}/srv" ]; then
    echo "using openshell-vm rootfs at ${FALLBACK_ROOTFS}"
    exit 0
  fi
fi

echo "ERROR: No rootfs available." >&2
echo "       Run: mise run vm:rootfs -- --base   # build rootfs (~5-10 min, requires Docker)" >&2
exit 1
