#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUNTIME_DIR="${ROOT}/target/debug/openshell-vm.runtime"
GATEWAY_BIN="${ROOT}/target/debug/openshell-vm"

if [ "$(uname -s)" = "Darwin" ]; then
  export DYLD_FALLBACK_LIBRARY_PATH="${RUNTIME_DIR}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
fi

args=("$@")
name="default"
rootfs_args=()
expect_name=0
expect_rootfs=0
subcommand=""
skip_prepare=0

for arg in "${args[@]}"; do
  if [ "${expect_name}" -eq 1 ]; then
    name="${arg}"
    expect_name=0
    continue
  fi

  if [ "${expect_rootfs}" -eq 1 ]; then
    rootfs_args=(--rootfs "${arg}")
    expect_rootfs=0
    continue
  fi

  case "${arg}" in
    --name)
      expect_name=1
      ;;
    --name=*)
      name="${arg#--name=}"
      ;;
    --rootfs)
      expect_rootfs=1
      ;;
    --rootfs=*)
      rootfs_args=("${arg}")
      ;;
    --help|-h|--version)
      skip_prepare=1
      ;;
    exec|prepare-rootfs)
      subcommand="${arg}"
      break
      ;;
  esac
done

if [ "${skip_prepare}" -eq 0 ] && [ -z "${subcommand}" ]; then
  prep_args=(--name "${name}")
  if [ "${#rootfs_args[@]}" -gt 0 ]; then
    prep_args=("${rootfs_args[@]}" "${prep_args[@]}")
  fi
  resolved_rootfs="$("${ROOT}/tasks/scripts/vm/ensure-vm-rootfs.sh" "${prep_args[@]}" \
    | tail -n 1 | sed 's/^using openshell-vm rootfs at //')"
  "${ROOT}/tasks/scripts/vm/sync-vm-rootfs.sh" "${prep_args[@]}"

  # When no --rootfs was supplied by the caller, inject the resolved rootfs path
  # so the binary finds the rootfs regardless of whether it is embedded.
  if [ "${#rootfs_args[@]}" -eq 0 ] && [ -n "${resolved_rootfs}" ]; then
    args=(--rootfs "${resolved_rootfs}" "${args[@]}")
  fi
fi

exec "${GATEWAY_BIN}" "${args[@]}"
