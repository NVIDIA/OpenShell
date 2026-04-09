#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Stage the openshell-vm sidecar runtime bundle next to local build outputs.
#
# Copies the uncompressed VM runtime libraries (libkrun, libkrunfw, gvproxy)
# from target/vm-runtime/ into the .runtime sidecar directories alongside
# each build output.  This is required for:
#   - build-rootfs.sh pre-initialization (boots the real VM to pre-bake k3s state)
#   - Direct invocation of target/debug/openshell-vm without embedding
#
# The source artifacts are collected by compress-vm-runtime.sh into
# target/vm-runtime/ before compression; this script re-uses that work dir.
#
# Usage:
#   ./tasks/scripts/vm/bundle-vm-runtime.sh

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

SOURCE_DIR="${ROOT}/target/vm-runtime"

if [ ! -d "${SOURCE_DIR}" ]; then
    echo "ERROR: VM runtime source not found at ${SOURCE_DIR}"
    echo "       Run: mise run vm:setup"
    exit 1
fi

# Verify required files are present
for required in libkrun.so gvproxy; do
    if ! ls "${SOURCE_DIR}/${required}" >/dev/null 2>&1; then
        # Try platform-specific variants
        if [ "$required" = "libkrun.so" ] && ls "${SOURCE_DIR}"/libkrun.dylib >/dev/null 2>&1; then
            continue
        fi
        echo "ERROR: Required runtime file not found: ${SOURCE_DIR}/${required}"
        echo "       Run: mise run vm:setup"
        exit 1
    fi
done

TARGETS=(
    "${ROOT}/target/debug"
    "${ROOT}/target/release"
)

for target_dir in "${TARGETS[@]}"; do
    # Only stage if the binary exists (avoid creating orphan runtime dirs)
    if [ ! -f "${target_dir}/openshell-vm" ] && [ ! -f "${target_dir}/openshell-vm.d" ]; then
        continue
    fi

    runtime_dir="${target_dir}/openshell-vm.runtime"
    mkdir -p "${runtime_dir}"

    for file in "${SOURCE_DIR}"/*; do
        [ -f "$file" ] || continue
        name="$(basename "$file")"
        install -m 0755 "$file" "${runtime_dir}/${name}"
    done

    echo "staged runtime bundle in ${runtime_dir}"
done
