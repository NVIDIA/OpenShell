#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Remove all openshell-vm cached artifacts.
#
# Use this when you need a clean slate — after running this, you will need to
# re-run `mise run vm:setup` before building again.
#
# Usage:
#   ./vm-clean.sh           # clean VM-specific artifacts
#   ./vm-clean.sh --all     # also remove the compiled binary

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

CLEAN_ALL=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            CLEAN_ALL=1
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--all]"
            echo ""
            echo "Remove all openshell-vm cached build artifacts."
            echo ""
            echo "Options:"
            echo "  --all   Also remove compiled binaries (target/debug/openshell-vm)"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

echo "==> Cleaning openshell-vm artifacts..."

removed=0

remove_if_exists() {
    local path="$1"
    local label="$2"
    if [ -e "$path" ]; then
        local size
        size="$(du -sh "$path" 2>/dev/null | cut -f1 || echo "?")"
        rm -rf "$path"
        echo "    Removed ${label} (${size}): ${path}"
        removed=$((removed + 1))
    fi
}

# Build artifacts under target/
remove_if_exists "${ROOT}/target/vm-runtime"              "uncompressed staging"
remove_if_exists "${ROOT}/target/vm-runtime-compressed"   "compressed artifacts"
remove_if_exists "${ROOT}/target/vm-runtime-download"     "downloaded tarballs"
remove_if_exists "${ROOT}/target/vm-runtime-extracted"    "extraction temp"
remove_if_exists "${ROOT}/target/libkrun-build"           "libkrun source build"
remove_if_exists "${ROOT}/target/custom-runtime"          "custom libkrunfw"
remove_if_exists "${ROOT}/target/rootfs-build"            "rootfs directory"

# Named instance rootfs directories
XDG_DATA="${XDG_DATA_HOME:-${HOME}/.local/share}"
VM_DATA_DIR="${XDG_DATA}/openshell/openshell-vm"
remove_if_exists "${VM_DATA_DIR}" "named instance rootfs"

# Embedded runtime cache
VM_RUNTIME_CACHE="${XDG_DATA}/openshell/vm-runtime"
remove_if_exists "${VM_RUNTIME_CACHE}" "embedded runtime cache"

if [ "$CLEAN_ALL" -eq 1 ]; then
    # Remove compiled binaries and sidecar bundles
    for profile in debug release; do
        remove_if_exists "${ROOT}/target/${profile}/openshell-vm"          "${profile} binary"
        remove_if_exists "${ROOT}/target/${profile}/openshell-vm.runtime"  "${profile} runtime bundle"
    done
fi

echo ""
if [ "$removed" -eq 0 ]; then
    echo "    Nothing to clean."
else
    echo "    Removed ${removed} item(s)."
fi
echo ""
echo "Next step: mise run vm:setup"
