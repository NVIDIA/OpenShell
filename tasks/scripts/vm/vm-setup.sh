#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# One-time setup for the openshell-vm runtime.
#
# Downloads pre-built runtime artifacts (libkrun, libkrunfw, gvproxy) from the
# vm-dev GitHub Release, or builds them from source when --from-source is set.
# After obtaining the runtime, compresses the artifacts for embedding into the
# openshell-vm binary.
#
# Usage:
#   ./vm-setup.sh                   # download pre-built (default, ~30s)
#   ./vm-setup.sh --from-source     # build from source (~15-45min)
#
# Environment:
#   FROM_SOURCE=1   - Equivalent to --from-source

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"
CLI_BIN="${ROOT}/scripts/bin/openshell"

FROM_SOURCE="${FROM_SOURCE:-0}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-source)
            FROM_SOURCE=1
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--from-source]"
            echo ""
            echo "Set up the openshell-vm runtime (libkrun, libkrunfw, gvproxy)."
            echo ""
            echo "Options:"
            echo "  --from-source   Build runtime from source instead of downloading (~15-45min)"
            echo ""
            echo "Environment:"
            echo "  FROM_SOURCE=1   Equivalent to --from-source"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Use --help for usage information" >&2
            exit 1
            ;;
    esac
done

PLATFORM="$(detect_platform)"
echo "==> openshell-vm setup"
echo "    Platform: ${PLATFORM}"
echo "    Mode:     $([ "$FROM_SOURCE" = "1" ] && echo "build from source" || echo "download pre-built")"
echo ""

# ── Obtain runtime artifacts ────────────────────────────────────────────

if [ "$FROM_SOURCE" = "1" ]; then
    echo "==> Building runtime from source..."
    echo ""

    case "$PLATFORM" in
        darwin-aarch64)
            # macOS: compile pre-built kernel.c into libkrunfw.dylib, then build libkrun.dylib.
            # The kernel.c file must be obtained from a Linux ARM64 build first.
            KERNEL_DIR="${ROOT}/target/libkrun-build"
            if [ ! -f "${KERNEL_DIR}/kernel.c" ]; then
                echo "Error: kernel.c not found at ${KERNEL_DIR}/kernel.c" >&2
                echo "" >&2
                echo "On macOS, the Linux kernel must be cross-compiled on a Linux host first." >&2
                echo "Either:" >&2
                echo "  1. Download pre-built runtime (default): mise run vm:setup" >&2
                echo "  2. Build kernel.c on Linux, copy to ${KERNEL_DIR}/, then re-run." >&2
                exit 1
            fi
            "${ROOT}/tasks/scripts/vm/build-libkrun-macos.sh" --kernel-dir "${KERNEL_DIR}"
            ;;
        linux-*)
            # Linux: build both libkrunfw and libkrun in one go
            "${ROOT}/tasks/scripts/vm/build-libkrun.sh"
            ;;
    esac
    echo ""
    echo "==> Compressing runtime artifacts for embedding..."
    "${ROOT}/tasks/scripts/vm/compress-vm-runtime.sh"
else
    echo "==> Downloading pre-built runtime..."
    "${ROOT}/tasks/scripts/vm/download-kernel-runtime.sh"
fi

# ── Validate ────────────────────────────────────────────────────────────

OUTPUT_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${ROOT}/target/vm-runtime-compressed}"

# Check that we have the essential compressed artifacts
missing=0
case "$PLATFORM" in
    darwin-aarch64)
        for f in libkrun.dylib.zst libkrunfw.5.dylib.zst gvproxy.zst; do
            if [ ! -f "${OUTPUT_DIR}/${f}" ]; then
                echo "ERROR: Missing ${OUTPUT_DIR}/${f}" >&2
                missing=1
            fi
        done
        ;;
    linux-aarch64|linux-x86_64)
        for f in libkrun.so.zst libkrunfw.so.5.zst gvproxy.zst; do
            if [ ! -f "${OUTPUT_DIR}/${f}" ]; then
                echo "ERROR: Missing ${OUTPUT_DIR}/${f}" >&2
                missing=1
            fi
        done
        ;;
esac

if [ "$missing" -eq 1 ]; then
    echo "" >&2
    echo "Setup failed: some runtime artifacts are missing." >&2
    exit 1
fi

echo ""
echo "==> Setup complete!"
echo "    Compressed artifacts in: ${OUTPUT_DIR}"
echo ""
echo "After starting the gateway:"
echo "  ${CLI_BIN} status"
echo "  ${CLI_BIN} sandbox create --name vm-test --from ubuntu:24.04"
