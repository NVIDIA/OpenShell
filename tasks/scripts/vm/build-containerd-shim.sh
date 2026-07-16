#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the openshell-containerd-shim cgo shared library and stage it as a
# compressed artifact next to libkrun/libkrunfw/gvproxy/umoci.
#
# Unlike those, this shim is small, pure Go source vendored in this repo
# (crates/openshell-driver-vm/goshim/), so it is always built locally from
# source rather than downloaded from a release. It wraps containerd's Go
# client libraries (core/remotes/docker, pkg/archive) to resolve/pull OCI
# registry images and unpack layers, and is loaded at runtime by
# crates/openshell-driver-vm/src/containerd_shim.rs via libloading — the
# same way the driver loads libkrun.
#
# Usage:
#   ./build-containerd-shim.sh
#
# Cross-compiles when GOOS/GOARCH/CC are set (used by
# deploy/docker/Dockerfile.driver-vm-macos to cross-build the macOS dylib
# from a Linux container via osxcross); otherwise builds natively for the
# current host.
#
# Environment:
#   OPENSHELL_VM_RUNTIME_COMPRESSED_DIR - Output directory (default: target/vm-runtime-compressed)
#   GOOS, GOARCH, CC                    - Cross-compilation target (all three, or none)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

GOSHIM_DIR="${ROOT}/crates/openshell-driver-vm/goshim"
WORK_DIR="${ROOT}/target/containerd-shim-build"
OUTPUT_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${ROOT}/target/vm-runtime-compressed}"

if ! command -v go >/dev/null 2>&1; then
    echo "Error: go toolchain not found. Install Go (https://go.dev/dl/) and retry." >&2
    exit 1
fi

TARGET_GOOS="${GOOS:-$( [ "$(uname -s)" = Darwin ] && echo darwin || echo linux )}"
case "$TARGET_GOOS" in
    darwin) LIB_NAME="libopenshell_containerd_shim.dylib" ;;
    linux)  LIB_NAME="libopenshell_containerd_shim.so" ;;
    *)
        echo "Error: Unsupported GOOS: ${TARGET_GOOS}" >&2
        exit 1
        ;;
esac

echo "==> Building openshell-containerd-shim (${LIB_NAME}, GOOS=${TARGET_GOOS})..."
mkdir -p "$WORK_DIR" "$OUTPUT_DIR"

(
    cd "$GOSHIM_DIR"
    export CGO_ENABLED=1
    export GOOS="$TARGET_GOOS"
    export GOARCH="${GOARCH:-}"
    export CC="${CC:-}"
    go build -trimpath -buildmode=c-shared -o "${WORK_DIR}/${LIB_NAME}" .
)
# The generated C header only serves cgo/C consumers; the Rust FFI bindings
# in containerd_shim.rs are maintained by hand against the exported symbols.
rm -f "${WORK_DIR}/${LIB_NAME%.dylib}.h" "${WORK_DIR}/${LIB_NAME%.so}.h"

compress_file "${WORK_DIR}/${LIB_NAME}" "${OUTPUT_DIR}/${LIB_NAME}.zst"
echo "==> Staged ${OUTPUT_DIR}/${LIB_NAME}.zst"
