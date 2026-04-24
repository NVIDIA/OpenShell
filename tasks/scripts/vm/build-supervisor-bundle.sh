#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUTPUT_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${ROOT}/target/vm-runtime-compressed}"

GUEST_ARCH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            GUEST_ARCH="$2"
            shift 2
            ;;
        --arch=*)
            GUEST_ARCH="${1#--arch=}"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--arch aarch64|x86_64]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [ -z "${GUEST_ARCH}" ]; then
    case "$(uname -m)" in
        aarch64|arm64) GUEST_ARCH="aarch64" ;;
        x86_64|amd64)  GUEST_ARCH="x86_64" ;;
        *)
            echo "ERROR: Unsupported host architecture: $(uname -m)" >&2
            echo "       Use --arch aarch64 or --arch x86_64 to override." >&2
            exit 1
            ;;
    esac
fi

case "${GUEST_ARCH}" in
    aarch64|arm64)
        RUST_TARGET="aarch64-unknown-linux-gnu"
        ;;
    x86_64|amd64)
        RUST_TARGET="x86_64-unknown-linux-gnu"
        ;;
    *)
        echo "ERROR: Unsupported guest architecture: ${GUEST_ARCH}" >&2
        echo "       Supported: aarch64, x86_64" >&2
        exit 1
        ;;
esac

SUPERVISOR_BIN="${ROOT}/target/${RUST_TARGET}/release/openshell-sandbox"
SUPERVISOR_OUTPUT="${OUTPUT_DIR}/openshell-sandbox.zst"

echo "==> Building openshell-sandbox supervisor bundle"
echo "    Guest arch: ${GUEST_ARCH}"
echo "    Rust target: ${RUST_TARGET}"
echo "    Output: ${SUPERVISOR_OUTPUT}"

mkdir -p "${OUTPUT_DIR}"

SUPERVISOR_BUILD_LOG="$(mktemp -t openshell-supervisor-build.XXXXXX.log)"
run_supervisor_build() {
    if command -v cargo-zigbuild >/dev/null 2>&1; then
        cargo zigbuild --release -p openshell-sandbox --target "${RUST_TARGET}" \
            --manifest-path "${ROOT}/Cargo.toml"
    else
        echo "    cargo-zigbuild not found, falling back to cargo build..."
        cargo build --release -p openshell-sandbox --target "${RUST_TARGET}" \
            --manifest-path "${ROOT}/Cargo.toml"
    fi
}

if run_supervisor_build >"${SUPERVISOR_BUILD_LOG}" 2>&1; then
    tail -5 "${SUPERVISOR_BUILD_LOG}"
    rm -f "${SUPERVISOR_BUILD_LOG}"
else
    status=$?
    echo "ERROR: supervisor build failed. Full output:" >&2
    cat "${SUPERVISOR_BUILD_LOG}" >&2
    echo "    (log saved at ${SUPERVISOR_BUILD_LOG})" >&2
    exit "${status}"
fi

if [ ! -f "${SUPERVISOR_BIN}" ]; then
    echo "ERROR: supervisor binary not found at ${SUPERVISOR_BIN}" >&2
    exit 1
fi

zstd -19 -T0 -f "${SUPERVISOR_BIN}" -o "${SUPERVISOR_OUTPUT}"

echo "==> Bundled supervisor ready"
echo "    Binary: $(du -sh "${SUPERVISOR_BIN}" | cut -f1)"
echo "    Compressed: $(du -sh "${SUPERVISOR_OUTPUT}" | cut -f1)"
