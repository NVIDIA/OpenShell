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

ensure_build_nofile_limit() {
    local desired="${OPENSHELL_VM_BUILD_NOFILE_LIMIT:-8192}"
    local minimum=1024
    local current=""
    local hard=""
    local target=""

    [ "$(uname -s)" = "Darwin" ] || return 0
    command -v cargo-zigbuild >/dev/null 2>&1 || return 0

    current="$(ulimit -n 2>/dev/null || echo "")"
    case "${current}" in
        ''|*[!0-9]*)
            return 0
            ;;
    esac

    if [ "${current}" -ge "${desired}" ]; then
        return 0
    fi

    hard="$(ulimit -Hn 2>/dev/null || echo "")"
    target="${desired}"
    case "${hard}" in
        ''|unlimited|infinity)
            ;;
        *[!0-9]*)
            ;;
        *)
            if [ "${hard}" -lt "${target}" ]; then
                target="${hard}"
            fi
            ;;
    esac

    if [ "${target}" -gt "${current}" ] && ulimit -n "${target}" 2>/dev/null; then
        echo "==> Raised open file limit for cargo-zigbuild: ${current} -> $(ulimit -n)"
    fi

    current="$(ulimit -n 2>/dev/null || echo "${current}")"
    case "${current}" in
        ''|*[!0-9]*)
            return 0
            ;;
    esac

    if [ "${current}" -lt "${desired}" ]; then
        echo "WARNING: Open file limit is ${current}; cargo-zigbuild is more reliable at ${desired}+ on macOS."
    fi

    if [ "${current}" -lt "${minimum}" ]; then
        echo "ERROR: Open file limit (${current}) is too low for cargo-zigbuild on macOS." >&2
        echo "       Run: ulimit -n ${desired}" >&2
        echo "       Then re-run this script." >&2
        exit 1
    fi
}

echo "==> Building openshell-sandbox supervisor bundle"
echo "    Guest arch: ${GUEST_ARCH}"
echo "    Rust target: ${RUST_TARGET}"
echo "    Output: ${SUPERVISOR_OUTPUT}"

mkdir -p "${OUTPUT_DIR}"
ensure_build_nofile_limit

SUPERVISOR_BUILD_LOG="$(mktemp -t openshell-supervisor-build.XXXXXX.log)"
run_supervisor_build() {
    local rustc_wrapper_mode="${1:-default}"
    local cargo_prefix=()

    if [ "${rustc_wrapper_mode}" = "without-rustc-wrapper" ]; then
        cargo_prefix=(env -u RUSTC_WRAPPER)
    fi

    if command -v cargo-zigbuild >/dev/null 2>&1; then
        "${cargo_prefix[@]}" cargo zigbuild --release -p openshell-sandbox --target "${RUST_TARGET}" \
            --manifest-path "${ROOT}/Cargo.toml"
    else
        echo "    cargo-zigbuild not found, falling back to cargo build..."
        "${cargo_prefix[@]}" cargo build --release -p openshell-sandbox --target "${RUST_TARGET}" \
            --manifest-path "${ROOT}/Cargo.toml"
    fi
}

print_build_failure() {
    echo "ERROR: supervisor build failed. Full output:" >&2
    cat "${SUPERVISOR_BUILD_LOG}" >&2
    echo "    (log saved at ${SUPERVISOR_BUILD_LOG})" >&2
}

if run_supervisor_build >"${SUPERVISOR_BUILD_LOG}" 2>&1; then
    tail -5 "${SUPERVISOR_BUILD_LOG}"
    rm -f "${SUPERVISOR_BUILD_LOG}"
else
    status=$?
    if [ -n "${RUSTC_WRAPPER:-}" ] && grep -Eq 'sccache: encountered fatal error|Too many open files|os error 24' "${SUPERVISOR_BUILD_LOG}"; then
        echo "WARNING: supervisor build failed through RUSTC_WRAPPER=${RUSTC_WRAPPER}; retrying without RUSTC_WRAPPER." >&2
        : >"${SUPERVISOR_BUILD_LOG}"
        if run_supervisor_build without-rustc-wrapper >"${SUPERVISOR_BUILD_LOG}" 2>&1; then
            tail -5 "${SUPERVISOR_BUILD_LOG}"
            rm -f "${SUPERVISOR_BUILD_LOG}"
        else
            status=$?
            print_build_failure
            exit "${status}"
        fi
    else
        print_build_failure
        exit "${status}"
    fi
fi

if [ ! -f "${SUPERVISOR_BIN}" ]; then
    echo "ERROR: supervisor binary not found at ${SUPERVISOR_BIN}" >&2
    exit 1
fi

zstd -19 -T0 -f "${SUPERVISOR_BIN}" -o "${SUPERVISOR_OUTPUT}"

echo "==> Bundled supervisor ready"
echo "    Binary: $(du -sh "${SUPERVISOR_BIN}" | cut -f1)"
echo "    Compressed: $(du -sh "${SUPERVISOR_OUTPUT}" | cut -f1)"
