#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUTPUT_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${ROOT}/target/vm-runtime-compressed}"

# shellcheck source=tasks/scripts/build-env.sh
source "${ROOT}/tasks/scripts/build-env.sh"

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
        SANDBOX_RUST_TARGET="aarch64-unknown-linux-musl"
        ;;
    x86_64|amd64)
        SANDBOX_RUST_TARGET="x86_64-unknown-linux-musl"
        ;;
    *)
        echo "ERROR: Unsupported guest architecture: ${GUEST_ARCH}" >&2
        echo "       Supported: aarch64, x86_64" >&2
        exit 1
        ;;
esac

SUPERVISOR_BIN="${ROOT}/target/${SANDBOX_RUST_TARGET}/release/openshell-sandbox"
SUPERVISOR_OUTPUT="${OUTPUT_DIR}/openshell-sandbox.zst"
GUEST_SUPERVISOR_BIN="${ROOT}/target/${SANDBOX_RUST_TARGET}/release/openshell-supervisor"
HOST_SUPERVISOR_BIN="${ROOT}/target/release/openshell-supervisor"
HOST_SUPERVISOR_OUTPUT="${OUTPUT_DIR}/openshell-supervisor.zst"
SUPERVISOR_RUNTIME_OUTPUT="${OUTPUT_DIR}/openshell-runtime.tar.zst"

echo "==> Building openshell-sandbox supervisor bundle"
echo "    Guest arch: ${GUEST_ARCH}"
echo "    Sandbox target: ${SANDBOX_RUST_TARGET} (static musl)"
echo "    Host supervisor target: native"
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
        ${cargo_prefix[@]+"${cargo_prefix[@]}"} cargo zigbuild --release -p openshell-sandbox -p openshell-supervisor --target "${SANDBOX_RUST_TARGET}" \
            --manifest-path "${ROOT}/Cargo.toml"
    else
        echo "    cargo-zigbuild not found, falling back to cargo build..."
        ${cargo_prefix[@]+"${cargo_prefix[@]}"} cargo build --release -p openshell-sandbox -p openshell-supervisor --target "${SANDBOX_RUST_TARGET}" \
            --manifest-path "${ROOT}/Cargo.toml"
    fi
    ${cargo_prefix[@]+"${cargo_prefix[@]}"} cargo build --release -p openshell-supervisor \
        --manifest-path "${ROOT}/Cargo.toml"
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

if [ ! -f "${SUPERVISOR_BIN}" ] || [ ! -f "${GUEST_SUPERVISOR_BIN}" ] || [ ! -f "${HOST_SUPERVISOR_BIN}" ]; then
    echo "ERROR: sandbox or supervisor binary not found after build" >&2
    exit 1
fi

if readelf -l "${SUPERVISOR_BIN}" 2>/dev/null | grep -q 'Requesting program interpreter'; then
    echo "ERROR: VM guest openshell-sandbox must be statically linked" >&2
    exit 1
fi

zstd -19 -T0 -f "${SUPERVISOR_BIN}" -o "${SUPERVISOR_OUTPUT}"
zstd -19 -T0 -f "${HOST_SUPERVISOR_BIN}" -o "${HOST_SUPERVISOR_OUTPUT}"

case "${GUEST_ARCH}" in
    aarch64|arm64) DOCKER_ARCH="arm64" ;;
    x86_64|amd64) DOCKER_ARCH="amd64" ;;
esac

echo "==> Building trusted supervisor helper runtime"
STAGED_SUPERVISOR="${ROOT}/deploy/docker/.build/prebuilt-binaries/${DOCKER_ARCH}/openshell-sandbox"
STAGED_CONTROL="${ROOT}/deploy/docker/.build/prebuilt-binaries/${DOCKER_ARCH}/openshell-supervisor"
RUNTIME_IMAGE="openshell-vm-helper-runtime:${DOCKER_ARCH}-$$"
mkdir -p "$(dirname "${STAGED_SUPERVISOR}")"
cp "${SUPERVISOR_BIN}" "${STAGED_SUPERVISOR}"
cp "${GUEST_SUPERVISOR_BIN}" "${STAGED_CONTROL}"

case "$(uname -m)" in
    aarch64|arm64) HOST_DOCKER_ARCH="arm64" ;;
    x86_64|amd64) HOST_DOCKER_ARCH="amd64" ;;
    *) HOST_DOCKER_ARCH="" ;;
esac

if [ "${HOST_DOCKER_ARCH}" = "${DOCKER_ARCH}" ]; then
    docker build \
        --build-arg "TARGETARCH=${DOCKER_ARCH}" \
        --file "${ROOT}/deploy/docker/Dockerfile.supervisor" \
        --tag "${RUNTIME_IMAGE}" \
        "${ROOT}"
else
    docker buildx build \
        --load \
        --platform "linux/${DOCKER_ARCH}" \
        --build-arg "TARGETARCH=${DOCKER_ARCH}" \
        --file "${ROOT}/deploy/docker/Dockerfile.supervisor" \
        --tag "${RUNTIME_IMAGE}" \
        "${ROOT}"
fi

RUNTIME_CONTAINER="$(docker create "${RUNTIME_IMAGE}")"
cleanup_runtime_image() {
    docker rm -f "${RUNTIME_CONTAINER}" >/dev/null 2>&1 || true
    docker image rm "${RUNTIME_IMAGE}" >/dev/null 2>&1 || true
}
trap cleanup_runtime_image EXIT
docker cp "${RUNTIME_CONTAINER}:/openshell-runtime" - \
    | zstd -19 -T0 -f -o "${SUPERVISOR_RUNTIME_OUTPUT}"
cleanup_runtime_image
trap - EXIT

echo "==> Bundled supervisor ready"
echo "    Binary: $(du -sh "${SUPERVISOR_BIN}" | cut -f1)"
echo "    Compressed: $(du -sh "${SUPERVISOR_OUTPUT}" | cut -f1)"
echo "    Helper runtime: $(du -sh "${SUPERVISOR_RUNTIME_OUTPUT}" | cut -f1)"
