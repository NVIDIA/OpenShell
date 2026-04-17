#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPRESSED_DIR="${ROOT}/target/vm-runtime-compressed"
STATE_DIR_DEFAULT="${ROOT}/target/openshell-vm-driver-dev"
STATE_DIR="${OPENSHELL_VM_DRIVER_STATE_DIR:-${STATE_DIR_DEFAULT}}"
DB_PATH_DEFAULT="${STATE_DIR}/openshell.db"
SERVER_PORT="${OPENSHELL_SERVER_PORT:-8080}"
VM_HOST_GATEWAY_DEFAULT="${OPENSHELL_VM_HOST_GATEWAY:-host.containers.internal}"

export OPENSHELL_VM_RUNTIME_COMPRESSED_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${COMPRESSED_DIR}}"

mkdir -p "${STATE_DIR}"

normalize_bool() {
    case "${1,,}" in
        1|true|yes|on) echo "true" ;;
        0|false|no|off) echo "false" ;;
        *)
            echo "invalid boolean value '$1' (expected true/false, 1/0, yes/no, on/off)" >&2
            exit 1
            ;;
    esac
}

if [ ! -f "${COMPRESSED_DIR}/rootfs.tar.zst" ]; then
    echo "==> Building base VM rootfs tarball"
    mise run vm:rootfs -- --base
fi

if [ ! -f "${COMPRESSED_DIR}/rootfs.tar.zst" ] || ! find "${COMPRESSED_DIR}" -maxdepth 1 -name 'libkrun*.zst' | grep -q .; then
    echo "==> Preparing embedded VM runtime"
    mise run vm:setup
fi

echo "==> Building gateway and VM compute driver"
cargo build -p openshell-server -p openshell-driver-vm

if [ "$(uname -s)" = "Darwin" ]; then
    echo "==> Codesigning VM compute driver"
    codesign \
        --entitlements "${ROOT}/crates/openshell-driver-vm/entitlements.plist" \
        --force \
        -s - \
        "${ROOT}/target/debug/openshell-driver-vm"
fi

export OPENSHELL_DISABLE_TLS="$(normalize_bool "${OPENSHELL_DISABLE_TLS:-true}")"
export OPENSHELL_DB_URL="${OPENSHELL_DB_URL:-sqlite:${DB_PATH_DEFAULT}}"
export OPENSHELL_DRIVERS="${OPENSHELL_DRIVERS:-vm}"
export OPENSHELL_GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-http://${VM_HOST_GATEWAY_DEFAULT}:${SERVER_PORT}}"
export OPENSHELL_SSH_GATEWAY_HOST="${OPENSHELL_SSH_GATEWAY_HOST:-127.0.0.1}"
export OPENSHELL_SSH_GATEWAY_PORT="${OPENSHELL_SSH_GATEWAY_PORT:-${SERVER_PORT}}"
export OPENSHELL_SSH_HANDSHAKE_SECRET="${OPENSHELL_SSH_HANDSHAKE_SECRET:-dev-vm-driver-secret}"
export OPENSHELL_VM_DRIVER_STATE_DIR="${STATE_DIR}"
export OPENSHELL_VM_COMPUTE_DRIVER_BIN="${OPENSHELL_VM_COMPUTE_DRIVER_BIN:-${ROOT}/target/debug/openshell-driver-vm}"

echo "==> Starting OpenShell server with VM compute driver"
exec "${ROOT}/target/debug/openshell-gateway"
