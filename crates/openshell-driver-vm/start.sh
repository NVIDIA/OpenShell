#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLI_BIN="${ROOT}/scripts/bin/openshell"
COMPRESSED_DIR="${ROOT}/target/vm-runtime-compressed"
SERVER_PORT="${OPENSHELL_SERVER_PORT:-8080}"
# Keep the driver socket path under AF_UNIX SUN_LEN on macOS.
STATE_DIR_ROOT="${OPENSHELL_VM_DRIVER_STATE_ROOT:-/tmp}"
STATE_LABEL_RAW="${OPENSHELL_VM_INSTANCE:-port-${SERVER_PORT}}"
STATE_LABEL="$(printf '%s' "${STATE_LABEL_RAW}" | tr -cs '[:alnum:]._-' '-')"
if [ -z "${STATE_LABEL}" ]; then
    STATE_LABEL="port-${SERVER_PORT}"
fi
STATE_DIR_DEFAULT="${STATE_DIR_ROOT}/openshell-vm-driver-dev-${USER:-user}-${STATE_LABEL}"
STATE_DIR="${OPENSHELL_VM_DRIVER_STATE_DIR:-${STATE_DIR_DEFAULT}}"
DB_PATH_DEFAULT="${STATE_DIR}/openshell.db"
VM_HOST_GATEWAY_DEFAULT="${OPENSHELL_VM_HOST_GATEWAY:-host.containers.internal}"
LOCAL_GATEWAY_ENDPOINT_DEFAULT="http://127.0.0.1:${SERVER_PORT}"
LOCAL_GATEWAY_ENDPOINT="${OPENSHELL_VM_LOCAL_GATEWAY_ENDPOINT:-${LOCAL_GATEWAY_ENDPOINT_DEFAULT}}"
GATEWAY_NAME_DEFAULT="vm-driver-${STATE_LABEL}"
GATEWAY_NAME="${OPENSHELL_VM_GATEWAY_NAME:-${GATEWAY_NAME_DEFAULT}}"
DRIVER_DIR_DEFAULT="${ROOT}/target/debug"
DRIVER_DIR="${OPENSHELL_DRIVER_DIR:-${DRIVER_DIR_DEFAULT}}"

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
export OPENSHELL_DRIVER_DIR="${DRIVER_DIR}"
export OPENSHELL_GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-http://${VM_HOST_GATEWAY_DEFAULT}:${SERVER_PORT}}"
export OPENSHELL_SSH_GATEWAY_HOST="${OPENSHELL_SSH_GATEWAY_HOST:-127.0.0.1}"
export OPENSHELL_SSH_GATEWAY_PORT="${OPENSHELL_SSH_GATEWAY_PORT:-${SERVER_PORT}}"
export OPENSHELL_SSH_HANDSHAKE_SECRET="${OPENSHELL_SSH_HANDSHAKE_SECRET:-dev-vm-driver-secret}"
export OPENSHELL_VM_DRIVER_STATE_DIR="${STATE_DIR}"

echo "==> Gateway registration"
echo "    Name: ${GATEWAY_NAME}"
echo "    Endpoint: ${LOCAL_GATEWAY_ENDPOINT}"
echo "    Register: ${CLI_BIN} gateway add --name ${GATEWAY_NAME} ${LOCAL_GATEWAY_ENDPOINT}"
echo "    Select:   ${CLI_BIN} gateway select ${GATEWAY_NAME}"
echo "    Driver:   ${OPENSHELL_DRIVER_DIR}/openshell-driver-vm"

echo "==> Starting OpenShell server with VM compute driver"
exec "${ROOT}/target/debug/openshell-gateway"
