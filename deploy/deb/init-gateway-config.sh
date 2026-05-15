#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

CONFIG_FILE="${1:?Usage: init-gateway-config.sh <config-file> <pki-dir> <driver-dir> <vm-state-dir>}"
PKI_DIR="${2:?Usage: init-gateway-config.sh <config-file> <pki-dir> <driver-dir> <vm-state-dir>}"
DRIVER_DIR="${3:?Usage: init-gateway-config.sh <config-file> <pki-dir> <driver-dir> <vm-state-dir>}"
VM_STATE_DIR="${4:?Usage: init-gateway-config.sh <config-file> <pki-dir> <driver-dir> <vm-state-dir>}"

if [ -f "$CONFIG_FILE" ]; then
    exit 0
fi

mkdir -p "$(dirname "$CONFIG_FILE")" "$VM_STATE_DIR"

port="${OPENSHELL_SERVER_PORT:-17670}"
scheme="https"
if [ "${OPENSHELL_DISABLE_TLS:-false}" = "true" ]; then
    scheme="http"
fi

tmp="${CONFIG_FILE}.tmp"
{
    cat <<EOF
[openshell]
version = 1

[openshell.gateway]
default_image = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
supervisor_image = "ghcr.io/nvidia/openshell/supervisor:latest"
EOF

    if [ "$scheme" = "https" ]; then
        cat <<EOF
guest_tls_ca = "${PKI_DIR}/ca.crt"
guest_tls_cert = "${PKI_DIR}/client/tls.crt"
guest_tls_key = "${PKI_DIR}/client/tls.key"
EOF
    fi

    cat <<EOF

[openshell.drivers.vm]
state_dir = "${VM_STATE_DIR}"
driver_dir = "${DRIVER_DIR}"
grpc_endpoint = "${scheme}://127.0.0.1:${port}"

[openshell.drivers.docker]
grpc_endpoint = "${scheme}://127.0.0.1:${port}"
EOF
} > "$tmp"

chmod 600 "$tmp"
mv "$tmp" "$CONFIG_FILE"
