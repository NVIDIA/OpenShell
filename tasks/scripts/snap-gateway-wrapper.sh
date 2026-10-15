#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Snap wrapper for openshell-gateway. The system service supplies explicit
# compatibility paths; the user service uses OpenShell's XDG defaults.

set -eu

if [ -z "${OPENSHELL_GATEWAY_CONFIG:-}" ] \
    && [ -n "${OPENSHELL_SNAP_CONFIG_FILE:-}" ] \
    && { [ -e "$OPENSHELL_SNAP_CONFIG_FILE" ] || [ -L "$OPENSHELL_SNAP_CONFIG_FILE" ]; }
then
    export OPENSHELL_GATEWAY_CONFIG="$OPENSHELL_SNAP_CONFIG_FILE"
fi

# The snap defaults to the bundled VM driver. Preserve an explicit service
# environment selector, then a selector in the effective gateway TOML.
if [ -z "${OPENSHELL_COMPUTE_DRIVER+x}" ] \
    && [ -z "${OPENSHELL_DRIVERS+x}" ]
then
    config_file=""
    expect_config_path=false
    for arg in "$@"; do
        if [ "$expect_config_path" = true ]; then
            config_file="$arg"
            expect_config_path=false
            continue
        fi
        case "$arg" in
            --config) expect_config_path=true ;;
            --config=*) config_file=${arg#--config=} ;;
        esac
    done
    if [ -z "$config_file" ]; then
        config_file="${OPENSHELL_GATEWAY_CONFIG:-}"
    fi
    if [ -z "$config_file" ] && [ -n "${XDG_CONFIG_HOME:-}" ]; then
        config_file="${XDG_CONFIG_HOME}/openshell/gateway.toml"
    fi
    if [ -z "$config_file" ] \
        || [ ! -f "$config_file" ] \
        || ! grep -Eq \
            -e "^[[:space:]]*(compute_driver|\"compute_driver\"|'compute_driver')[[:space:]]*=" \
            -e "^[[:space:]]*(openshell|\"openshell\"|'openshell')[[:space:]]*\.[[:space:]]*(gateway|\"gateway\"|'gateway')[[:space:]]*\.[[:space:]]*(compute_driver|\"compute_driver\"|'compute_driver')[[:space:]]*=" \
            "$config_file"
    then
        export OPENSHELL_COMPUTE_DRIVER=vm
    fi
fi

if [ -z "${OPENSHELL_LOCAL_TLS_DIR:-}" ]; then
    if [ -z "${XDG_STATE_HOME:-}" ]; then
        echo "openshell-gateway: OPENSHELL_LOCAL_TLS_DIR or XDG_STATE_HOME is required" >&2
        exit 1
    fi
    export OPENSHELL_LOCAL_TLS_DIR="${XDG_STATE_HOME}/openshell/tls"
fi

"${SNAP}/bin/openshell-gateway" config preflight -- "$@"

# Generate the local TLS bundle and the JWT bundle used for launch-scoped
# supervisor credentials; generate-certs is idempotent and preserves an
# existing bundle.
"${SNAP}/bin/openshell-gateway" generate-certs \
    --output-dir "$OPENSHELL_LOCAL_TLS_DIR" \
    --server-san host.openshell.internal

exec "${SNAP}/bin/openshell-gateway" "$@"
