#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Snap wrapper for openshell-gateway. The system service supplies explicit
# compatibility paths; the user service uses OpenShell's XDG defaults.

set -eu

config_file=
if [ -n "${OPENSHELL_GATEWAY_CONFIG:-}" ]; then
    config_file="$OPENSHELL_GATEWAY_CONFIG"
elif [ -n "${OPENSHELL_SNAP_CONFIG_FILE:-}" ]; then
    config_file="$OPENSHELL_SNAP_CONFIG_FILE"
elif [ -n "${XDG_CONFIG_HOME:-}" ]; then
    config_file="${XDG_CONFIG_HOME}/openshell/gateway.toml"
fi

if [ -z "${OPENSHELL_DB_URL:-}" ] && [ -n "${XDG_STATE_HOME:-}" ]; then
    umask 077
    mkdir -p "${XDG_STATE_HOME}/openshell/gateway"
    export OPENSHELL_DB_URL="sqlite:${XDG_STATE_HOME}/openshell/gateway/openshell.db?mode=rwc"
fi

if [ -z "${OPENSHELL_LOCAL_TLS_DIR:-}" ]; then
    if [ -z "${XDG_STATE_HOME:-}" ]; then
        echo "openshell-gateway: OPENSHELL_LOCAL_TLS_DIR or XDG_STATE_HOME is required" >&2
        exit 1
    fi
    export OPENSHELL_LOCAL_TLS_DIR="${XDG_STATE_HOME}/openshell/tls"
fi

should_write_default_vm_config() {
    [ -n "$config_file" ] || return 1
    [ ! -e "$config_file" ] && [ ! -L "$config_file" ] || return 1
    kvm_device=/dev/kvm
    [ -r "$kvm_device" ] && [ -w "$kvm_device" ] || return 1

    case "${OPENSHELL_DB_URL:-}" in
        sqlite::memory:* | sqlite:*mode=memory*)
            return 0
            ;;
        sqlite:*)
            database_file=${OPENSHELL_DB_URL#sqlite:}
            database_file=${database_file%%\?*}
            [ -n "$database_file" ] || return 1
            [ ! -e "$database_file" ] && [ ! -L "$database_file" ]
            ;;
        *)
            return 1
            ;;
    esac
}

if should_write_default_vm_config; then
    umask 077
    mkdir -p "$(dirname "$config_file")"
    printf '%s\n' \
        '[openshell]' \
        'version = 2' \
        '' \
        '[openshell.gateway]' \
        'compute_driver = "vm"' >"$config_file"
fi

# Only export OPENSHELL_GATEWAY_CONFIG if it actually exists, otherwise the
# gateway will error
if [ -n "$config_file" ] \
    && { [ -e "$config_file" ] || [ -L "$config_file" ]; }
then
    export OPENSHELL_GATEWAY_CONFIG="$config_file"
fi

"${SNAP}/bin/openshell-gateway" config preflight -- "$@"

# Generate the local TLS bundle and the JWT bundle used for launch-scoped
# supervisor credentials; generate-certs is idempotent and preserves an
# existing bundle.
"${SNAP}/bin/openshell-gateway" generate-certs \
    --output-dir "$OPENSHELL_LOCAL_TLS_DIR" \
    --server-san host.openshell.internal

exec "${SNAP}/bin/openshell-gateway" "$@"
