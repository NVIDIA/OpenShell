#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Snap wrapper for openshell-gateway. Sets snap-specific defaults:
#   - OPENSHELL_DB_URL  -> sqlite:$SNAP_COMMON/gateway.db (overridable)
#   - OPENSHELL_DISABLE_TLS -> true
# It validates, but never creates or rewrites, an operator-provided config
# before starting the gateway.

set -eu

CANONICAL_CONFIG_FILE="${SNAP_COMMON}/gateway.toml"
export OPENSHELL_DB_URL="${OPENSHELL_DB_URL:-sqlite:${SNAP_COMMON}/gateway.db?mode=rwc}"
export OPENSHELL_DISABLE_TLS="${OPENSHELL_DISABLE_TLS:-true}"

# Mirror clap's CLI-over-environment precedence so preflight always inspects
# the same file the daemon will load. Reject ambiguous duplicate selectors
# before either command runs.
cli_config=""
config_seen=false
expect_config_path=false
options_done=false
for argument in "$@"; do
    if [ "$options_done" = true ]; then
        continue
    fi
    if [ "$expect_config_path" = true ]; then
        case "$argument" in
            -*)
                echo "openshell-gateway: --config requires a nonempty path" >&2
                exit 2
                ;;
        esac
        if [ "$config_seen" = true ]; then
            echo "openshell-gateway: duplicate --config option" >&2
            exit 2
        fi
        cli_config=$argument
        config_seen=true
        expect_config_path=false
        continue
    fi
    case "$argument" in
        --)
            options_done=true
            ;;
        --config)
            expect_config_path=true
            ;;
        --config=*)
            if [ "$config_seen" = true ]; then
                echo "openshell-gateway: duplicate --config option" >&2
                exit 2
            fi
            cli_config=${argument#--config=}
            config_seen=true
            ;;
    esac
done
if [ "$expect_config_path" = true ] || { [ "$config_seen" = true ] && [ -z "$cli_config" ]; }; then
    echo "openshell-gateway: --config requires a nonempty path" >&2
    exit 2
fi

if [ "$config_seen" = true ]; then
    "${SNAP}/bin/openshell-gateway" config preflight "--path=$cli_config"
    exec "${SNAP}/bin/openshell-gateway" "$@"
elif [ -n "${OPENSHELL_GATEWAY_CONFIG:-}" ]; then
    "${SNAP}/bin/openshell-gateway" config preflight
    exec "${SNAP}/bin/openshell-gateway" "$@"
elif [ -e "$CANONICAL_CONFIG_FILE" ] || [ -L "$CANONICAL_CONFIG_FILE" ]; then
    "${SNAP}/bin/openshell-gateway" config preflight --path "$CANONICAL_CONFIG_FILE"
    exec "${SNAP}/bin/openshell-gateway" --config "$CANONICAL_CONFIG_FILE" "$@"
else
    "${SNAP}/bin/openshell-gateway" config preflight
    exec "${SNAP}/bin/openshell-gateway" "$@"
fi
