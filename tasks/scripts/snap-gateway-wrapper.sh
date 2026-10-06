#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Snap wrapper for ryno-gateway. Sets snap-specific defaults:
#   - RYNO_DB_URL        -> sqlite:$SNAP_COMMON/gateway.db (overridable)
#   - RYNO_LOCAL_TLS_DIR -> $SNAP_COMMON/tls (overridable)
# The gateway serves TLS from the generated bundle and requires client
# certificates. It bootstraps package-managed credentials and validates, but
# never creates or rewrites, an operator-provided config before starting.

set -eu

CANONICAL_CONFIG_FILE="${SNAP_COMMON}/gateway.toml"
export RYNO_DB_URL="${RYNO_DB_URL:-sqlite:${SNAP_COMMON}/gateway.db?mode=rwc}"
export RYNO_LOCAL_TLS_DIR="${RYNO_LOCAL_TLS_DIR:-${SNAP_COMMON}/tls}"

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
                echo "ryno-gateway: --config requires a nonempty path" >&2
                exit 2
                ;;
        esac
        if [ "$config_seen" = true ]; then
            echo "ryno-gateway: duplicate --config option" >&2
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
                echo "ryno-gateway: duplicate --config option" >&2
                exit 2
            fi
            cli_config=${argument#--config=}
            config_seen=true
            ;;
    esac
done
if [ "$expect_config_path" = true ] || { [ "$config_seen" = true ] && [ -z "$cli_config" ]; }; then
    echo "ryno-gateway: --config requires a nonempty path" >&2
    exit 2
fi

# Generate the local TLS bundle and the JWT bundle used for launch-scoped
# supervisor credentials; generate-certs is idempotent and preserves an
# existing bundle.
"${SNAP}/bin/ryno-gateway" generate-certs \
    --output-dir "$RYNO_LOCAL_TLS_DIR" \
    --server-san host.ryno.internal

if [ "$config_seen" = true ]; then
    "${SNAP}/bin/ryno-gateway" config preflight -- "$@"
    exec "${SNAP}/bin/ryno-gateway" "$@"
elif [ -n "${RYNO_GATEWAY_CONFIG:-}" ]; then
    "${SNAP}/bin/ryno-gateway" config preflight -- "$@"
    exec "${SNAP}/bin/ryno-gateway" "$@"
elif [ -e "$CANONICAL_CONFIG_FILE" ] || [ -L "$CANONICAL_CONFIG_FILE" ]; then
    "${SNAP}/bin/ryno-gateway" config preflight -- --config "$CANONICAL_CONFIG_FILE" "$@"
    exec "${SNAP}/bin/ryno-gateway" --config "$CANONICAL_CONFIG_FILE" "$@"
else
    "${SNAP}/bin/ryno-gateway" config preflight -- "$@"
    exec "${SNAP}/bin/ryno-gateway" "$@"
fi
