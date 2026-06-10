#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Snap wrapper for openshell-gateway. Sets snap-specific defaults:
#   - OPENSHELL_DB_URL  -> sqlite:$SNAP_COMMON/gateway.db (overridable)
#   - OPENSHELL_DISABLE_TLS -> true
# If $SNAP_COMMON/gateway.toml exists, passes it as --config so operators
# can override settings without rebuilding the snap.

set -eu

CANONICAL_CONFIG_FILE="${SNAP_COMMON}/gateway.toml"
export OPENSHELL_DB_URL="${OPENSHELL_DB_URL:-sqlite:${SNAP_COMMON}/gateway.db?mode=rwc}"
export OPENSHELL_DISABLE_TLS="${OPENSHELL_DISABLE_TLS:-true}"

if [ -z "${OPENSHELL_GATEWAY_CONFIG:-}" ] && [ -f "$CANONICAL_CONFIG_FILE" ]; then
    exec "${SNAP}/bin/openshell-gateway" --config "$CANONICAL_CONFIG_FILE" "$@"
fi

exec "${SNAP}/bin/openshell-gateway" "$@"
