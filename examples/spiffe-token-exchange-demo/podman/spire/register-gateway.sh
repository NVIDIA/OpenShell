#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

TRUST_DOMAIN="${TRUST_DOMAIN:-openshell.local}"
GATEWAY_SPIFFE_ID="${GATEWAY_SPIFFE_ID:-spiffe://${TRUST_DOMAIN}/openshell/gateway/demo}"
SPIRE_AGENT_PARENT_ID="${SPIRE_AGENT_PARENT_ID:-spiffe://${TRUST_DOMAIN}/openshell/spire-agent/demo}"
SPIRE_SERVER_SOCKET="${SPIRE_SERVER_SOCKET:-/run/spire/server/private/api.sock}"
SPIRE_SERVER_CONTAINER="${SPIRE_SERVER_CONTAINER:-openshell-spiffe-demo-spire-server}"
SPIRE_SERVER_BIN="${SPIRE_SERVER_BIN:-/opt/spire/bin/spire-server}"

if [[ -n "${GATEWAY_SELECTORS:-}" ]]; then
    read -r -a selectors <<<"$GATEWAY_SELECTORS"
else
    gateway_path="${GATEWAY_WORKLOAD_PATH:-$(command -v openshell-server || true)}"
    if [[ -n "$gateway_path" ]]; then
        selectors=("unix:uid:$(id -u)" "unix:path:${gateway_path}")
    else
        printf "GATEWAY_WORKLOAD_PATH is unset and openshell-server is not on PATH; falling back to unix:uid only\n" >&2
        selectors=("unix:uid:$(id -u)")
    fi
fi

args=(
    entry create
    -socketPath "$SPIRE_SERVER_SOCKET"
    -parentID "$SPIRE_AGENT_PARENT_ID"
    -spiffeID "$GATEWAY_SPIFFE_ID"
    -jwtSVIDTTL 300
)

for selector in "${selectors[@]}"; do
    args+=(-selector "$selector")
done

printf "Registering gateway SPIFFE entry: %s\n" "$GATEWAY_SPIFFE_ID" >&2
podman exec "$SPIRE_SERVER_CONTAINER" "$SPIRE_SERVER_BIN" "${args[@]}"
