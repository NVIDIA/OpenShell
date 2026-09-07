#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf "usage: %s <sandbox-id>\n" "$0" >&2
    exit 2
fi

SANDBOX_ID="$1"
TRUST_DOMAIN="${TRUST_DOMAIN:-openshell.local}"
SANDBOX_SPIFFE_ID="${SANDBOX_SPIFFE_ID:-spiffe://${TRUST_DOMAIN}/openshell/sandbox/${SANDBOX_ID}}"
SPIRE_AGENT_PARENT_ID="${SPIRE_AGENT_PARENT_ID:-spiffe://${TRUST_DOMAIN}/openshell/spire-agent/demo}"
SPIRE_SERVER_SOCKET="${SPIRE_SERVER_SOCKET:-/run/spire/server/private/api.sock}"
SPIRE_SERVER_CONTAINER="${SPIRE_SERVER_CONTAINER:-openshell-spiffe-demo-spire-server}"
SPIRE_SERVER_BIN="${SPIRE_SERVER_BIN:-/opt/spire/bin/spire-server}"

if [[ -n "${SANDBOX_SELECTORS:-}" ]]; then
    read -r -a selectors <<<"$SANDBOX_SELECTORS"
else
    selectors=(
        "docker:label:openshell.managed:true"
        "docker:label:openshell.ai/sandbox-id:${SANDBOX_ID}"
    )
fi

args=(
    entry create
    -socketPath "$SPIRE_SERVER_SOCKET"
    -parentID "$SPIRE_AGENT_PARENT_ID"
    -spiffeID "$SANDBOX_SPIFFE_ID"
    -jwtSVIDTTL 300
)

for selector in "${selectors[@]}"; do
    args+=(-selector "$selector")
done

printf "Registering sandbox SPIFFE entry: %s\n" "$SANDBOX_SPIFFE_ID" >&2
podman exec "$SPIRE_SERVER_CONTAINER" "$SPIRE_SERVER_BIN" "${args[@]}"
