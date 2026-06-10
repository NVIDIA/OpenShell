#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Manual smoke test: drive openshell-sdk and @openshell/sdk's OIDC paths
# against a local Keycloak (the same realm used by the Python OIDC e2e suite).
#
# Prerequisites:
#   mise run keycloak         # start Keycloak on http://localhost:8180
#   mise run sdk-node:build   # build the napi binding
#
# Usage:
#   scripts/openshell-sdk-oidc-smoke.sh
#
# Overrides (env):
#   KEYCLOAK_URL, REALM, CLIENT_ID, USERNAME, PASSWORD

set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
REALM="${REALM:-openshell}"
CLIENT_ID="${CLIENT_ID:-openshell-cli}"
USERNAME="${USERNAME:-admin@test}"
PASSWORD="${PASSWORD:-admin}"

ISSUER="${KEYCLOAK_URL}/realms/${REALM}"
TOKEN_URL="${ISSUER}/protocol/openid-connect/token"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

mint_refresh_token() {
    curl -sf -X POST "$TOKEN_URL" \
        --data-urlencode "grant_type=password" \
        --data-urlencode "client_id=${CLIENT_ID}" \
        --data-urlencode "username=${USERNAME}" \
        --data-urlencode "password=${PASSWORD}" \
        --data-urlencode "scope=openid" \
        | jq -r .refresh_token
}

echo "==> verifying Keycloak realm is reachable: ${ISSUER}"
if ! curl -sfo /dev/null "${ISSUER}/.well-known/openid-configuration"; then
    echo "ERR: ${ISSUER}/.well-known/openid-configuration is not reachable." >&2
    echo "     Start Keycloak first:  mise run keycloak" >&2
    exit 1
fi

echo "==> minting initial refresh token via the password grant"
refresh_token="$(mint_refresh_token)"
if [ -z "$refresh_token" ] || [ "$refresh_token" = "null" ]; then
    echo "ERR: Keycloak did not return a refresh_token." >&2
    exit 1
fi
echo "    refresh_token: ${refresh_token:0:24}..."

export OPENSHELL_OIDC_ISSUER="$ISSUER"
export OPENSHELL_OIDC_CLIENT_ID="$CLIENT_ID"
export OPENSHELL_OIDC_REFRESH_TOKEN="$refresh_token"

echo
echo "============================================================"
echo "== Rust: openshell_sdk::oidc::{discover, refresh_token}"
echo "============================================================"
cargo run --quiet --example oidc_smoke -p openshell-sdk

echo
echo "============================================================"
echo "== TypeScript: @openshell/sdk OidcRefresher"
echo "============================================================"
# The Rust run rotated the refresh token server-side; mint a fresh one.
export OPENSHELL_OIDC_REFRESH_TOKEN="$(mint_refresh_token)"
node "${repo_root}/crates/openshell-sdk-node/test/oidc_smoke.mjs"

echo
echo "==> all OIDC smoke checks passed"
