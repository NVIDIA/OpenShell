#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run a command against the local Keycloak OIDC fixture. An already-running
# fixture is preserved; a fixture started by this wrapper is removed on exit.

set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <command> [args...]" >&2
    exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYCLOAK_PORT="${KEYCLOAK_PORT:-8180}"

if [ -n "${CONTAINER_RUNTIME:-}" ]; then
    RUNTIME="$CONTAINER_RUNTIME"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    RUNTIME=docker
elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    RUNTIME=podman
else
    echo "Error: no usable Docker or Podman runtime found" >&2
    exit 1
fi

STARTED_KEYCLOAK=0
cleanup() {
    local status=$?
    trap - EXIT
    if [ "$status" -ne 0 ]; then
        echo "Keycloak logs from failed OIDC E2E run:" >&2
        "$RUNTIME" logs --tail 80 openshell-keycloak >&2 2>/dev/null || true
    fi
    if [ "$STARTED_KEYCLOAK" -eq 1 ]; then
        CONTAINER_RUNTIME="$RUNTIME" KEYCLOAK_PORT="$KEYCLOAK_PORT" \
            "$ROOT_DIR/scripts/keycloak-dev.sh" stop
    fi
    exit "$status"
}
trap cleanup EXIT

if ! CONTAINER_RUNTIME="$RUNTIME" KEYCLOAK_PORT="$KEYCLOAK_PORT" \
    "$ROOT_DIR/scripts/keycloak-dev.sh" status >/dev/null 2>&1; then
    STARTED_KEYCLOAK=1
    CONTAINER_RUNTIME="$RUNTIME" KEYCLOAK_PORT="$KEYCLOAK_PORT" \
        "$ROOT_DIR/scripts/keycloak-dev.sh" start
fi

export OPENSHELL_E2E_OIDC_ISSUER="${OPENSHELL_E2E_OIDC_ISSUER:-http://localhost:${KEYCLOAK_PORT}/realms/openshell}"
export OPENSHELL_E2E_OIDC_USERNAME="${OPENSHELL_E2E_OIDC_USERNAME:-admin@test}"
export OPENSHELL_E2E_OIDC_PASSWORD="${OPENSHELL_E2E_OIDC_PASSWORD:-admin}"
export OPENSHELL_E2E_OIDC_ROLE="${OPENSHELL_E2E_OIDC_ROLE:-openshell-admin}"

"$@"
