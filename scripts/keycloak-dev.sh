#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Start/stop a Keycloak dev instance for OIDC testing.
# Usage:
#   ./scripts/keycloak-dev.sh start   # start Keycloak on port 8180
#   ./scripts/keycloak-dev.sh stop    # stop and remove the container
#   ./scripts/keycloak-dev.sh status  # check if Keycloak is running

set -euo pipefail

CONTAINER_NAME="openshell-keycloak"
KEYCLOAK_IMAGE="quay.io/keycloak/keycloak:24.0"
KEYCLOAK_PORT="${KEYCLOAK_PORT:-8180}"
REALM_FILE="$(cd "$(dirname "$0")" && pwd)/keycloak-realm.json"
HEALTH_TIMEOUT=90

# Container runtime: honour CONTAINER_RUNTIME, else prefer docker, fall back to podman.
if [ -n "${CONTAINER_RUNTIME:-}" ]; then
    CTR="$CONTAINER_RUNTIME"
elif command -v docker &>/dev/null; then
    CTR=docker
elif command -v podman &>/dev/null; then
    CTR=podman
else
    echo "Error: neither docker nor podman found in PATH" >&2
    exit 1
fi

cmd_start() {
    # Idempotent: if the container is already running, just print info.
    if $CTR inspect "$CONTAINER_NAME" &>/dev/null; then
        if $CTR inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q true; then
            echo "Keycloak is already running on port $KEYCLOAK_PORT"
            print_info
            return 0
        fi
        echo "Removing stopped container $CONTAINER_NAME..."
        $CTR rm "$CONTAINER_NAME" >/dev/null
    fi

    if [ ! -f "$REALM_FILE" ]; then
        echo "Error: realm file not found: $REALM_FILE" >&2
        exit 1
    fi

    echo "Starting Keycloak ($KEYCLOAK_IMAGE) on port $KEYCLOAK_PORT..."

    $CTR run -d \
        --name "$CONTAINER_NAME" \
        -p "${KEYCLOAK_PORT}:8080" \
        -e KEYCLOAK_ADMIN=admin \
        -e KEYCLOAK_ADMIN_PASSWORD=admin \
        -v "${REALM_FILE}:/opt/keycloak/data/import/realm.json:ro,z" \
        "$KEYCLOAK_IMAGE" \
        start-dev --import-realm

    echo "Waiting for Keycloak to become healthy (up to ${HEALTH_TIMEOUT}s)..."
    local elapsed=0
    while [ $elapsed -lt $HEALTH_TIMEOUT ]; do
        if curl -sf "http://localhost:${KEYCLOAK_PORT}/realms/master" >/dev/null 2>&1; then
            echo "Keycloak is ready."
            print_info
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    echo "Error: Keycloak did not become healthy within ${HEALTH_TIMEOUT}s" >&2
    echo "Logs:"
    $CTR logs --tail 30 "$CONTAINER_NAME"
    exit 1
}

cmd_stop() {
    if $CTR inspect "$CONTAINER_NAME" &>/dev/null; then
        echo "Stopping and removing $CONTAINER_NAME..."
        $CTR stop "$CONTAINER_NAME" 2>/dev/null || true
        $CTR rm "$CONTAINER_NAME" 2>/dev/null || true
        echo "Done."
    else
        echo "Container $CONTAINER_NAME is not running."
    fi
}

cmd_status() {
    if $CTR inspect "$CONTAINER_NAME" &>/dev/null; then
        if $CTR inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q true; then
            echo "Keycloak is running on port $KEYCLOAK_PORT"
            print_info
            return 0
        fi
        echo "Container $CONTAINER_NAME exists but is not running."
        return 1
    fi
    echo "Container $CONTAINER_NAME does not exist."
    return 1
}

print_info() {
    local issuer="http://localhost:${KEYCLOAK_PORT}/realms/openshell"
    echo ""
    echo "  Issuer URL:     $issuer"
    echo "  Discovery:      ${issuer}/.well-known/openid-configuration"
    echo "  Admin console:  http://localhost:${KEYCLOAK_PORT}/admin  (admin/admin)"
    echo ""
    echo "  Test users:"
    echo "    admin@test / admin  (role: openshell-admin)"
    echo "    user@test  / user   (role: openshell-user)"
    echo ""
    echo "  Get a token:"
    echo "    curl -s -X POST ${issuer}/protocol/openid-connect/token \\"
    echo "      -d 'grant_type=password&client_id=openshell-cli&username=admin@test&password=admin' \\"
    echo "      | jq -r .access_token"
    echo ""
}

case "${1:-help}" in
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    status) cmd_status ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        exit 1
        ;;
esac
