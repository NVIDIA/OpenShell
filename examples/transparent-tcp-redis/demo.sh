#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_FILE="${SCRIPT_DIR}/policy.yaml"
CLIENT_FILE="${SCRIPT_DIR}/redis_client.py"

SANDBOX_NAME="${SANDBOX_NAME:-tcp-redis-demo}"
REDIS_CONTAINER="${REDIS_CONTAINER:-openshell-transparent-tcp-redis-demo}"
DOCKER_NETWORK="${OPENSHELL_DOCKER_NETWORK:-openshell-docker}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
REDIS_REAL_IP=""

SANDBOX_CREATED=0
REDIS_CREATED=0

cleanup() {
    local status=$?
    local ocsf_pattern
    local relevant_logs
    local sandbox_logs
    trap - EXIT

    if [[ "$SANDBOX_CREATED" == "1" ]]; then
        printf '\nRelevant OCSF events:\n'
        ocsf_pattern='\[OCSF \].*(Policy DNS mapped|Transparent TCP mapping_id=|policy_dns_ineligible|transparent_tcp_port_mismatch|BYPASS_DETECT)'
        # Give the bounded gateway log stream a moment to receive the final
        # network decision before fetching it and deleting the sandbox.
        sleep 1
        if sandbox_logs="$(openshell logs "$SANDBOX_NAME" \
            --source sandbox \
            --since 10m \
            -n 500 2>&1)"; then
            if relevant_logs="$(printf '%s\n' "$sandbox_logs" | grep -E "$ocsf_pattern")"; then
                printf '%s\n' "$relevant_logs"
            else
                printf 'No relevant policy DNS or transparent TCP events found.\n'
            fi
        else
            printf 'Unable to retrieve sandbox logs:\n%s\n' "$sandbox_logs" >&2
        fi
    fi

    printf '\nCleaning up...\n'
    if [[ "$SANDBOX_CREATED" == "1" ]]; then
        openshell sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
    fi
    if [[ "$REDIS_CREATED" == "1" ]]; then
        docker rm --force "$REDIS_CONTAINER" >/dev/null 2>&1 || true
    fi

    exit "$status"
}
trap cleanup EXIT

run() {
    printf '\n$'
    printf ' %q' "$@"
    printf '\n'
    "$@"
}

for command in docker openshell; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'required command not found: %s\n' "$command" >&2
        exit 1
    fi
done

if ! docker info >/dev/null 2>&1; then
    printf 'Docker is not available. Start Docker and try again.\n' >&2
    exit 1
fi

if ! docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1; then
    printf 'Docker network %q does not exist.\n' "$DOCKER_NETWORK" >&2
    printf 'Start a Docker-backed OpenShell gateway, or set OPENSHELL_DOCKER_NETWORK.\n' >&2
    exit 1
fi

if ! openshell sandbox list --limit 1 >/dev/null 2>&1; then
    printf 'The configured OpenShell gateway is not reachable.\n' >&2
    printf 'Start or select a Docker-backed gateway and try again.\n' >&2
    exit 1
fi

if docker container inspect "$REDIS_CONTAINER" >/dev/null 2>&1; then
    printf 'Redis container %q already exists; choose REDIS_CONTAINER or remove it.\n' "$REDIS_CONTAINER" >&2
    exit 1
fi

if openshell sandbox get "$SANDBOX_NAME" >/dev/null 2>&1; then
    printf 'Sandbox %q already exists; choose SANDBOX_NAME or delete it.\n' "$SANDBOX_NAME" >&2
    exit 1
fi

printf 'Starting Redis on the OpenShell Docker network...\n'
REDIS_CREATED=1
run docker run \
    --detach \
    --rm \
    --name "$REDIS_CONTAINER" \
    --network "$DOCKER_NETWORK" \
    --network-alias redis.openshell.demo \
    "$REDIS_IMAGE" \
    redis-server --save '' --appendonly no

for _ in $(seq 1 30); do
    if docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null | grep -qx PONG; then
        break
    fi
    sleep 1
done
if ! docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null | grep -qx PONG; then
    printf 'Redis did not become ready.\n' >&2
    exit 1
fi
REDIS_REAL_IP="$(docker inspect \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$REDIS_CONTAINER")"
if [[ -z "$REDIS_REAL_IP" ]]; then
    printf 'Could not determine the Redis container IP.\n' >&2
    exit 1
fi

printf '\nCreating a Docker-backed sandbox with an explicit TCP endpoint policy...\n'
SANDBOX_CREATED=1
run openshell sandbox create \
    --name "$SANDBOX_NAME" \
    --policy "$POLICY_FILE" \
    --upload "${CLIENT_FILE}:/sandbox" \
    --no-auto-providers \
    --no-tty \
    -- echo 'sandbox ready'

printf '\nRunning native Redis commands from the sandbox...\n'
run openshell sandbox exec \
    --name "$SANDBOX_NAME" \
    --no-tty \
    -- python3 /sandbox/redis_client.py "$REDIS_REAL_IP" "$REDIS_CONTAINER"

printf '\nTransparent TCP Redis example completed successfully.\n'
