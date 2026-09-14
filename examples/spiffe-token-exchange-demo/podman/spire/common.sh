#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SPIRE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PODMAN_NETWORK="${PODMAN_NETWORK:-openshell}"
TRUST_DOMAIN="${TRUST_DOMAIN:-openshell.local}"
SPIRE_AGENT_PARENT_ID="${SPIRE_AGENT_PARENT_ID:-spiffe://${TRUST_DOMAIN}/openshell/spire-agent/demo}"
SPIRE_SERVER_IMAGE="${SPIRE_SERVER_IMAGE:-ghcr.io/spiffe/spire-server:1.12.4}"
SPIRE_AGENT_IMAGE="${SPIRE_AGENT_IMAGE:-ghcr.io/spiffe/spire-agent:1.12.4}"
SPIRE_OIDC_IMAGE="${SPIRE_OIDC_IMAGE:-ghcr.io/spiffe/oidc-discovery-provider:1.12.4}"
SPIRE_SERVER_CONTAINER="${SPIRE_SERVER_CONTAINER:-openshell-spiffe-demo-spire-server}"
SPIRE_AGENT_CONTAINER="${SPIRE_AGENT_CONTAINER:-openshell-spiffe-demo-spire-agent}"
SPIRE_OIDC_CONTAINER="${SPIRE_OIDC_CONTAINER:-openshell-spiffe-demo-spire-oidc}"
SPIRE_SERVER_BIN="${SPIRE_SERVER_BIN:-/opt/spire/bin/spire-server}"
OIDC_PORT="${OIDC_PORT:-18081}"
SPIRE_STATE_DIR="${SPIRE_STATE_DIR:-}"
SPIRE_ENV_FILE="${SPIRE_ENV_FILE:-}"
CLEANUP_EXISTING="${CLEANUP_EXISTING:-1}"
PODMAN_SOCKET_DEMO_OWNED="${PODMAN_SOCKET_DEMO_OWNED:-0}"

run() {
    printf "\n$ %s\n" "$*" >&2
    "$@"
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf "missing required command: %s\n" "$cmd" >&2
        exit 1
    fi
}

cleanup_container() {
    podman rm -f "$1" >/dev/null 2>&1 || true
}

ensure_network() {
    if ! podman network exists "$PODMAN_NETWORK" >/dev/null 2>&1; then
        run podman network create "$PODMAN_NETWORK"
    fi
}

normalize_podman_socket_path() {
    local socket_path="$1"
    if [[ "$socket_path" == unix://* ]]; then
        socket_path="${socket_path#unix://}"
    fi
    printf "%s\n" "$socket_path"
}

detect_podman_socket() {
    if [[ -n "${PODMAN_SOCKET:-}" ]]; then
        normalize_podman_socket_path "$PODMAN_SOCKET"
        return
    fi
    if [[ -n "${XDG_RUNTIME_DIR:-}" && -S "${XDG_RUNTIME_DIR}/podman/podman.sock" ]]; then
        printf "%s\n" "${XDG_RUNTIME_DIR}/podman/podman.sock"
        return
    fi
    if [[ -S "/run/user/$(id -u)/podman/podman.sock" ]]; then
        printf "%s\n" "/run/user/$(id -u)/podman/podman.sock"
        return
    fi
    if [[ -S /run/podman/podman.sock ]]; then
        printf "%s\n" /run/podman/podman.sock
        return
    fi
    if [[ -S /var/run/docker.sock ]]; then
        printf "%s\n" /var/run/docker.sock
        return
    fi
    local connection_socket
    connection_socket="$(
        podman system connection list --format '{{.URI}}' 2>/dev/null |
            sed -n 's|^unix://||p' |
            while IFS= read -r candidate; do
                if [[ -S "$candidate" ]]; then
                    printf "%s\n" "$candidate"
                    break
                fi
            done
    )"
    if [[ -n "$connection_socket" ]]; then
        printf "%s\n" "$connection_socket"
        return
    fi
    return 1
}

podman_socket_volume() {
    local source="$1"
    local target="$2"
    if [[ "$PODMAN_SOCKET_DEMO_OWNED" == "1" ]]; then
        printf "%s:%s:z\n" "$source" "$target"
    else
        printf "%s:%s\n" "$source" "$target"
    fi
}

quote_env_value() {
    printf "%q" "$1"
}

write_env_line() {
    local name="$1"
    local value="$2"
    if [[ -n "$SPIRE_ENV_FILE" ]]; then
        printf "%s=%s\n" "$name" "$(quote_env_value "$value")" >>"$SPIRE_ENV_FILE"
    fi
}

reset_env_file() {
    if [[ -n "$SPIRE_ENV_FILE" ]]; then
        mkdir -p "$(dirname "$SPIRE_ENV_FILE")"
        : >"$SPIRE_ENV_FILE"
    fi
}

copy_config() {
    local source="$1"
    local dest="$2"
    mkdir -p "$(dirname "$dest")"
    cp "$source" "$dest"
    chmod 0644 "$dest"
}

wait_for_socket() {
    local path="$1"
    local label="$2"
    for _ in $(seq 1 80); do
        if [[ -S "$path" ]]; then
            return
        fi
        sleep 0.25
    done
    printf "%s was not created at %s\n" "$label" "$path" >&2
    return 1
}

wait_for_http() {
    local url="$1"
    local label="$2"
    for _ in $(seq 1 80); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return
        fi
        sleep 0.25
    done
    printf "%s did not become ready at %s\n" "$label" "$url" >&2
    return 1
}
