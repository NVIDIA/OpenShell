#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=spire/common.sh
source "${SCRIPT_DIR}/spire/common.sh"

require_cmd podman
require_cmd curl
require_cmd openssl

if [[ -n "${SPIRE_AGENT_ENV_FILE:-}" ]]; then
    # shellcheck disable=SC1090
    source "$SPIRE_AGENT_ENV_FILE"
fi

GATEWAY_CONTAINER="${GATEWAY_CONTAINER:-openshell-spiffe-demo-gateway}"
GATEWAY_IMAGE="${GATEWAY_IMAGE:-ghcr.io/nvidia/openshell/gateway:latest}"
GATEWAY_ID="${GATEWAY_ID:-podman-spiffe-demo}"
GATEWAY_PORT="${GATEWAY_PORT:-8888}"
GATEWAY_HEALTH_PORT="${GATEWAY_HEALTH_PORT:-8889}"
GATEWAY_STATE_DIR="${GATEWAY_STATE_DIR:-}"
GATEWAY_ENV_FILE="${GATEWAY_ENV_FILE:-}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-}"
SUPERVISOR_IMAGE="${SUPERVISOR_IMAGE:-}"
SANDBOX_IMAGE_PULL_POLICY="${SANDBOX_IMAGE_PULL_POLICY:-missing}"
PODMAN_STOP_TIMEOUT_SECS="${PODMAN_STOP_TIMEOUT_SECS:-3}"
GATEWAY_OIDC_ISSUER="${GATEWAY_OIDC_ISSUER:-}"
GATEWAY_OIDC_AUDIENCE="${GATEWAY_OIDC_AUDIENCE:-openshell-cli}"
GATEWAY_OIDC_JWKS_TTL_SECS="${GATEWAY_OIDC_JWKS_TTL_SECS:-3600}"
GATEWAY_OIDC_ROLES_CLAIM="${GATEWAY_OIDC_ROLES_CLAIM:-realm_access.roles}"
GATEWAY_OIDC_ADMIN_ROLE="${GATEWAY_OIDC_ADMIN_ROLE:-openshell-admin}"
GATEWAY_OIDC_USER_ROLE="${GATEWAY_OIDC_USER_ROLE:-openshell-user}"
GATEWAY_OIDC_SCOPES_CLAIM="${GATEWAY_OIDC_SCOPES_CLAIM:-}"
GATEWAY_OIDC_CLIENT_ID="${GATEWAY_OIDC_CLIENT_ID:-openshell-cli}"
GATEWAY_OIDC_LOGIN_SCOPES="${GATEWAY_OIDC_LOGIN_SCOPES:-}"
if [[ -z "${GATEWAY_ALLOW_UNAUTHENTICATED_USERS:-}" ]]; then
    if [[ -n "$GATEWAY_OIDC_ISSUER" ]]; then
        GATEWAY_ALLOW_UNAUTHENTICATED_USERS="false"
    else
        GATEWAY_ALLOW_UNAUTHENTICATED_USERS="true"
    fi
fi

if [[ -z "${SPIRE_AGENT_SOCKET_HOST_PATH:-}" ]]; then
    printf "SPIRE_AGENT_SOCKET_HOST_PATH is required; source start-agent.sh's env file or set SPIRE_AGENT_ENV_FILE\n" >&2
    exit 1
fi
if [[ ! -S "$SPIRE_AGENT_SOCKET_HOST_PATH" ]]; then
    printf "SPIRE agent Workload API socket does not exist: %s\n" "$SPIRE_AGENT_SOCKET_HOST_PATH" >&2
    exit 1
fi
if ! PODMAN_SOCKET="$(detect_podman_socket)"; then
    printf "could not find a Podman API socket; set PODMAN_SOCKET\n" >&2
    exit 1
fi
if [[ ! "$PODMAN_STOP_TIMEOUT_SECS" =~ ^[0-9]+$ ]]; then
    printf "PODMAN_STOP_TIMEOUT_SECS must be a non-negative integer, got: %s\n" "$PODMAN_STOP_TIMEOUT_SECS" >&2
    exit 1
fi
if [[ ! "$GATEWAY_OIDC_JWKS_TTL_SECS" =~ ^[0-9]+$ ]]; then
    printf "GATEWAY_OIDC_JWKS_TTL_SECS must be a non-negative integer, got: %s\n" "$GATEWAY_OIDC_JWKS_TTL_SECS" >&2
    exit 1
fi
if [[ "$GATEWAY_ALLOW_UNAUTHENTICATED_USERS" != "true" && "$GATEWAY_ALLOW_UNAUTHENTICATED_USERS" != "false" ]]; then
    printf "GATEWAY_ALLOW_UNAUTHENTICATED_USERS must be true or false, got: %s\n" "$GATEWAY_ALLOW_UNAUTHENTICATED_USERS" >&2
    exit 1
fi

if [[ -z "$GATEWAY_STATE_DIR" ]]; then
    GATEWAY_STATE_DIR="$(mktemp -d)"
fi

toml_string_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf "%s\n" "$value"
}

write_gateway_env_line() {
    local name="$1"
    local value="$2"
    if [[ -n "$GATEWAY_ENV_FILE" ]]; then
        printf "%s=%s\n" "$name" "$(quote_env_value "$value")" >>"$GATEWAY_ENV_FILE"
    fi
}

reset_gateway_env_file() {
    if [[ -n "$GATEWAY_ENV_FILE" ]]; then
        mkdir -p "$(dirname "$GATEWAY_ENV_FILE")"
        : >"$GATEWAY_ENV_FILE"
    fi
}

write_gateway_config() {
    local podman_socket_in_container="$1"
    local jwt_dir="${GATEWAY_STATE_DIR}/jwt"
    local config_path="${GATEWAY_STATE_DIR}/gateway.toml"
    local sandbox_image_line=""
    local supervisor_image_line=""
    local oidc_block=""

    mkdir -p "$jwt_dir"
    if [[ ! -s "${jwt_dir}/signing.pem" ]]; then
        openssl genpkey -algorithm ed25519 -out "${jwt_dir}/signing.pem" >/dev/null 2>&1
        openssl pkey -in "${jwt_dir}/signing.pem" -pubout -out "${jwt_dir}/public.pem" >/dev/null 2>&1
        openssl rand -hex 8 >"${jwt_dir}/kid"
    fi
    if [[ -n "$SANDBOX_IMAGE" ]]; then
        sandbox_image_line="default_image = \"$(toml_string_escape "$SANDBOX_IMAGE")\""
    fi
    if [[ -n "$SUPERVISOR_IMAGE" ]]; then
        supervisor_image_line="supervisor_image = \"$(toml_string_escape "$SUPERVISOR_IMAGE")\""
    fi
    if [[ -n "$GATEWAY_OIDC_ISSUER" ]]; then
        oidc_block="
[openshell.gateway.oidc]
issuer = \"$(toml_string_escape "$GATEWAY_OIDC_ISSUER")\"
audience = \"$(toml_string_escape "$GATEWAY_OIDC_AUDIENCE")\"
jwks_ttl_secs = ${GATEWAY_OIDC_JWKS_TTL_SECS}
roles_claim = \"$(toml_string_escape "$GATEWAY_OIDC_ROLES_CLAIM")\"
admin_role = \"$(toml_string_escape "$GATEWAY_OIDC_ADMIN_ROLE")\"
user_role = \"$(toml_string_escape "$GATEWAY_OIDC_USER_ROLE")\"
scopes_claim = \"$(toml_string_escape "$GATEWAY_OIDC_SCOPES_CLAIM")\"
"
    fi

    cat >"$config_path" <<EOF
[openshell]
version = 1

[openshell.gateway]
bind_address = "0.0.0.0:8080"
health_bind_address = "0.0.0.0:8081"
log_level = "info"
compute_drivers = ["podman"]
disable_tls = true

[openshell.gateway.auth]
allow_unauthenticated_users = ${GATEWAY_ALLOW_UNAUTHENTICATED_USERS}

[openshell.gateway.gateway_jwt]
signing_key_path = "${jwt_dir}/signing.pem"
public_key_path = "${jwt_dir}/public.pem"
kid_path = "${jwt_dir}/kid"
gateway_id = "$(toml_string_escape "$GATEWAY_ID")"
ttl_secs = 3600
${oidc_block}

[openshell.drivers.podman]
socket_path = "${podman_socket_in_container}"
network_name = "$(toml_string_escape "$PODMAN_NETWORK")"
grpc_endpoint = "http://${GATEWAY_CONTAINER}:8080"
image_pull_policy = "$(toml_string_escape "$SANDBOX_IMAGE_PULL_POLICY")"
stop_timeout_secs = ${PODMAN_STOP_TIMEOUT_SECS}
provider_spiffe_workload_api_socket = "${SPIRE_AGENT_SOCKET_HOST_PATH}"
$sandbox_image_line
$supervisor_image_line
EOF

    printf "%s\n" "$config_path"
}

reset_gateway_env_file
ensure_network
mkdir -p "$GATEWAY_STATE_DIR"
chmod 0777 "$GATEWAY_STATE_DIR"

podman_socket_in_container="/run/podman/podman.sock"
gateway_config="$(write_gateway_config "$podman_socket_in_container")"

if [[ "$CLEANUP_EXISTING" == "1" ]]; then
    cleanup_container "$GATEWAY_CONTAINER"
fi

run podman run -d \
    --name "$GATEWAY_CONTAINER" \
    --network "$PODMAN_NETWORK" \
    --network-alias "$GATEWAY_CONTAINER" \
    --label openshell.spiffe-demo=gateway \
    --user 0 \
    --security-opt label=disable \
    -p "127.0.0.1:${GATEWAY_PORT}:8080" \
    -p "127.0.0.1:${GATEWAY_HEALTH_PORT}:8081" \
    -v "$(podman_socket_volume "$PODMAN_SOCKET" "$podman_socket_in_container")" \
    -v "${SPIRE_AGENT_SOCKET_HOST_PATH}:${SPIRE_AGENT_SOCKET_HOST_PATH}:z" \
    -v "${GATEWAY_STATE_DIR}:${GATEWAY_STATE_DIR}:z" \
    -e "OPENSHELL_GATEWAY_CONFIG=${gateway_config}" \
    -e "OPENSHELL_DB_URL=sqlite:${GATEWAY_STATE_DIR}/gateway.db?mode=rwc" \
    -e "OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET=${SPIRE_AGENT_SOCKET_HOST_PATH}" \
    -e "XDG_DATA_HOME=${GATEWAY_STATE_DIR}/data" \
    -e "HOME=${GATEWAY_STATE_DIR}" \
    "$GATEWAY_IMAGE" \
    --config "$gateway_config"

if ! wait_for_http "http://127.0.0.1:${GATEWAY_HEALTH_PORT}/readyz" "OpenShell gateway"; then
    podman logs "$GATEWAY_CONTAINER" >&2 || true
    exit 1
fi

write_gateway_env_line GATEWAY_STATE_DIR "$GATEWAY_STATE_DIR"
write_gateway_env_line GATEWAY_CONFIG "$gateway_config"
write_gateway_env_line GATEWAY_CONTAINER "$GATEWAY_CONTAINER"
write_gateway_env_line GATEWAY_ENDPOINT "http://127.0.0.1:${GATEWAY_PORT}"
write_gateway_env_line GATEWAY_HEALTH_ENDPOINT "http://127.0.0.1:${GATEWAY_HEALTH_PORT}"
write_gateway_env_line GATEWAY_OIDC_ISSUER "$GATEWAY_OIDC_ISSUER"
write_gateway_env_line GATEWAY_OIDC_AUDIENCE "$GATEWAY_OIDC_AUDIENCE"
write_gateway_env_line GATEWAY_OIDC_CLIENT_ID "$GATEWAY_OIDC_CLIENT_ID"
write_gateway_env_line GATEWAY_OIDC_LOGIN_SCOPES "$GATEWAY_OIDC_LOGIN_SCOPES"

printf "OpenShell gateway container: %s\n" "$GATEWAY_CONTAINER"
printf "OpenShell gateway endpoint: http://127.0.0.1:%s\n" "$GATEWAY_PORT"
printf "OpenShell gateway health endpoint: http://127.0.0.1:%s\n" "$GATEWAY_HEALTH_PORT"
printf "OpenShell gateway config: %s\n" "$gateway_config"
printf "SPIRE agent Workload API socket: %s\n" "$SPIRE_AGENT_SOCKET_HOST_PATH"
if [[ -n "$GATEWAY_OIDC_ISSUER" ]]; then
    printf "OpenShell gateway OIDC issuer: %s\n" "$GATEWAY_OIDC_ISSUER"
    printf "Register/login with:\n"
    printf "  openshell gateway add http://127.0.0.1:%s --name %s --oidc-issuer %s --oidc-client-id %s --oidc-audience %s" \
        "$GATEWAY_PORT" "$GATEWAY_ID" "$GATEWAY_OIDC_ISSUER" "$GATEWAY_OIDC_CLIENT_ID" "$GATEWAY_OIDC_AUDIENCE"
    if [[ -n "$GATEWAY_OIDC_LOGIN_SCOPES" ]]; then
        printf " --oidc-scopes %s" "$GATEWAY_OIDC_LOGIN_SCOPES"
    fi
    printf "\n"
fi
if [[ -n "$GATEWAY_ENV_FILE" ]]; then
    printf "Wrote environment file: %s\n" "$GATEWAY_ENV_FILE"
fi
