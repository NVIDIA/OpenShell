#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROFILE_TEMPLATE="${SCRIPT_DIR}/provider-profile.yaml"
TOKEN_ISSUER_JS="${DEMO_ROOT}/k8s/token-issuer.js"
PROTECTED_SERVICE_JS="${DEMO_ROOT}/k8s/protected-service.js"

SANDBOX_NAME="${SANDBOX_NAME:-spiffe-podman-demo}"
PROVIDER_NAME="${PROVIDER_NAME:-spiffe-token-exchange-demo-podman}"
PROFILE_ID="${PROFILE_ID:-spiffe-token-exchange-demo-podman}"
START_GATEWAY="${START_GATEWAY:-0}"
MANAGED_GATEWAY_PORT="${MANAGED_GATEWAY_PORT:-18082}"
MANAGED_GATEWAY_HEALTH_PORT="${MANAGED_GATEWAY_HEALTH_PORT:-18083}"
if [[ -z "${GATEWAY_ENDPOINT:-}" ]]; then
    if [[ "$START_GATEWAY" == "1" ]]; then
        GATEWAY_ENDPOINT="http://127.0.0.1:${MANAGED_GATEWAY_PORT}"
    else
        GATEWAY_ENDPOINT="http://127.0.0.1:8080"
    fi
fi
PODMAN_NETWORK="${PODMAN_NETWORK:-openshell}"
TOKEN_ISSUER_PORT="${TOKEN_ISSUER_PORT:-18080}"
OIDC_PORT="${OIDC_PORT:-18081}"
TOKEN_ISSUER_SERVICE_HOST="${TOKEN_ISSUER_SERVICE_HOST:-token-exchange-issuer.default.svc.cluster.local}"
KEEP_SANDBOX="${KEEP_SANDBOX:-0}"
KEEP_DEMO="${KEEP_DEMO:-0}"
START_SPIRE="${START_SPIRE:-1}"
ACCESS_TOKEN_SECRET="${ACCESS_TOKEN_SECRET:-$(openssl rand -hex 32)}"
TRUST_DOMAIN="${TRUST_DOMAIN:-openshell.local}"
SPIRE_AGENT_PARENT_ID="${SPIRE_AGENT_PARENT_ID:-spiffe://${TRUST_DOMAIN}/openshell/spire-agent/demo}"
SPIRE_AGENT_SOCKET_HOST_PATH="${SPIRE_AGENT_SOCKET_HOST_PATH:-}"
SPIRE_SERVER_IMAGE="${SPIRE_SERVER_IMAGE:-ghcr.io/spiffe/spire-server:1.12.4}"
SPIRE_AGENT_IMAGE="${SPIRE_AGENT_IMAGE:-ghcr.io/spiffe/spire-agent:1.12.4}"
SPIRE_OIDC_IMAGE="${SPIRE_OIDC_IMAGE:-ghcr.io/spiffe/oidc-discovery-provider:1.12.4}"
NODE_IMAGE="${NODE_IMAGE:-node:22-alpine}"
SPIRE_SERVER_CONTAINER="${SPIRE_SERVER_CONTAINER:-openshell-spiffe-demo-spire-server}"
SPIRE_AGENT_CONTAINER="${SPIRE_AGENT_CONTAINER:-openshell-spiffe-demo-spire-agent}"
SPIRE_OIDC_CONTAINER="${SPIRE_OIDC_CONTAINER:-openshell-spiffe-demo-spire-oidc}"
GATEWAY_CONTAINER="${GATEWAY_CONTAINER:-openshell-spiffe-demo-gateway}"
GATEWAY_IMAGE="${GATEWAY_IMAGE:-ghcr.io/nvidia/openshell/gateway:latest}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-}"
SUPERVISOR_IMAGE="${SUPERVISOR_IMAGE:-}"
SANDBOX_IMAGE_PULL_POLICY="${SANDBOX_IMAGE_PULL_POLICY:-missing}"
PODMAN_STOP_TIMEOUT_SECS="${PODMAN_STOP_TIMEOUT_SECS:-3}"
TOKEN_ISSUER_CONTAINER="${TOKEN_ISSUER_CONTAINER:-openshell-spiffe-demo-token-issuer}"
ALPHA_CONTAINER="${ALPHA_CONTAINER:-openshell-spiffe-demo-alpha}"
BETA_CONTAINER="${BETA_CONTAINER:-openshell-spiffe-demo-beta}"

TMP_DIR="$(mktemp -d)"
RENDERED_PROFILE="${TMP_DIR}/provider-profile.yaml"
MOUNT_DIR="${TMP_DIR}/mounts"
TOKEN_ISSUER_JS_MOUNT="${MOUNT_DIR}/token-issuer.js"
PROTECTED_SERVICE_JS_MOUNT="${MOUNT_DIR}/protected-service.js"
PODMAN_SERVICE_PID=""
PODMAN_SOCKET_DEMO_OWNED="0"

default_gateway_name() {
    if [[ -n "${GATEWAY_NAME:-}" ]]; then
        printf "%s\n" "$GATEWAY_NAME"
        return
    fi
    if [[ -n "${OPENSHELL_GATEWAY:-}" ]]; then
        printf "%s\n" "$OPENSHELL_GATEWAY"
        return
    fi
    if [[ "$START_GATEWAY" == "1" ]]; then
        printf "podman-spiffe-demo\n"
        return
    fi

    local config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
    if [[ -s "${config_home}/openshell/active_gateway" ]]; then
        head -n1 "${config_home}/openshell/active_gateway"
        return
    fi
    if [[ -s /etc/openshell/active_gateway ]]; then
        head -n1 /etc/openshell/active_gateway
        return
    fi

    printf "local\n"
}

GATEWAY_NAME="$(default_gateway_name)"
OS=(openshell --gateway "$GATEWAY_NAME" --gateway-endpoint "$GATEWAY_ENDPOINT")

run() {
    printf "\n$ %s\n" "$*"
    "$@"
}

prepare_demo_mounts() {
    mkdir -p "$MOUNT_DIR"
    cp "$TOKEN_ISSUER_JS" "$TOKEN_ISSUER_JS_MOUNT"
    cp "$PROTECTED_SERVICE_JS" "$PROTECTED_SERVICE_JS_MOUNT"
    chmod 0644 \
        "$TOKEN_ISSUER_JS_MOUNT" \
        "$PROTECTED_SERVICE_JS_MOUNT"
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf "missing required command: %s\n" "$cmd" >&2
        exit 1
    fi
}

wait_for_port() {
    local port="$1"
    local label="$2"
    for _ in $(seq 1 80); do
        if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    printf "%s did not become reachable on 127.0.0.1:%s\n" "$label" "$port" >&2
    exit 1
}

subject_token_from_json() {
    python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])'
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    if [[ "$haystack" != *"$needle"* ]]; then
        printf "expected output to contain: %s\n" "$needle" >&2
        printf "actual output:\n%s\n" "$haystack" >&2
        exit 1
    fi
}

require_uint() {
    local name="$1"
    local value="$2"
    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        printf "%s must be a non-negative integer, got: %s\n" "$name" "$value" >&2
        exit 1
    fi
}

toml_string_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf "%s\n" "$value"
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

start_podman_service() {
    local socket_path="$1"

    mkdir -p "$(dirname "$socket_path")"
    printf "\n$ podman system service --time=0 unix://%s\n" "$socket_path" >&2
    podman system service --time=0 "unix://${socket_path}" &
    PODMAN_SERVICE_PID="$!"

    for _ in $(seq 1 80); do
        if [[ -S "$socket_path" ]]; then
            chmod 0666 "$socket_path" || true
            return
        fi
        if ! kill -0 "$PODMAN_SERVICE_PID" >/dev/null 2>&1; then
            wait "$PODMAN_SERVICE_PID" || true
            PODMAN_SERVICE_PID=""
            break
        fi
        sleep 0.25
    done

    printf "Podman API service did not create %s; set PODMAN_SOCKET to a running API socket\n" "$socket_path" >&2
    exit 1
}

ensure_podman_socket() {
    local detected_socket
    if detected_socket="$(detect_podman_socket)"; then
        PODMAN_SOCKET="$detected_socket"
        PODMAN_SOCKET_DEMO_OWNED="0"
        return
    fi

    local socket_dir="${TMP_DIR}/podman"
    local socket_path="${socket_dir}/podman.sock"

    printf "\nNo Podman API socket found; starting a temporary rootless Podman API service.\n" >&2
    start_podman_service "$socket_path"
    PODMAN_SOCKET="$socket_path"
    PODMAN_SOCKET_DEMO_OWNED="1"
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

cleanup_container() {
    podman rm -f "$1" >/dev/null 2>&1 || true
}

dump_diagnostics() {
    set +e

    printf "\n=== diagnostics: openshell sandbox logs ===\n" >&2
    "${OS[@]}" logs "$SANDBOX_NAME" -n 120 --source sandbox >&2

    printf "\n=== diagnostics: podman containers ===\n" >&2
    podman ps -a --filter "name=openshell-spiffe-demo" >&2

    for container in \
        "$SPIRE_SERVER_CONTAINER" \
        "$SPIRE_AGENT_CONTAINER" \
        "$SPIRE_OIDC_CONTAINER" \
        "$GATEWAY_CONTAINER" \
        "$TOKEN_ISSUER_CONTAINER" \
        "$ALPHA_CONTAINER" \
        "$BETA_CONTAINER"; do
        printf "\n=== diagnostics: %s logs ===\n" "$container" >&2
        podman logs "$container" >&2
    done

    printf "\n=== diagnostics: sandbox container labels ===\n" >&2
    podman ps -a \
        --filter "label=openshell.ai/sandbox-name=${SANDBOX_NAME}" \
        --format '{{.ID}} {{.Names}} {{.Labels}}' >&2
}

cleanup() {
    if [[ "$KEEP_SANDBOX" != "1" ]]; then
        "${OS[@]}" sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
    fi

    if [[ "$KEEP_DEMO" != "1" ]]; then
        cleanup_container "$TOKEN_ISSUER_CONTAINER"
        cleanup_container "$ALPHA_CONTAINER"
        cleanup_container "$BETA_CONTAINER"
        if [[ "$START_GATEWAY" == "1" ]]; then
            cleanup_container "$GATEWAY_CONTAINER"
        fi
        if [[ "$START_SPIRE" == "1" ]]; then
            cleanup_container "$SPIRE_OIDC_CONTAINER"
            cleanup_container "$SPIRE_AGENT_CONTAINER"
            cleanup_container "$SPIRE_SERVER_CONTAINER"
        fi
        if [[ -n "$PODMAN_SERVICE_PID" ]]; then
            kill "$PODMAN_SERVICE_PID" >/dev/null 2>&1 || true
            wait "$PODMAN_SERVICE_PID" >/dev/null 2>&1 || true
            PODMAN_SERVICE_PID=""
        fi
        rm -rf "$TMP_DIR"
    else
        printf "\nKeeping demo resources. Temporary files: %s\n" "$TMP_DIR" >&2
        if [[ -n "$PODMAN_SERVICE_PID" ]]; then
            printf "Temporary Podman API service PID: %s\n" "$PODMAN_SERVICE_PID" >&2
        fi
    fi
}

on_exit() {
    local status="$1"
    if [[ "$status" -ne 0 ]]; then
        dump_diagnostics || true
    fi
    cleanup
    exit "$status"
}
trap 'on_exit $?' EXIT

ensure_network() {
    if ! podman network exists "$PODMAN_NETWORK" >/dev/null 2>&1; then
        run podman network create "$PODMAN_NETWORK"
    fi
}

start_spire() {
    local podman_socket="$1"
    local spire_state_dir="${TMP_DIR}/spire"
    local server_env="${TMP_DIR}/spire-server.env"
    local agent_env="${TMP_DIR}/spire-agent.env"

    PODMAN_NETWORK="$PODMAN_NETWORK" \
        TRUST_DOMAIN="$TRUST_DOMAIN" \
        SPIRE_AGENT_PARENT_ID="$SPIRE_AGENT_PARENT_ID" \
        SPIRE_SERVER_IMAGE="$SPIRE_SERVER_IMAGE" \
        SPIRE_OIDC_IMAGE="$SPIRE_OIDC_IMAGE" \
        SPIRE_SERVER_CONTAINER="$SPIRE_SERVER_CONTAINER" \
        SPIRE_OIDC_CONTAINER="$SPIRE_OIDC_CONTAINER" \
        SPIRE_STATE_DIR="$spire_state_dir" \
        SPIRE_ENV_FILE="$server_env" \
        OIDC_PORT="$OIDC_PORT" \
        bash "${SCRIPT_DIR}/spire/start-server-oidc.sh"

    # shellcheck disable=SC1090
    source "$server_env"

    PODMAN_NETWORK="$PODMAN_NETWORK" \
        TRUST_DOMAIN="$TRUST_DOMAIN" \
        SPIRE_AGENT_PARENT_ID="$SPIRE_AGENT_PARENT_ID" \
        SPIRE_AGENT_IMAGE="$SPIRE_AGENT_IMAGE" \
        SPIRE_SERVER_CONTAINER="$SPIRE_SERVER_CONTAINER" \
        SPIRE_AGENT_CONTAINER="$SPIRE_AGENT_CONTAINER" \
        SPIRE_STATE_DIR="$SPIRE_STATE_DIR" \
        SPIRE_ENV_FILE="$agent_env" \
        PODMAN_SOCKET="$podman_socket" \
        PODMAN_SOCKET_DEMO_OWNED="$PODMAN_SOCKET_DEMO_OWNED" \
        bash "${SCRIPT_DIR}/spire/start-agent.sh"

    # shellcheck disable=SC1090
    source "$agent_env"
}

write_managed_gateway_config() {
    local podman_socket_in_container="$1"
    local gateway_dir="${TMP_DIR}/gateway"
    local jwt_dir="${gateway_dir}/jwt"
    local config_path="${gateway_dir}/gateway.toml"
    local sandbox_image_line=""
    local supervisor_image_line=""

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
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${jwt_dir}/signing.pem"
public_key_path = "${jwt_dir}/public.pem"
kid_path = "${jwt_dir}/kid"
gateway_id = "podman-spiffe-demo"
ttl_secs = 3600

[openshell.drivers.podman]
socket_path = "${podman_socket_in_container}"
network_name = "${PODMAN_NETWORK}"
grpc_endpoint = "http://${GATEWAY_CONTAINER}:8080"
image_pull_policy = "$(toml_string_escape "$SANDBOX_IMAGE_PULL_POLICY")"
stop_timeout_secs = ${PODMAN_STOP_TIMEOUT_SECS}
provider_spiffe_workload_api_socket = "${SPIRE_AGENT_SOCKET_HOST_PATH}"
$sandbox_image_line
$supervisor_image_line
EOF

    printf "%s\n" "$config_path"
}

start_gateway() {
    local podman_socket="$1"
    local podman_socket_in_container="/run/podman/podman.sock"
    local gateway_dir="${TMP_DIR}/gateway"
    local config_path

    config_path="$(write_managed_gateway_config "$podman_socket_in_container")"
    cleanup_container "$GATEWAY_CONTAINER"

    run podman run -d \
        --name "$GATEWAY_CONTAINER" \
        --network "$PODMAN_NETWORK" \
        --network-alias "$GATEWAY_CONTAINER" \
        --label openshell.spiffe-demo=gateway \
        --user 0 \
        --security-opt label=disable \
        -p "127.0.0.1:${MANAGED_GATEWAY_PORT}:8080" \
        -p "127.0.0.1:${MANAGED_GATEWAY_HEALTH_PORT}:8081" \
        -v "$(podman_socket_volume "$podman_socket" "$podman_socket_in_container")" \
        -v "${SPIRE_AGENT_SOCKET_HOST_PATH}:${SPIRE_AGENT_SOCKET_HOST_PATH}:z" \
        -v "${gateway_dir}:${gateway_dir}:z" \
        -e "OPENSHELL_GATEWAY_CONFIG=${config_path}" \
        -e "OPENSHELL_DB_URL=sqlite:${gateway_dir}/gateway.db?mode=rwc" \
        -e "OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET=${SPIRE_AGENT_SOCKET_HOST_PATH}" \
        -e "XDG_DATA_HOME=${gateway_dir}/data" \
        -e "HOME=${gateway_dir}" \
        "$GATEWAY_IMAGE" \
        --config "$config_path"

    for _ in $(seq 1 120); do
        if curl -fsS "http://127.0.0.1:${MANAGED_GATEWAY_HEALTH_PORT}/readyz" >/dev/null 2>&1 ||
            curl -fsS "http://127.0.0.1:${MANAGED_GATEWAY_HEALTH_PORT}/healthz" >/dev/null 2>&1; then
            return
        fi
        sleep 0.5
    done

    printf "managed OpenShell gateway did not become ready at %s\n" "$GATEWAY_ENDPOINT" >&2
    exit 1
}

start_demo_services() {
    cleanup_container "$TOKEN_ISSUER_CONTAINER"
    cleanup_container "$ALPHA_CONTAINER"
    cleanup_container "$BETA_CONTAINER"

    run podman run -d \
        --name "$TOKEN_ISSUER_CONTAINER" \
        --network "$PODMAN_NETWORK" \
        --network-alias token-exchange-issuer \
        --network-alias "$TOKEN_ISSUER_SERVICE_HOST" \
        -p "127.0.0.1:${TOKEN_ISSUER_PORT}:8080" \
        -v "${TOKEN_ISSUER_JS_MOUNT}:/demo/token-issuer.js:ro,z" \
        -e "ACCESS_TOKEN_SECRET=${ACCESS_TOKEN_SECRET}" \
        -e "ACCESS_TOKEN_ISSUER=${TOKEN_ISSUER_BASE_URL}" \
        -e "SPIRE_JWKS_URI=http://spire-oidc:8080/keys" \
        -e "SPIRE_ISSUER=http://spire-oidc:8080" \
        -e "JWT_SVID_AUDIENCE=${TOKEN_ISSUER_BASE_URL}" \
        -e "SUPERVISOR_TRUST_DOMAIN_PREFIX=spiffe://${TRUST_DOMAIN}/openshell/sandbox/" \
        -e "GATEWAY_TRUST_DOMAIN_PREFIX=spiffe://${TRUST_DOMAIN}/openshell/gateway/" \
        -e "DEMO_USER_SUBJECT=demo-user" \
        "$NODE_IMAGE" \
        node /demo/token-issuer.js

    run podman run -d \
        --name "$ALPHA_CONTAINER" \
        --network "$PODMAN_NETWORK" \
        --network-alias alpha-exchange \
        --network-alias alpha-exchange.default.svc.cluster.local \
        -v "${PROTECTED_SERVICE_JS_MOUNT}:/demo/protected-service.js:ro,z" \
        -e SERVICE_NAME=alpha \
        -e EXPECTED_AUDIENCE=alpha \
        -e EXPECTED_SCOPE=alpha \
        -e "ACCESS_TOKEN_SECRET=${ACCESS_TOKEN_SECRET}" \
        -e "ACCESS_TOKEN_ISSUER=${TOKEN_ISSUER_BASE_URL}" \
        "$NODE_IMAGE" \
        node /demo/protected-service.js

    run podman run -d \
        --name "$BETA_CONTAINER" \
        --network "$PODMAN_NETWORK" \
        --network-alias beta-exchange \
        --network-alias beta-exchange.default.svc.cluster.local \
        -v "${PROTECTED_SERVICE_JS_MOUNT}:/demo/protected-service.js:ro,z" \
        -e SERVICE_NAME=beta \
        -e EXPECTED_AUDIENCE=beta \
        -e EXPECTED_SCOPE=beta \
        -e "ACCESS_TOKEN_SECRET=${ACCESS_TOKEN_SECRET}" \
        -e "ACCESS_TOKEN_ISSUER=${TOKEN_ISSUER_BASE_URL}" \
        "$NODE_IMAGE" \
        node /demo/protected-service.js

    wait_for_port "$TOKEN_ISSUER_PORT" "token issuer"
}

render_provider_profile() {
    sed "s|__TOKEN_ISSUER_BASE_URL__|${TOKEN_ISSUER_BASE_URL}|g" \
        "$PROFILE_TEMPLATE" >"$RENDERED_PROFILE"
}

sandbox_id() {
    local output
    output="$("${OS[@]}" sandbox get "$SANDBOX_NAME")"
    awk '/Id:/ && !found { print $2; found=1 }' <<<"$output"
}

register_gateway_entry() {
    if [[ "${REGISTER_GATEWAY_ENTRY:-1}" != "1" ]]; then
        return
    fi
    if [[ "$START_GATEWAY" == "1" && -z "${GATEWAY_SELECTORS:-}" ]]; then
        GATEWAY_SELECTORS="docker:label:openshell.spiffe-demo:gateway"
    fi
    TRUST_DOMAIN="$TRUST_DOMAIN" \
        GATEWAY_SELECTORS="${GATEWAY_SELECTORS:-}" \
        SPIRE_AGENT_PARENT_ID="$SPIRE_AGENT_PARENT_ID" \
        SPIRE_SERVER_CONTAINER="$SPIRE_SERVER_CONTAINER" \
        bash "${SCRIPT_DIR}/spire/register-gateway.sh"
}

register_sandbox_entry() {
    local id="$1"
    TRUST_DOMAIN="$TRUST_DOMAIN" \
        SPIRE_AGENT_PARENT_ID="$SPIRE_AGENT_PARENT_ID" \
        SPIRE_SERVER_CONTAINER="$SPIRE_SERVER_CONTAINER" \
        bash "${SCRIPT_DIR}/spire/register-sandbox.sh" "$id"
}

sandbox_curl_until() {
    local label="$1"
    local url="$2"
    local expected="$3"
    local output=""

    for attempt in $(seq 1 18); do
        printf "\n$ openshell sandbox exec %s curl (attempt %s)\n" "$label" "$attempt"
        if output=$("${OS[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- curl -sS --max-time 10 "$url" 2>&1); then
            printf "%s\n" "$output"
            if [[ "$output" == *"$expected"* ]]; then
                SANDBOX_CURL_OUTPUT="$output"
                return 0
            fi
        else
            printf "%s\n" "$output"
        fi
        sleep 2
    done

    printf "timed out waiting for %s to return expected output\n" "$label" >&2
    printf "last output:\n%s\n" "$output" >&2
    exit 1
}

require_cmd podman
require_cmd openssl
require_cmd openshell
require_cmd curl
require_cmd python3
require_cmd nc
require_cmd awk
require_cmd sed

require_uint PODMAN_STOP_TIMEOUT_SECS "$PODMAN_STOP_TIMEOUT_SECS"
prepare_demo_mounts
ensure_network

ensure_podman_socket
if [[ "$START_SPIRE" == "1" ]]; then
    start_spire "$PODMAN_SOCKET"
elif [[ -z "$SPIRE_AGENT_SOCKET_HOST_PATH" ]]; then
    printf "START_SPIRE=0 requires SPIRE_AGENT_SOCKET_HOST_PATH\n" >&2
    exit 1
fi

if [[ "$START_GATEWAY" == "1" ]]; then
    start_gateway "$PODMAN_SOCKET"
fi

if [[ -z "${TOKEN_ISSUER_BASE_URL:-}" ]]; then
    TOKEN_ISSUER_BASE_URL="http://${TOKEN_ISSUER_SERVICE_HOST}:8080"
fi

printf "\nUsing OpenShell gateway '%s' at %s\n" "$GATEWAY_NAME" "$GATEWAY_ENDPOINT"
printf "Using Podman network '%s'\n" "$PODMAN_NETWORK"
printf "Using token issuer base URL '%s'\n" "$TOKEN_ISSUER_BASE_URL"
printf "SPIRE agent Workload API socket for gateway and Podman driver: %s\n" "$SPIRE_AGENT_SOCKET_HOST_PATH"
if [[ "$START_GATEWAY" == "1" ]]; then
    printf "Managed gateway container: %s\n" "$GATEWAY_CONTAINER"
    printf "Managed gateway image: %s\n" "$GATEWAY_IMAGE"
    if [[ -n "$SANDBOX_IMAGE" ]]; then
        printf "Managed sandbox image: %s\n" "$SANDBOX_IMAGE"
    fi
    if [[ -n "$SUPERVISOR_IMAGE" ]]; then
        printf "Managed supervisor image: %s\n" "$SUPERVISOR_IMAGE"
    fi
    printf "Managed sandbox image pull policy: %s\n\n" "$SANDBOX_IMAGE_PULL_POLICY"
    printf "Managed Podman stop timeout: %s seconds\n\n" "$PODMAN_STOP_TIMEOUT_SECS"
else
    printf "\nThe gateway must already be running with:\n"
    printf "  OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET=%s\n" "$SPIRE_AGENT_SOCKET_HOST_PATH"
    printf "  [openshell.drivers.podman].provider_spiffe_workload_api_socket=%s\n" "$SPIRE_AGENT_SOCKET_HOST_PATH"
    printf "  [openshell.drivers.podman].network_name=%s\n\n" "$PODMAN_NETWORK"
    printf "The gateway process must be able to resolve and reach %s.\n" "$TOKEN_ISSUER_SERVICE_HOST"
    printf "For a host-running gateway, add local DNS/hosts routing to the published issuer port %s if needed.\n\n" "$TOKEN_ISSUER_PORT"
fi

register_gateway_entry
start_demo_services
render_provider_profile

SUBJECT_TOKEN="$(curl -fsS "http://127.0.0.1:${TOKEN_ISSUER_PORT}/demo-subject-token" | subject_token_from_json)"

"${OS[@]}" sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
"${OS[@]}" provider delete "$PROVIDER_NAME" >/dev/null 2>&1 || true
"${OS[@]}" provider profile delete "$PROFILE_ID" >/dev/null 2>&1 || true

run "${OS[@]}" provider profile lint -f "$RENDERED_PROFILE"
run "${OS[@]}" provider profile import -f "$RENDERED_PROFILE"
run "${OS[@]}" provider create --name "$PROVIDER_NAME" --type "$PROFILE_ID" --credential "subject_token=${SUBJECT_TOKEN}"
run "${OS[@]}" sandbox create --name "$SANDBOX_NAME" --provider "$PROVIDER_NAME" --keep --no-tty -- echo "sandbox ready"

SANDBOX_ID="$(sandbox_id)"
if [[ -z "$SANDBOX_ID" ]]; then
    printf "could not determine sandbox ID from openshell sandbox get\n" >&2
    exit 1
fi
printf "\nSandbox ID: %s\n" "$SANDBOX_ID"

register_sandbox_entry "$SANDBOX_ID"

sandbox_curl_until "alpha" "http://alpha-exchange:8080/" "alpha called with path /:"
ALPHA_OUTPUT="$SANDBOX_CURL_OUTPUT"
assert_contains "$ALPHA_OUTPUT" "sub: demo-user"
assert_contains "$ALPHA_OUTPUT" "aud: alpha, account"
assert_contains "$ALPHA_OUTPUT" "scope: alpha profile email"
assert_contains "$ALPHA_OUTPUT" "azp: spiffe://${TRUST_DOMAIN}/openshell/sandbox/"
assert_contains "$ALPHA_OUTPUT" "client_id: spiffe://${TRUST_DOMAIN}/openshell/sandbox/"

sandbox_curl_until "beta" "http://beta-exchange:8080/" "beta called with path /:"
BETA_OUTPUT="$SANDBOX_CURL_OUTPUT"
assert_contains "$BETA_OUTPUT" "sub: demo-user"
assert_contains "$BETA_OUTPUT" "aud: beta, account"
assert_contains "$BETA_OUTPUT" "scope: beta profile email"
assert_contains "$BETA_OUTPUT" "azp: spiffe://${TRUST_DOMAIN}/openshell/sandbox/"
assert_contains "$BETA_OUTPUT" "client_id: spiffe://${TRUST_DOMAIN}/openshell/sandbox/"

printf "\nPodman SPIFFE token exchange demo succeeded.\n"
