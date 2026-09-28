#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone openshell-gateway backed by the Docker compute driver for
# local manual testing.
#
# Defaults:
# - Plaintext HTTP on 127.0.0.1:18080
# - Dedicated sandbox namespace "docker-dev"
# - Persistent state under .cache/gateway-docker
#
# Common overrides:
#   OPENSHELL_SERVER_PORT=19080 mise run gateway:docker
#   OPENSHELL_DOCKER_GATEWAY_NAME=my-docker-gateway mise run gateway:docker
#   OPENSHELL_SANDBOX_NAMESPACE=my-ns mise run gateway:docker
#   OPENSHELL_SANDBOX_IMAGE=ghcr.io/... mise run gateway:docker
#   OPENSHELL_SUPERVISOR_IMAGE=ghcr.io/... mise run gateway:docker
#   OPENSHELL_SANDBOX_RUNTIME_IMAGE=ghcr.io/... mise run gateway:docker
#
# After the gateway is running, point the CLI at it with either:
#   openshell --gateway docker-dev <command>
#   openshell gateway use docker-dev   # then plain `openshell <command>`

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tasks/scripts/gateway-toml.sh
source "${ROOT}/tasks/scripts/gateway-toml.sh"
# shellcheck source=tasks/scripts/gateway-pull-policy.sh
source "${ROOT}/tasks/scripts/gateway-pull-policy.sh"
PORT="${OPENSHELL_SERVER_PORT:-18080}"
GATEWAY_NAME="${OPENSHELL_DOCKER_GATEWAY_NAME:-docker-dev}"
STATE_DIR="${OPENSHELL_DOCKER_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-docker}"
SANDBOX_NAMESPACE="${OPENSHELL_SANDBOX_NAMESPACE:-docker-dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-nvcr.io/nvidia/base/ubuntu:24.04}"
SUPERVISOR_IMAGE="${OPENSHELL_SUPERVISOR_IMAGE:-openshell/supervisor:dev}"
SANDBOX_RUNTIME_IMAGE="${OPENSHELL_SANDBOX_RUNTIME_IMAGE:-openshell/sandbox:dev}"
SANDBOX_IMAGE_PULL_POLICY="$(normalize_image_pull_policy "${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-if_not_present}")"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"

port_is_in_use() {
  local port=$1
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  if command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "${port}" >/dev/null 2>&1
    return $?
  fi
  (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1
}

ensure_docker_runtime_image() {
  local image=$1
  local configured_image=$2
  local build_target=$3
  local role=$4

  if [[ -n "${configured_image}" ]]; then
    if docker image inspect "${image}" >/dev/null 2>&1; then
      return
    fi
    echo "ERROR: ${role} image '${image}' not found locally." >&2
    echo "       Build it with Docker or unset its image override to build the local :dev image." >&2
    exit 1
  fi

  # Always run the build pipeline for default development images so source
  # changes cannot leave a fixed :dev tag pointing at stale runtime code.
  echo "Refreshing Docker ${role} image (${image})..."
  CONTAINER_ENGINE=docker IMAGE_TAG=dev mise run "build:docker:${build_target}"

  if ! docker image inspect "${image}" >/dev/null 2>&1; then
    echo "ERROR: expected ${role} image '${image}' after build" >&2
    exit 1
  fi
}

append_local_otlp_config_if_available() {
  local config_path=$1
  if ! port_is_in_use 4317; then
    echo "OTLP collector not detected on 127.0.0.1:4317; trace export disabled."
    return
  fi

  cat >>"${config_path}" <<'EOF'

[openshell.gateway.otlp]
endpoint = "http://127.0.0.1:4317"
EOF
  echo "OTLP trace export enabled for http://127.0.0.1:4317."
}

register_gateway_metadata() {
  local name=$1
  local endpoint=$2
  local port=$3
  local config_home gateway_dir

  config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"
  gateway_dir="${config_home}/openshell/gateways/${name}"

  mkdir -p "${gateway_dir}"
  cat >"${gateway_dir}/metadata.json" <<EOF
{
  "name": "${name}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${port},
  "auth_mode": "plaintext"
}
EOF
}

if [[ ! "${GATEWAY_NAME}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: OPENSHELL_DOCKER_GATEWAY_NAME must contain only letters, numbers, dots, underscores, or dashes" >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker CLI is required" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon is not reachable" >&2
  exit 2
fi

if port_is_in_use "${PORT}"; then
  echo "ERROR: port ${PORT} is already in use; free it or set OPENSHELL_SERVER_PORT" >&2
  exit 2
fi

ensure_docker_runtime_image \
  "${SUPERVISOR_IMAGE}" \
  "${OPENSHELL_SUPERVISOR_IMAGE:-}" \
  supervisor \
  supervisor
ensure_docker_runtime_image \
  "${SANDBOX_RUNTIME_IMAGE}" \
  "${OPENSHELL_SANDBOX_RUNTIME_IMAGE:-}" \
  sandbox \
  "sandbox runtime"

GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-http://127.0.0.1:${PORT}}"

CARGO_BUILD_JOBS_ARG=()
if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
  CARGO_BUILD_JOBS_ARG=(-j "${CARGO_BUILD_JOBS}")
fi

echo "Building openshell-gateway..."
cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
  -p openshell-gateway --bin openshell-gateway

TLS_DIR="${STATE_DIR}/tls"
echo "Generating local gateway credentials..."
"${GATEWAY_BIN}" generate-certs \
  --output-dir "${TLS_DIR}" \
  --server-san "127.0.0.1" \
  --server-san "localhost" \
  --server-san "host.openshell.internal"

mkdir -p "${STATE_DIR}"
CONFIG_PATH="${STATE_DIR}/gateway.toml"
cat >"${CONFIG_PATH}" <<EOF
[openshell]
version = 2

[openshell.gateway]
name = "${GATEWAY_NAME}"
compute_driver = "docker"
disable_tls = true

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${TLS_DIR}/jwt/signing.pem"
public_key_path = "${TLS_DIR}/jwt/public.pem"
kid_path = "${TLS_DIR}/jwt/kid"
gateway_id = "${GATEWAY_NAME}"

[openshell.drivers.docker]
default_image = "${SANDBOX_IMAGE}"
supervisor_image = "${SUPERVISOR_IMAGE}"
sandbox_runtime_image = "${SANDBOX_RUNTIME_IMAGE}"
image_pull_policy = "${SANDBOX_IMAGE_PULL_POLICY}"
sandbox_label = "${SANDBOX_NAMESPACE}"
grpc_endpoint = "${GRPC_ENDPOINT}"
# Explicit supervisor-compatible default. Set RuntimeDefault or
# Localhost/<profile> only on a Docker host with AppArmor enabled.
app_armor_profile = "Unconfined"
EOF

# Keep the local task's proxy inputs aligned with [openshell.drivers.docker].
# Credentials stay in the referenced root-owned file; do not echo their value.
if [[ -n "${OPENSHELL_SANDBOX_HTTPS_PROXY+x}" ]]; then
  printf 'https_proxy = "%s"\n' "$(toml_escape "${OPENSHELL_SANDBOX_HTTPS_PROXY}")" >>"${CONFIG_PATH}"
fi
if [[ -n "${OPENSHELL_SANDBOX_NO_PROXY+x}" ]]; then
  printf 'no_proxy = "%s"\n' "$(toml_escape "${OPENSHELL_SANDBOX_NO_PROXY}")" >>"${CONFIG_PATH}"
fi
if [[ -n "${OPENSHELL_SANDBOX_PROXY_AUTH_FILE+x}" ]]; then
  printf 'proxy_auth_file = "%s"\n' "$(toml_escape "${OPENSHELL_SANDBOX_PROXY_AUTH_FILE}")" >>"${CONFIG_PATH}"
fi
if [[ -n "${OPENSHELL_SANDBOX_PROXY_AUTH_ALLOW_INSECURE+x}" ]]; then
  printf 'proxy_auth_allow_insecure = %s\n' "${OPENSHELL_SANDBOX_PROXY_AUTH_ALLOW_INSECURE}" >>"${CONFIG_PATH}"
fi
if [[ -n "${OPENSHELL_SANDBOX_PROXY_CONNECT_BY_HOSTNAME+x}" ]]; then
  printf 'proxy_connect_by_hostname = %s\n' "${OPENSHELL_SANDBOX_PROXY_CONNECT_BY_HOSTNAME}" >>"${CONFIG_PATH}"
fi
if [[ -n "${OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET+x}" ]]; then
  printf 'provider_spiffe_workload_api_socket = "%s"\n' "$(toml_escape "${OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET}")" >>"${CONFIG_PATH}"
fi

append_local_otlp_config_if_available "${CONFIG_PATH}"

GATEWAY_ENDPOINT="http://127.0.0.1:${PORT}"
register_gateway_metadata "${GATEWAY_NAME}" "${GATEWAY_ENDPOINT}" "${PORT}"

echo "Starting standalone Docker gateway..."
echo "  gateway:   ${GATEWAY_NAME}"
echo "  endpoint:  ${GATEWAY_ENDPOINT}"
echo "  namespace: ${SANDBOX_NAMESPACE}"
echo "  state dir: ${STATE_DIR}"
echo
echo "Point the CLI at this gateway with one of:"
echo "  openshell --gateway ${GATEWAY_NAME} status"
echo "  openshell gateway select ${GATEWAY_NAME}"
echo

exec "${GATEWAY_BIN}" \
  --config "${CONFIG_PATH}" \
  --port "${PORT}" \
  --log-level "${LOG_LEVEL}" \
  --compute-driver docker \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
