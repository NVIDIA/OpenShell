#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone ryno-gateway backed by the Podman compute driver for
# local manual testing.
#
# Defaults:
# - Plaintext HTTP on 127.0.0.1:18080 (IPv6 loopback on macOS Podman Machine)
# - Gateway installation and CLI registration name "podman-dev"
# - Persistent state under .cache/gateway-podman
# - Supervisor sideload image ryno/supervisor:dev, refreshed on launch
#
# Common overrides:
#   RYNO_SERVER_PORT=19080 mise run gateway:podman
#   RYNO_PODMAN_GATEWAY_NAME=my-podman-gateway mise run gateway:podman
#   RYNO_SANDBOX_NAMESPACE=my-ns mise run gateway:podman
#   RYNO_SANDBOX_IMAGE=ghcr.io/... mise run gateway:podman
#   RYNO_SUPERVISOR_IMAGE=ghcr.io/... mise run gateway:podman
#   RYNO_SANDBOX_RUNTIME_IMAGE=ghcr.io/... mise run gateway:podman

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tasks/scripts/gateway-toml.sh
source "${ROOT}/tasks/scripts/gateway-toml.sh"
# shellcheck source=tasks/scripts/gateway-pull-policy.sh
source "${ROOT}/tasks/scripts/gateway-pull-policy.sh"
PORT="${RYNO_SERVER_PORT:-18080}"
GATEWAY_NAME="${RYNO_PODMAN_GATEWAY_NAME:-podman-dev}"
STATE_DIR="${RYNO_PODMAN_GATEWAY_STATE_DIR:-${RYNO_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-podman}}"
SANDBOX_NAMESPACE="${RYNO_SANDBOX_NAMESPACE:-podman-dev}"
SANDBOX_IMAGE="${RYNO_SANDBOX_IMAGE:-nvcr.io/nvidia/base/ubuntu:24.04}"
SANDBOX_IMAGE_PULL_POLICY="$(normalize_image_pull_policy "${RYNO_SANDBOX_IMAGE_PULL_POLICY:-if_not_present}")"
GRPC_ENDPOINT="${RYNO_GRPC_ENDPOINT:-}"
LOG_LEVEL="${RYNO_LOG_LEVEL:-info}"
PRIMARY_BIND_IP="${RYNO_BIND_ADDRESS:-127.0.0.1}"
CLI_ENDPOINT_HOST="127.0.0.1"
GATEWAY_BIN="${ROOT}/target/debug/ryno-gateway"

command_available() {
  command -v "$1" >/dev/null 2>&1
}

require_mise() {
  if ! command_available mise; then
    echo "ERROR: mise is required to build local gateway artifacts" >&2
    exit 1
  fi
}

podman_available() {
  command_available podman && podman info >/dev/null 2>&1
}

require_podman_service() {
  if ! command_available podman; then
    echo "ERROR: podman is not installed or not in PATH" >&2
    exit 1
  fi

  if ! podman_available; then
    echo "ERROR: podman service is not reachable. Start it with:" >&2
    if [[ "$(uname -s)" == "Darwin" ]]; then
      echo "  podman machine start" >&2
    else
      echo "  systemctl --user start podman.socket" >&2
    fi
    exit 1
  fi
}

ensure_podman_runtime_image() {
  local image=$1
  local configured_image=$2
  local build_target=$3
  local role=$4

  if [[ -n "${configured_image}" ]]; then
    if podman image exists "${image}" >/dev/null 2>&1; then
      return
    fi
    echo "ERROR: ${role} image '${image}' not found locally." >&2
    echo "       Build it with Podman or unset its image override to build the local :dev image." >&2
    exit 1
  fi

  # Always run the build pipeline for the default development image so source
  # changes cannot leave the fixed :dev tag pointing at a stale runtime.
  # Cargo and BuildKit caches keep unchanged rebuilds incremental.
  echo "Refreshing Podman ${role} image (${image})..."
  require_mise
  CONTAINER_ENGINE=podman IMAGE_TAG=dev mise run "build:docker:${build_target}"

  if ! podman image exists "${image}" >/dev/null 2>&1; then
    echo "ERROR: expected ${role} image '${image}' after build" >&2
    exit 1
  fi
}

port_is_in_use() {
  local port=$1
  if command_available lsof; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  if command_available nc; then
    nc -z 127.0.0.1 "${port}" >/dev/null 2>&1
    return $?
  fi
  (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1
}

append_local_otlp_config_if_available() {
  local config_path=$1
  if ! port_is_in_use 4317; then
    echo "OTLP collector not detected on 127.0.0.1:4317; trace export disabled."
    return
  fi

  cat >>"${config_path}" <<'EOF'

[ryno.gateway.otlp]
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
  gateway_dir="${config_home}/ryno/gateways/${name}"

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
  printf '%s' "${name}" >"${config_home}/ryno/active_gateway"
}

if [[ ! "${GATEWAY_NAME}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: RYNO_PODMAN_GATEWAY_NAME must contain only letters, numbers, dots, underscores, or dashes" >&2
  exit 2
fi

require_podman_service

if port_is_in_use "${PORT}"; then
  echo "ERROR: port ${PORT} is already in use; free it or set RYNO_SERVER_PORT" >&2
  exit 2
fi

SUPERVISOR_IMAGE="${RYNO_SUPERVISOR_IMAGE:-ryno/supervisor:dev}"
SANDBOX_RUNTIME_IMAGE="${RYNO_SANDBOX_RUNTIME_IMAGE:-ryno/sandbox:dev}"
ensure_podman_runtime_image \
  "${SUPERVISOR_IMAGE}" \
  "${RYNO_SUPERVISOR_IMAGE:-}" \
  supervisor \
  supervisor
ensure_podman_runtime_image \
  "${SANDBOX_RUNTIME_IMAGE}" \
  "${RYNO_SANDBOX_RUNTIME_IMAGE:-}" \
  sandbox \
  "sandbox runtime"
export RYNO_SUPERVISOR_IMAGE="${SUPERVISOR_IMAGE}"

echo "Building ryno-gateway..."
require_mise
mise run build:gateway

if [[ ! -x "${GATEWAY_BIN}" ]]; then
  echo "ERROR: expected gateway binary at ${GATEWAY_BIN}" >&2
  exit 1
fi

TLS_DIR="${STATE_DIR}/tls"
echo "Generating local gateway credentials..."
"${GATEWAY_BIN}" generate-certs \
  --output-dir "${TLS_DIR}" \
  --server-san "127.0.0.1" \
  --server-san "localhost" \
  --server-san "host.ryno.internal"

mkdir -p "${STATE_DIR}"
CONFIG_PATH="${STATE_DIR}/gateway.toml"
# The config may reference credential-bearing material (e.g. proxy_auth_file);
# keep it owner-only regardless of the ambient umask.
install -m 600 /dev/null "${CONFIG_PATH}"
cat >"${CONFIG_PATH}" <<EOF
[ryno]
version = 2

[ryno.gateway]
name = "${GATEWAY_NAME}"
compute_driver = "podman"
disable_tls = true

[ryno.gateway.auth]
allow_unauthenticated_users = true

[ryno.gateway.gateway_jwt]
signing_key_path = "${TLS_DIR}/jwt/signing.pem"
public_key_path = "${TLS_DIR}/jwt/public.pem"
kid_path = "${TLS_DIR}/jwt/kid"
gateway_id = "${GATEWAY_NAME}"

[ryno.drivers.podman]
default_image = "${SANDBOX_IMAGE}"
supervisor_image = "${SUPERVISOR_IMAGE}"
sandbox_runtime_image = "${SANDBOX_RUNTIME_IMAGE}"
image_pull_policy = "${SANDBOX_IMAGE_PULL_POLICY}"
# Local development requires supervisor mount setup that Podman's runtime
# profile may deny. Production configs preserve Podman's default when omitted.
app_armor_profile = "Unconfined"
health_check_interval_secs = 10
EOF

if [[ -n "${GRPC_ENDPOINT}" ]]; then
  printf 'grpc_endpoint = "%s"\n' "${GRPC_ENDPOINT}" >>"${CONFIG_PATH}"
fi
# ${VAR+x} distinguishes unset from set-but-empty: an unset variable writes
# nothing, but an explicitly empty one is written through so the gateway's
# fail-closed proxy validation rejects it instead of silently dropping it.
if [[ -n "${RYNO_SANDBOX_HTTPS_PROXY+x}" ]]; then
  printf 'https_proxy = "%s"\n' "$(toml_escape "${RYNO_SANDBOX_HTTPS_PROXY}")" >>"${CONFIG_PATH}"
fi
if [[ -n "${RYNO_SANDBOX_NO_PROXY+x}" ]]; then
  printf 'no_proxy = "%s"\n' "$(toml_escape "${RYNO_SANDBOX_NO_PROXY}")" >>"${CONFIG_PATH}"
fi
if [[ -n "${RYNO_SANDBOX_PROXY_AUTH_FILE+x}" ]]; then
  printf 'proxy_auth_file = "%s"\n' "$(toml_escape "${RYNO_SANDBOX_PROXY_AUTH_FILE}")" >>"${CONFIG_PATH}"
fi
if [[ -n "${RYNO_SANDBOX_PROXY_AUTH_ALLOW_INSECURE+x}" ]]; then
  case "${RYNO_SANDBOX_PROXY_AUTH_ALLOW_INSECURE}" in
    true|false)
      printf 'proxy_auth_allow_insecure = %s\n' "${RYNO_SANDBOX_PROXY_AUTH_ALLOW_INSECURE}" >>"${CONFIG_PATH}"
      ;;
    *)
      # Write invalid booleans as strings so config parsing rejects them.
      printf 'proxy_auth_allow_insecure = "%s"\n' "$(toml_escape "${RYNO_SANDBOX_PROXY_AUTH_ALLOW_INSECURE}")" >>"${CONFIG_PATH}"
      ;;
  esac
fi
if [[ -n "${RYNO_SANDBOX_PROXY_CONNECT_BY_HOSTNAME+x}" ]]; then
  case "${RYNO_SANDBOX_PROXY_CONNECT_BY_HOSTNAME}" in
    true|false)
      printf 'proxy_connect_by_hostname = %s\n' "${RYNO_SANDBOX_PROXY_CONNECT_BY_HOSTNAME}" >>"${CONFIG_PATH}"
      ;;
    *)
      # Write invalid booleans as strings so config parsing rejects them.
      printf 'proxy_connect_by_hostname = "%s"\n' "$(toml_escape "${RYNO_SANDBOX_PROXY_CONNECT_BY_HOSTNAME}")" >>"${CONFIG_PATH}"
      ;;
  esac
fi
if [[ -n "${RYNO_SANDBOX_PROXY_CA_BUNDLE+x}" ]]; then
  printf 'proxy_ca_bundle = "%s"\n' "$(toml_escape "${RYNO_SANDBOX_PROXY_CA_BUNDLE}")" >>"${CONFIG_PATH}"
fi

append_local_otlp_config_if_available "${CONFIG_PATH}"

GATEWAY_ENDPOINT="http://${CLI_ENDPOINT_HOST}:${PORT}"
register_gateway_metadata "${GATEWAY_NAME}" "${GATEWAY_ENDPOINT}" "${PORT}"

echo "Starting standalone Podman gateway..."
echo "  gateway:   ${GATEWAY_NAME}"
echo "  endpoint:  ${GATEWAY_ENDPOINT}"
echo "  bind:      ${PRIMARY_BIND_IP}:${PORT}"
echo "  namespace: ${SANDBOX_NAMESPACE}"
echo "  state dir: ${STATE_DIR}"
echo "  supervisor image: ${SUPERVISOR_IMAGE}"
echo
echo "Active gateway set to '${GATEWAY_NAME}'. The CLI now targets this gateway by default."
echo

exec "${GATEWAY_BIN}" \
  --config "${CONFIG_PATH}" \
  --bind-address "${PRIMARY_BIND_IP}" \
  --port "${PORT}" \
  --log-level "${LOG_LEVEL}" \
  --compute-driver podman \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
