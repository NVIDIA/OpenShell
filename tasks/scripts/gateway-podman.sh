#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone openshell-gateway backed by the Podman compute driver for
# local manual testing.
#
# Defaults:
# - Plaintext HTTP on 127.0.0.1:18080 (IPv6 loopback on macOS Podman Machine)
# - Gateway installation and CLI registration name "podman-dev"
# - Persistent state under .cache/gateway-podman
# - Supervisor sideload image openshell/supervisor:dev, refreshed on launch
#
# Common overrides:
#   OPENSHELL_SERVER_PORT=19080 mise run gateway:podman
#   OPENSHELL_PODMAN_GATEWAY_NAME=my-podman-gateway mise run gateway:podman
#   OPENSHELL_SANDBOX_NAMESPACE=my-ns mise run gateway:podman
#   OPENSHELL_SANDBOX_IMAGE=ghcr.io/... mise run gateway:podman

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${OPENSHELL_SERVER_PORT:-18080}"
GATEWAY_NAME="${OPENSHELL_PODMAN_GATEWAY_NAME:-podman-dev}"
STATE_DIR="${OPENSHELL_PODMAN_GATEWAY_STATE_DIR:-${OPENSHELL_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-podman}}"
SANDBOX_NAMESPACE="${OPENSHELL_SANDBOX_NAMESPACE:-podman-dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
SANDBOX_IMAGE_PULL_POLICY="${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-IfNotPresent}"
GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-}"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
PRIMARY_BIND_IP="${OPENSHELL_BIND_ADDRESS:-127.0.0.1}"
CLI_ENDPOINT_HOST="127.0.0.1"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"

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

ensure_podman_supervisor_image() {
  local supervisor_image=$1

  if [[ -n "${OPENSHELL_SUPERVISOR_IMAGE:-}" ]]; then
    if podman image exists "${supervisor_image}" >/dev/null 2>&1; then
      return
    fi
    echo "ERROR: supervisor image '${supervisor_image}' not found locally." >&2
    echo "       Build it with Podman or unset OPENSHELL_SUPERVISOR_IMAGE to build openshell/supervisor:dev." >&2
    exit 1
  fi

  # Always run the build pipeline for the default development image so source
  # changes cannot leave the fixed :dev tag pointing at a stale supervisor.
  # Cargo and BuildKit caches keep unchanged rebuilds incremental.
  echo "Refreshing Podman supervisor sideload image (${supervisor_image})..."
  require_mise
  CONTAINER_ENGINE=podman IMAGE_TAG=dev mise run build:docker:supervisor

  if ! podman image exists "${supervisor_image}" >/dev/null 2>&1; then
    echo "ERROR: expected supervisor image '${supervisor_image}' after build" >&2
    exit 1
  fi
}

podman_pull_policy() {
  case "$1" in
    Always|always) echo "always" ;;
    IfNotPresent|ifnotpresent|missing|"") echo "missing" ;;
    Never|never) echo "never" ;;
    Newer|newer) echo "newer" ;;
    *)
      echo "ERROR: unsupported Podman image pull policy '$1'" >&2
      exit 2
      ;;
  esac
}

# Escape a value for embedding in a double-quoted TOML basic string, so
# quotes, backslashes, or control characters in an environment value cannot
# corrupt gateway.toml or inject extra configuration keys.
toml_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "${s}"
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
  printf '%s' "${name}" >"${config_home}/openshell/active_gateway"
}

if [[ -z "${OPENSHELL_BIND_ADDRESS:-}" && "$(uname -s)" == "Darwin" ]]; then
  # Podman Machine reserves IPv4 loopback for its callback-only listener.
  # Keep the primary listener distinct while using a hostname that resolves
  # to IPv6 loopback for local CLI connections. An explicit bind address
  # overrides this platform default.
  PRIMARY_BIND_IP="::1"
  CLI_ENDPOINT_HOST="localhost"
fi

if [[ ! "${GATEWAY_NAME}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: OPENSHELL_PODMAN_GATEWAY_NAME must contain only letters, numbers, dots, underscores, or dashes" >&2
  exit 2
fi

require_podman_service

if port_is_in_use "${PORT}"; then
  echo "ERROR: port ${PORT} is already in use; free it or set OPENSHELL_SERVER_PORT" >&2
  exit 2
fi

SUPERVISOR_IMAGE="${OPENSHELL_SUPERVISOR_IMAGE:-openshell/supervisor:dev}"
ensure_podman_supervisor_image "${SUPERVISOR_IMAGE}"
export OPENSHELL_SUPERVISOR_IMAGE="${SUPERVISOR_IMAGE}"

echo "Building openshell-gateway..."
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
  --server-san "host.openshell.internal"

mkdir -p "${STATE_DIR}"
CONFIG_PATH="${STATE_DIR}/gateway.toml"
# The config may reference credential-bearing material (e.g. proxy_auth_file);
# keep it owner-only regardless of the ambient umask.
install -m 600 /dev/null "${CONFIG_PATH}"
cat >"${CONFIG_PATH}" <<EOF
[openshell]
version = 1

[openshell.gateway]
name = "${GATEWAY_NAME}"
compute_drivers = ["podman"]
default_image = "${SANDBOX_IMAGE}"
disable_tls = true

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${TLS_DIR}/jwt/signing.pem"
public_key_path = "${TLS_DIR}/jwt/public.pem"
kid_path = "${TLS_DIR}/jwt/kid"
gateway_id = "${GATEWAY_NAME}"
ttl_secs = 3600

[openshell.drivers.podman]
supervisor_image = "${SUPERVISOR_IMAGE}"
image_pull_policy = "$(podman_pull_policy "${SANDBOX_IMAGE_PULL_POLICY}")"
EOF

if [[ -n "${GRPC_ENDPOINT}" ]]; then
  printf 'grpc_endpoint = "%s"\n' "${GRPC_ENDPOINT}" >>"${CONFIG_PATH}"
fi
# ${VAR+x} distinguishes unset from set-but-empty: an unset variable writes
# nothing, but an explicitly empty one is written through so the gateway's
# fail-closed proxy validation rejects it instead of silently dropping it.
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
  case "${OPENSHELL_SANDBOX_PROXY_AUTH_ALLOW_INSECURE}" in
    true|false)
      printf 'proxy_auth_allow_insecure = %s\n' "${OPENSHELL_SANDBOX_PROXY_AUTH_ALLOW_INSECURE}" >>"${CONFIG_PATH}"
      ;;
    *)
      # Write invalid booleans as strings so config parsing rejects them.
      printf 'proxy_auth_allow_insecure = "%s"\n' "$(toml_escape "${OPENSHELL_SANDBOX_PROXY_AUTH_ALLOW_INSECURE}")" >>"${CONFIG_PATH}"
      ;;
  esac
fi
if [[ -n "${OPENSHELL_SANDBOX_PROXY_CONNECT_BY_HOSTNAME+x}" ]]; then
  case "${OPENSHELL_SANDBOX_PROXY_CONNECT_BY_HOSTNAME}" in
    true|false)
      printf 'proxy_connect_by_hostname = %s\n' "${OPENSHELL_SANDBOX_PROXY_CONNECT_BY_HOSTNAME}" >>"${CONFIG_PATH}"
      ;;
    *)
      # Write invalid booleans as strings so config parsing rejects them.
      printf 'proxy_connect_by_hostname = "%s"\n' "$(toml_escape "${OPENSHELL_SANDBOX_PROXY_CONNECT_BY_HOSTNAME}")" >>"${CONFIG_PATH}"
      ;;
  esac
fi
if [[ -n "${OPENSHELL_SANDBOX_PROXY_CA_BUNDLE+x}" ]]; then
  printf 'proxy_ca_bundle = "%s"\n' "$(toml_escape "${OPENSHELL_SANDBOX_PROXY_CA_BUNDLE}")" >>"${CONFIG_PATH}"
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
  --drivers podman \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
