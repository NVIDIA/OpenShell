#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone openshell-gateway using the detected compute driver.
#
# Auto-detection follows the gateway's runtime order:
#   Kubernetes -> Podman -> Docker
#
# VM/MicroVM is intentionally explicit-only because it requires runtime setup.
# Use either:
#   OPENSHELL_DRIVERS=vm mise run gateway
#   mise run gateway:vm

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"

usage() {
  cat <<'EOF'
Usage: mise run gateway [-- --driver DRIVER]

Start a local OpenShell gateway with the detected compute driver.

Driver detection order:
  kubernetes -> podman -> docker

Options:
  --driver DRIVER  Override detection. Accepted values:
                   kubernetes, podman, docker, vm, microvm
  -h, --help       Show this help.

Environment:
  OPENSHELL_DRIVERS       Driver override used by openshell-gateway.
  OPENSHELL_GATEWAY_NAME  Gateway name for delegated or Kubernetes runs.
  OPENSHELL_BIND_ADDRESS  Gateway listener address. Defaults to 127.0.0.1,
                          or ::1 for Podman Machine on macOS.
  OPENSHELL_SERVER_PORT   Gateway port. Defaults to 8080 for Kubernetes,
                          18080 for Podman/Docker, and 18081 for VM.
Docker, Podman, and VM runs delegate to their gateway:<driver> setup scripts.
EOF
}

normalize_driver() {
  local driver
  driver="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"

  case "${driver}" in
    kubernetes|k8s) echo "kubernetes" ;;
    podman) echo "podman" ;;
    docker) echo "docker" ;;
    vm|microvm) echo "vm" ;;
    "")
      echo "ERROR: empty driver value" >&2
      exit 2
      ;;
    *)
      echo "ERROR: unsupported driver '$1' (expected kubernetes, podman, docker, vm, or microvm)" >&2
      exit 2
      ;;
  esac
}

command_available() {
  command -v "$1" >/dev/null 2>&1
}

require_mise() {
  if ! command_available mise; then
    echo "ERROR: mise is required to build local gateway artifacts" >&2
    exit 1
  fi
}

run_mise_task() {
  require_mise
  mise run "$@"
}

podman_available() {
  command_available podman && podman info >/dev/null 2>&1
}

docker_available() {
  command_available docker && docker info >/dev/null 2>&1
}

detect_driver() {
  if [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]]; then
    echo "kubernetes"
    return
  fi

  if podman_available; then
    echo "podman"
    return
  fi

  if docker_available; then
    echo "docker"
    return
  fi

  echo "ERROR: no compute driver detected." >&2
  echo "       Start Podman or Docker, run inside Kubernetes, or set OPENSHELL_DRIVERS." >&2
  exit 2
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

explicit_driver=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --driver)
      if [[ "$#" -lt 2 ]]; then
        echo "ERROR: --driver requires a value" >&2
        exit 2
      fi
      explicit_driver="$(normalize_driver "$2")"
      shift 2
      ;;
    --driver=*)
      explicit_driver="$(normalize_driver "${1#--driver=}")"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown gateway option '$1'" >&2
      echo >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "${explicit_driver}" && -n "${OPENSHELL_DRIVERS:-}" ]]; then
  echo "ERROR: use either --driver or OPENSHELL_DRIVERS, not both" >&2
  exit 2
fi

if [[ -z "${explicit_driver}" && -n "${OPENSHELL_DRIVERS:-}" ]]; then
  if [[ "${OPENSHELL_DRIVERS}" == *,* ]]; then
    echo "ERROR: mise run gateway supports one driver; got OPENSHELL_DRIVERS=${OPENSHELL_DRIVERS}" >&2
    exit 2
  fi
  explicit_driver="$(normalize_driver "${OPENSHELL_DRIVERS}")"
fi

DRIVER="${explicit_driver:-$(detect_driver)}"

case "${DRIVER}" in
  docker)
    export OPENSHELL_DOCKER_GATEWAY_NAME="${OPENSHELL_DOCKER_GATEWAY_NAME:-${OPENSHELL_GATEWAY_NAME:-docker-dev}}"
    exec bash "${ROOT}/tasks/scripts/gateway-docker.sh"
    ;;
  podman)
    export OPENSHELL_PODMAN_GATEWAY_NAME="${OPENSHELL_PODMAN_GATEWAY_NAME:-${OPENSHELL_GATEWAY_NAME:-podman-dev}}"
    exec bash "${ROOT}/tasks/scripts/gateway-podman.sh"
    ;;
  vm)
    export OPENSHELL_VM_GATEWAY_NAME="${OPENSHELL_VM_GATEWAY_NAME:-${OPENSHELL_GATEWAY_NAME:-vm-dev}}"
    exec bash "${ROOT}/tasks/scripts/gateway-vm.sh"
    ;;
esac

PORT="${OPENSHELL_SERVER_PORT:-8080}"
GATEWAY_NAME="${OPENSHELL_GATEWAY_NAME:-${DRIVER}-dev}"
STATE_DIR="${OPENSHELL_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-${DRIVER}}"
SANDBOX_NAMESPACE="${OPENSHELL_SANDBOX_NAMESPACE:-${DRIVER}-dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
SANDBOX_IMAGE_PULL_POLICY="${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-IfNotPresent}"
GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-}"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
PRIMARY_BIND_IP="${OPENSHELL_BIND_ADDRESS:-127.0.0.1}"

if [[ ! "${GATEWAY_NAME}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: OPENSHELL_GATEWAY_NAME must contain only letters, numbers, dots, underscores, or dashes" >&2
  exit 2
fi

if port_is_in_use "${PORT}"; then
  echo "ERROR: port ${PORT} is already in use; free it or set OPENSHELL_SERVER_PORT" >&2
  exit 2
fi

echo "Building openshell-gateway..."
run_mise_task build:gateway

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
compute_drivers = ["${DRIVER}"]
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
EOF

cat >>"${CONFIG_PATH}" <<EOF

[openshell.drivers.kubernetes]
namespace = "${SANDBOX_NAMESPACE}"
image_pull_policy = "${SANDBOX_IMAGE_PULL_POLICY}"
EOF
if [[ -n "${GRPC_ENDPOINT}" ]]; then
  printf 'grpc_endpoint = "%s"\n' "${GRPC_ENDPOINT}" >>"${CONFIG_PATH}"
fi

GATEWAY_ENDPOINT="http://127.0.0.1:${PORT}"
register_gateway_metadata "${GATEWAY_NAME}" "${GATEWAY_ENDPOINT}" "${PORT}"

echo "Starting standalone ${DRIVER} gateway..."
echo "  gateway:   ${GATEWAY_NAME}"
echo "  endpoint:  ${GATEWAY_ENDPOINT}"
echo "  bind:      ${PRIMARY_BIND_IP}:${PORT}"
echo "  namespace: ${SANDBOX_NAMESPACE}"
echo "  state dir: ${STATE_DIR}"
echo
echo "Active gateway set to '${GATEWAY_NAME}'. The CLI now targets this gateway by default."
echo

exec "${GATEWAY_BIN}" \
  --config "${CONFIG_PATH}" \
  --bind-address "${PRIMARY_BIND_IP}" \
  --port "${PORT}" \
  --log-level "${LOG_LEVEL}" \
  --drivers "${DRIVER}" \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
