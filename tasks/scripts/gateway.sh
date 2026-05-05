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
  OPENSHELL_GATEWAY_NAME  Gateway name for generic podman/kubernetes runs.
  OPENSHELL_SERVER_PORT   Gateway port. Defaults to 8080 for Kubernetes,
                          18080 for Podman/Docker, and 18081 for VM.
  OPENSHELL_SUPERVISOR_IMAGE
                          Podman supervisor sideload image. Defaults to
                          openshell/supervisor:dev and is built on demand.

Docker and VM runs delegate to gateway:docker and gateway:vm setup scripts.
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

binary_detected() {
  command_available "$1" && "$1" --version >/dev/null 2>&1
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

  if podman image exists "${supervisor_image}" >/dev/null 2>&1; then
    return
  fi

  if [[ -n "${OPENSHELL_SUPERVISOR_IMAGE:-}" ]]; then
    echo "ERROR: supervisor image '${supervisor_image}' not found locally." >&2
    echo "       Build it with Podman or unset OPENSHELL_SUPERVISOR_IMAGE to build openshell/supervisor:dev." >&2
    exit 1
  fi

  echo "Building Podman supervisor sideload image (${supervisor_image})..."
  CONTAINER_ENGINE=podman IMAGE_TAG=dev \
    bash "${ROOT}/tasks/scripts/docker-build-image.sh" supervisor-output

  if ! podman image exists "${supervisor_image}" >/dev/null 2>&1; then
    echo "ERROR: expected supervisor image '${supervisor_image}' after build" >&2
    exit 1
  fi
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
  vm)
    export OPENSHELL_VM_GATEWAY_NAME="${OPENSHELL_VM_GATEWAY_NAME:-${OPENSHELL_GATEWAY_NAME:-vm-dev}}"
    exec bash "${ROOT}/tasks/scripts/gateway-vm.sh"
    ;;
esac

DEFAULT_PORT="18080"
if [[ "${DRIVER}" == "kubernetes" ]]; then
  DEFAULT_PORT="8080"
fi

PORT="${OPENSHELL_SERVER_PORT:-${DEFAULT_PORT}}"
GATEWAY_NAME="${OPENSHELL_GATEWAY_NAME:-${DRIVER}-dev}"
STATE_DIR="${OPENSHELL_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-${DRIVER}}"
SANDBOX_NAMESPACE="${OPENSHELL_SANDBOX_NAMESPACE:-${DRIVER}-dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
SANDBOX_IMAGE_PULL_POLICY="${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-IfNotPresent}"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"

if [[ "${DRIVER}" == "podman" ]]; then
  require_podman_service
  SUPERVISOR_IMAGE="${OPENSHELL_SUPERVISOR_IMAGE:-openshell/supervisor:dev}"
  ensure_podman_supervisor_image "${SUPERVISOR_IMAGE}"
  export OPENSHELL_SUPERVISOR_IMAGE="${SUPERVISOR_IMAGE}"
fi

if [[ ! "${GATEWAY_NAME}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: OPENSHELL_GATEWAY_NAME must contain only letters, numbers, dots, underscores, or dashes" >&2
  exit 2
fi

if port_is_in_use "${PORT}"; then
  echo "ERROR: port ${PORT} is already in use; free it or set OPENSHELL_SERVER_PORT" >&2
  exit 2
fi

echo "Building openshell-gateway..."
cargo build -p openshell-server --bin openshell-gateway

mkdir -p "${STATE_DIR}"

GATEWAY_ENDPOINT="http://127.0.0.1:${PORT}"
register_gateway_metadata "${GATEWAY_NAME}" "${GATEWAY_ENDPOINT}" "${PORT}"

echo "Starting standalone ${DRIVER} gateway..."
echo "  gateway:   ${GATEWAY_NAME}"
echo "  endpoint:  ${GATEWAY_ENDPOINT}"
echo "  namespace: ${SANDBOX_NAMESPACE}"
echo "  state dir: ${STATE_DIR}"
if [[ "${DRIVER}" == "podman" ]]; then
  echo "  supervisor image: ${OPENSHELL_SUPERVISOR_IMAGE}"
fi
echo
echo "Active gateway set to '${GATEWAY_NAME}'. The CLI now targets this gateway by default."
echo

exec "${GATEWAY_BIN}" \
  --port "${PORT}" \
  --log-level "${LOG_LEVEL}" \
  --drivers "${DRIVER}" \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc" \
  --sandbox-namespace "${SANDBOX_NAMESPACE}" \
  --sandbox-image "${SANDBOX_IMAGE}" \
  --sandbox-image-pull-policy "${SANDBOX_IMAGE_PULL_POLICY}"
