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
#   OPENSHELL_COMPUTE_DRIVER=vm mise run gateway
#   mise run gateway:vm

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tasks/scripts/gateway-common.sh
source "${ROOT}/tasks/scripts/gateway-common.sh"

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
  OPENSHELL_COMPUTE_DRIVER       Driver override used by openshell-gateway.
  OPENSHELL_GATEWAY_NAME  Gateway name for delegated or Kubernetes runs.
  OPENSHELL_BIND_ADDRESS  Gateway listener address. Defaults to 127.0.0.1,
                          or ::1 for Podman Machine on macOS.
  OPENSHELL_SERVER_PORT   Gateway port. Defaults to 8080 for Kubernetes,
                          18080 for Podman/Docker, and 18081 for VM.
Each run delegates to its gateway:<driver> setup script.
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
  echo "       Start Podman or Docker, run inside Kubernetes, or set OPENSHELL_COMPUTE_DRIVER." >&2
  exit 2
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

if [[ -n "${explicit_driver}" && -n "${OPENSHELL_COMPUTE_DRIVER:-}" ]]; then
  echo "ERROR: use either --driver or OPENSHELL_COMPUTE_DRIVER, not both" >&2
  exit 2
fi

if [[ -z "${explicit_driver}" && -n "${OPENSHELL_COMPUTE_DRIVER:-}" ]]; then
  if [[ "${OPENSHELL_COMPUTE_DRIVER}" == *,* ]]; then
    echo "ERROR: mise run gateway supports one driver; got OPENSHELL_COMPUTE_DRIVER=${OPENSHELL_COMPUTE_DRIVER}" >&2
    exit 2
  fi
  explicit_driver="$(normalize_driver "${OPENSHELL_COMPUTE_DRIVER}")"
fi

DRIVER="${explicit_driver:-$(detect_driver)}"

case "${DRIVER}" in
  kubernetes)
    export OPENSHELL_GATEWAY_NAME="${OPENSHELL_GATEWAY_NAME:-kubernetes-dev}"
    exec bash "${ROOT}/tasks/scripts/gateway-kubernetes.sh"
    ;;
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
