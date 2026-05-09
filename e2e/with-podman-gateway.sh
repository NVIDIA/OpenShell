#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run an e2e command against a Podman-backed OpenShell gateway.
#
# Modes:
#   - OPENSHELL_GATEWAY_ENDPOINT unset:
#       Build and start an ephemeral standalone gateway with the Podman compute
#       driver, then run the command against that gateway.
#   - OPENSHELL_GATEWAY_ENDPOINT=http://host:port:
#       Use the existing plaintext gateway endpoint and run the command.
#
# Podman e2e currently uses plaintext gateway traffic. The Podman driver does
# not yet inject gateway mTLS client materials into sandbox containers.

set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: e2e/with-podman-gateway.sh <command> [args...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

PODMAN_XDG_CONFIG_HOME_WAS_SET=0
PODMAN_XDG_CONFIG_HOME=""
if [ "${XDG_CONFIG_HOME+x}" = x ]; then
  PODMAN_XDG_CONFIG_HOME_WAS_SET=1
  PODMAN_XDG_CONFIG_HOME="${XDG_CONFIG_HOME}"
  export OPENSHELL_E2E_CONTAINER_ENGINE_XDG_CONFIG_HOME="${PODMAN_XDG_CONFIG_HOME}"
  unset OPENSHELL_E2E_CONTAINER_ENGINE_UNSET_XDG_CONFIG_HOME
else
  export OPENSHELL_E2E_CONTAINER_ENGINE_UNSET_XDG_CONFIG_HOME=1
  unset OPENSHELL_E2E_CONTAINER_ENGINE_XDG_CONFIG_HOME
fi

with_podman_config() {
  if [ "${PODMAN_XDG_CONFIG_HOME_WAS_SET}" = "1" ]; then
    XDG_CONFIG_HOME="${PODMAN_XDG_CONFIG_HOME}" "$@"
  else
    env -u XDG_CONFIG_HOME "$@"
  fi
}

podman_cmd() {
  with_podman_config podman "$@"
}

WORKDIR_PARENT="${TMPDIR:-/tmp}"
WORKDIR_PARENT="${WORKDIR_PARENT%/}"
WORKDIR="$(mktemp -d "${WORKDIR_PARENT}/openshell-e2e-podman.XXXXXX")"
GATEWAY_BIN=""
CLI_BIN=""
GATEWAY_PID=""
GATEWAY_LOG="${WORKDIR}/gateway.log"
GATEWAY_PID_FILE="${WORKDIR}/gateway.pid"
GATEWAY_ARGS_FILE="${WORKDIR}/gateway.args"
E2E_NAMESPACE=""
PODMAN_NETWORK_NAME=""
PODMAN_NETWORK_MANAGED=0
PODMAN_SERVICE_PID=""
PODMAN_SERVICE_LOG="${WORKDIR}/podman-service.log"
PODMAN_SOCKET=""

# Isolate CLI/SDK gateway metadata from the developer's real config.
export XDG_CONFIG_HOME="${WORKDIR}/config"

cleanup() {
  local exit_code=$?

  e2e_stop_gateway "${GATEWAY_PID}" "${GATEWAY_PID_FILE}"

  local sandbox_ids=""
  if [ -n "${E2E_NAMESPACE}" ] && command -v podman >/dev/null 2>&1; then
    sandbox_ids="$(podman_cmd ps -aq \
      --filter "label=openshell.managed=true" \
      --filter "label=openshell.sandbox-namespace=${E2E_NAMESPACE}" \
      2>/dev/null || true)"
  fi

  if [ "${exit_code}" -ne 0 ] && [ -n "${sandbox_ids}" ]; then
    echo "=== sandbox container logs (preserved for debugging) ==="
    for id in ${sandbox_ids}; do
      echo "--- container ${id} (inspect) ---"
      podman_cmd inspect --format '{{.Name}} state={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' "${id}" 2>/dev/null || true
      echo "--- container ${id} (last 80 log lines) ---"
      podman_cmd logs --tail 80 "${id}" 2>&1 || true
    done
    echo "=== end sandbox container logs ==="
  fi

  if [ -n "${sandbox_ids}" ]; then
    for id in ${sandbox_ids}; do
      local sandbox_id
      sandbox_id="$(podman_cmd inspect --format '{{ index .Config.Labels "openshell.sandbox-id" }}' "${id}" 2>/dev/null || true)"
      podman_cmd rm -f "${id}" >/dev/null 2>&1 || true
      if [ -n "${sandbox_id}" ] && [ "${sandbox_id}" != "<no value>" ]; then
        podman_cmd volume rm -f "openshell-sandbox-${sandbox_id}-workspace" >/dev/null 2>&1 || true
        podman_cmd secret rm "openshell-handshake-${sandbox_id}" >/dev/null 2>&1 || true
      fi
    done
  fi

  if [ "${PODMAN_NETWORK_MANAGED}" = "1" ] \
     && [ -n "${PODMAN_NETWORK_NAME}" ] \
     && command -v podman >/dev/null 2>&1; then
    podman_cmd network rm "${PODMAN_NETWORK_NAME}" >/dev/null 2>&1 || true
  fi

  e2e_print_gateway_log_on_failure "${exit_code}" "${GATEWAY_LOG}"
  if [ "${exit_code}" -ne 0 ] && [ -f "${PODMAN_SERVICE_LOG}" ]; then
    echo "=== podman service log (preserved for debugging) ==="
    cat "${PODMAN_SERVICE_LOG}" || true
    echo "=== end podman service log ==="
  fi

  if [ -n "${PODMAN_SERVICE_PID}" ]; then
    kill "${PODMAN_SERVICE_PID}" >/dev/null 2>&1 || true
    wait "${PODMAN_SERVICE_PID}" >/dev/null 2>&1 || true
  fi

  rm -rf "${WORKDIR}" 2>/dev/null || true
}
trap cleanup EXIT

ensure_e2e_podman_network() {
  local network=$1

  if podman_cmd network inspect "${network}" >/dev/null 2>&1; then
    return 0
  fi

  podman_cmd network create \
    --driver bridge \
    --label openshell.managed=true \
    --label "openshell.sandbox-namespace=${E2E_NAMESPACE}" \
    "${network}" >/dev/null
  PODMAN_NETWORK_MANAGED=1
}

default_podman_socket_path() {
  case "$(uname -s)" in
    Darwin)
      printf '%s\n' "${HOME}/.local/share/containers/podman/machine/podman.sock"
      ;;
    Linux)
      if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
        printf '%s\n' "${XDG_RUNTIME_DIR}/podman/podman.sock"
      else
        printf '%s\n' "/run/user/$(id -u)/podman/podman.sock"
      fi
      ;;
    *)
      return 1
      ;;
  esac
}

ensure_podman_api_socket() {
  if [ -n "${OPENSHELL_PODMAN_SOCKET:-}" ]; then
    return 0
  fi

  local default_socket
  if default_socket="$(default_podman_socket_path)" \
     && [ -S "${default_socket}" ] \
     && podman_cmd --url "unix://${default_socket}" info >/dev/null 2>&1; then
    export OPENSHELL_PODMAN_SOCKET="${default_socket}"
    return 0
  fi

  PODMAN_SOCKET="${WORKDIR}/podman/podman.sock"
  mkdir -p "$(dirname "${PODMAN_SOCKET}")"

  echo "Starting temporary Podman API service at ${PODMAN_SOCKET}..."
  with_podman_config podman system service --time=0 "unix://${PODMAN_SOCKET}" \
    >"${PODMAN_SERVICE_LOG}" 2>&1 &
  PODMAN_SERVICE_PID=$!
  export OPENSHELL_PODMAN_SOCKET="${PODMAN_SOCKET}"

  local elapsed=0
  local timeout=30
  while [ "${elapsed}" -lt "${timeout}" ]; do
    if [ -S "${PODMAN_SOCKET}" ] \
       && podman_cmd --url "unix://${PODMAN_SOCKET}" info >/dev/null 2>&1; then
      return 0
    fi

    if ! kill -0 "${PODMAN_SERVICE_PID}" 2>/dev/null; then
      echo "ERROR: Podman API service exited before becoming reachable" >&2
      cat "${PODMAN_SERVICE_LOG}" >&2 || true
      exit 2
    fi

    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "ERROR: Podman API service did not become reachable within ${timeout}s" >&2
  cat "${PODMAN_SERVICE_LOG}" >&2 || true
  exit 2
}

resolve_podman_supervisor_image() {
  if [ -n "${OPENSHELL_SUPERVISOR_IMAGE:-}" ]; then
    printf '%s\n' "${OPENSHELL_SUPERVISOR_IMAGE}"
    return 0
  fi

  if [ -n "${CI:-}" ]; then
    if [ -z "${IMAGE_TAG:-}" ]; then
      echo "ERROR: IMAGE_TAG must be set in CI when no Podman supervisor image override is provided." >&2
      exit 2
    fi

    local registry="${OPENSHELL_REGISTRY:-ghcr.io/nvidia/openshell}"
    printf '%s/supervisor:%s\n' "${registry%/}" "${IMAGE_TAG}"
    return 0
  fi

  printf '%s\n' "openshell/supervisor:dev"
}

ensure_podman_supervisor_image() {
  local image=$1

  if podman_cmd image exists "${image}" 2>/dev/null; then
    return 0
  fi

  if [ "${image}" = "openshell/supervisor:dev" ] \
     && [ -z "${OPENSHELL_SUPERVISOR_IMAGE:-}" ] \
     && [ -z "${CI:-}" ]; then
    echo "Building local Podman supervisor image ${image}..."
    with_podman_config env CONTAINER_ENGINE=podman IMAGE_TAG=dev \
      bash "${ROOT}/tasks/scripts/docker-build-image.sh" supervisor
    if podman_cmd image exists "${image}" 2>/dev/null; then
      return 0
    fi

    echo "ERROR: expected supervisor image '${image}' after local build." >&2
    exit 2
  fi

  echo "Pulling Podman supervisor image ${image}..."
  if podman_cmd pull "${image}"; then
    return 0
  fi

  echo "ERROR: supervisor image '${image}' is not available." >&2
  echo "       Build it, push it, or set OPENSHELL_SUPERVISOR_IMAGE to a pullable image." >&2
  exit 2
}

if [ -n "${OPENSHELL_GATEWAY_ENDPOINT:-}" ]; then
  case "${OPENSHELL_GATEWAY_ENDPOINT}" in
    http://*) ;;
    https://*)
      echo "ERROR: OPENSHELL_GATEWAY_ENDPOINT endpoint mode is HTTP-only for Podman e2e." >&2
      echo "       Podman e2e does not yet support sandbox mTLS client material injection." >&2
      exit 2
      ;;
    *)
      echo "ERROR: OPENSHELL_GATEWAY_ENDPOINT must start with http:// for Podman e2e endpoint mode." >&2
      exit 2
      ;;
  esac

  GATEWAY_NAME="${OPENSHELL_GATEWAY:-openshell-e2e-podman-endpoint}"
  e2e_register_plaintext_gateway \
    "${XDG_CONFIG_HOME}" \
    "${GATEWAY_NAME}" \
    "${OPENSHELL_GATEWAY_ENDPOINT}" \
    "$(e2e_endpoint_port "${OPENSHELL_GATEWAY_ENDPOINT}")"
  export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
  export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-300}"
  export OPENSHELL_E2E_DRIVER="${OPENSHELL_E2E_DRIVER:-podman}"
  export OPENSHELL_E2E_CONTAINER_ENGINE="${OPENSHELL_E2E_CONTAINER_ENGINE:-podman}"

  echo "Using existing Podman e2e gateway endpoint: ${OPENSHELL_GATEWAY_ENDPOINT}"
  "$@"
  exit $?
fi

# Preflight for managed Podman gateway mode.
if ! command -v podman >/dev/null 2>&1; then
  echo "ERROR: podman CLI is required to run Podman-backed e2e tests" >&2
  exit 2
fi
if ! podman_cmd info >/dev/null 2>&1; then
  echo "ERROR: podman service is not reachable (podman info failed)" >&2
  echo "       Start it with 'podman machine start' on macOS, or the user service on Linux." >&2
  exit 2
fi
ensure_podman_api_socket

e2e_build_gateway_binaries "${ROOT}" TARGET_DIR GATEWAY_BIN CLI_BIN

SUPERVISOR_IMAGE="$(resolve_podman_supervisor_image)"
ensure_podman_supervisor_image "${SUPERVISOR_IMAGE}"
echo "Using Podman supervisor image: ${SUPERVISOR_IMAGE}"

DEFAULT_SANDBOX_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
SANDBOX_IMAGE="${OPENSHELL_E2E_PODMAN_SANDBOX_IMAGE:-${OPENSHELL_SANDBOX_IMAGE:-${DEFAULT_SANDBOX_IMAGE}}}"
if ! podman_cmd image exists "${SANDBOX_IMAGE}" 2>/dev/null; then
  echo "Pulling ${SANDBOX_IMAGE}..."
  podman_cmd pull "${SANDBOX_IMAGE}"
fi

HOST_PORT=$(e2e_pick_port)
HEALTH_PORT=$(e2e_pick_port)
STATE_DIR="${WORKDIR}/state"
mkdir -p "${STATE_DIR}"

HANDSHAKE_SECRET="e2e-podman-$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
E2E_NAMESPACE="e2e-podman-$$-${HOST_PORT}"
PODMAN_NETWORK_NAME="${E2E_NAMESPACE}"
ensure_e2e_podman_network "${PODMAN_NETWORK_NAME}"

export OPENSHELL_E2E_DRIVER="podman"
export OPENSHELL_E2E_CONTAINER_ENGINE="podman"
export OPENSHELL_E2E_NETWORK_NAME="${PODMAN_NETWORK_NAME}"
export OPENSHELL_E2E_SANDBOX_NAMESPACE="${E2E_NAMESPACE}"

echo "Starting openshell-gateway on port ${HOST_PORT} (namespace: ${E2E_NAMESPACE})..."
GATEWAY_ARGS=(
  --bind-address 0.0.0.0
  --port "${HOST_PORT}"
  --health-port "${HEALTH_PORT}"
  --ssh-gateway-port "${HOST_PORT}"
  --drivers podman
  --disable-tls
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
  --sandbox-namespace "${E2E_NAMESPACE}"
  --sandbox-image "${SANDBOX_IMAGE}"
  --sandbox-image-pull-policy missing
  --log-level info
)

e2e_write_gateway_args_file "${GATEWAY_ARGS_FILE}" "${GATEWAY_ARGS[@]}"
e2e_export_gateway_restart_metadata \
  "${GATEWAY_BIN}" \
  "${GATEWAY_ARGS_FILE}" \
  "${GATEWAY_LOG}" \
  "${GATEWAY_PID_FILE}"

OPENSHELL_SSH_HANDSHAKE_SECRET="${HANDSHAKE_SECRET}" \
OPENSHELL_SUPERVISOR_IMAGE="${SUPERVISOR_IMAGE}" \
OPENSHELL_NETWORK_NAME="${PODMAN_NETWORK_NAME}" \
  "${GATEWAY_BIN}" "${GATEWAY_ARGS[@]}" >"${GATEWAY_LOG}" 2>&1 &
GATEWAY_PID=$!
printf '%s\n' "${GATEWAY_PID}" >"${GATEWAY_PID_FILE}"

GATEWAY_NAME="openshell-e2e-podman-${HOST_PORT}"
CLI_GATEWAY_ENDPOINT="http://127.0.0.1:${HOST_PORT}"
e2e_register_plaintext_gateway \
  "${XDG_CONFIG_HOME}" \
  "${GATEWAY_NAME}" \
  "${CLI_GATEWAY_ENDPOINT}" \
  "${HOST_PORT}"

export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-300}"

echo "Waiting for gateway to become healthy..."
elapsed=0
timeout=120
while [ "${elapsed}" -lt "${timeout}" ]; do
  if ! kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo "ERROR: openshell-gateway exited before becoming healthy"
    exit 1
  fi
  if curl -sf "http://127.0.0.1:${HEALTH_PORT}/healthz" >/dev/null 2>&1; then
    echo "Gateway healthy after ${elapsed}s."
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
if [ "${elapsed}" -ge "${timeout}" ]; then
  echo "ERROR: gateway did not become healthy within ${timeout}s"
  exit 1
fi

echo "Running e2e command against ${CLI_GATEWAY_ENDPOINT}: $*"
"$@"
