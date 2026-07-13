#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run an e2e command against a Docker-backed OpenShell gateway.
#
# Modes:
#   - OPENSHELL_GATEWAY_ENDPOINT unset:
#       Build and start an ephemeral standalone gateway with the Docker compute
#       driver, then run the command against that gateway.
#   - OPENSHELL_GATEWAY_ENDPOINT=http://host:port:
#       Use the existing plaintext gateway endpoint and run the command.
#
# HTTPS endpoint-only mode is intentionally unsupported here. Use a named
# gateway config when mTLS materials are needed.
#
# Sandbox image overrides:
#   OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE=...
#   OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE_PULL_POLICY=Always|IfNotPresent|Never
#
# The default community sandbox image uses :latest. This wrapper refreshes it
# before starting the gateway, while the Docker driver defaults to IfNotPresent
# so local Dockerfile-built images remain usable.
#
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: e2e/with-docker-gateway.sh <command> [args...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

e2e_preserve_mise_dirs

require_container_engine_lane() {
  local lane=$1
  local label=$2
  local selected_engine selected_driver

  if [ -n "${OPENSHELL_E2E_CONTAINER_ENGINE:-}" ]; then
    echo "ERROR: OPENSHELL_E2E_CONTAINER_ENGINE is no longer supported." >&2
    echo "       Set CONTAINER_ENGINE=${lane} for the ${label} e2e lane, or unset it." >&2
    exit 2
  fi
  selected_engine="$(printf '%s' "${CONTAINER_ENGINE:-}" | tr '[:upper:]' '[:lower:]')"
  selected_driver="$(printf '%s' "${OPENSHELL_E2E_DRIVER:-}" | tr '[:upper:]' '[:lower:]')"

  if [ -n "${selected_engine}" ] && [ "${selected_engine}" != "${lane}" ]; then
    echo "ERROR: CONTAINER_ENGINE=${CONTAINER_ENGINE} conflicts with the ${label} e2e lane." >&2
    echo "       Set CONTAINER_ENGINE=${lane} or unset CONTAINER_ENGINE." >&2
    exit 2
  fi
  if [ -n "${selected_driver}" ] && [ "${selected_driver}" != "${lane}" ]; then
    echo "ERROR: OPENSHELL_E2E_DRIVER=${OPENSHELL_E2E_DRIVER} conflicts with the ${label} e2e lane." >&2
    echo "       Set OPENSHELL_E2E_DRIVER=${lane} or unset OPENSHELL_E2E_DRIVER." >&2
    exit 2
  fi

  export CONTAINER_ENGINE="${lane}"
  export OPENSHELL_E2E_DRIVER="${lane}"
}

require_container_engine_lane docker Docker
CONTAINER_ENGINE_QUIET="${CONTAINER_ENGINE_QUIET:-1}"
# shellcheck source=tasks/scripts/container-engine.sh
source "${ROOT}/tasks/scripts/container-engine.sh"

github_actions_host_docker_tmpdir() {
  if [ "${GITHUB_ACTIONS:-}" != "true" ] \
     || [ ! -S /var/run/docker.sock ] \
     || [ ! -d /__w/_temp ]; then
    return 1
  fi

  # Container jobs talk to the host Docker daemon. Bind mount source paths must
  # exist on the host, but the gateway also validates those same paths inside
  # the job container before handing them to Docker. This must be a real mount
  # rather than a symlink because the Docker driver canonicalizes file paths.
  if [ -d /home/runner/_work/_temp ]; then
    printf '%s\n' /home/runner/_work/_temp
    return 0
  fi

  echo "ERROR: GitHub Actions Docker e2e requires /home/runner/_work mounted inside the job container." >&2
  echo "       Mount /home/runner/_work:/home/runner/_work so Docker bind paths resolve on both sides." >&2
  return 2
}

if WORKDIR_PARENT="$(github_actions_host_docker_tmpdir)"; then
  :
else
  status=$?
  if [ "${status}" -eq 2 ]; then
    exit 2
  fi
  WORKDIR_PARENT="${TMPDIR:-/tmp}"
fi

e2e_align_docker_host_with_cli_context

WORKDIR_PARENT="${WORKDIR_PARENT%/}"
WORKDIR="$(mktemp -d "${WORKDIR_PARENT}/openshell-e2e-gateway.XXXXXX")"
GATEWAY_BIN=""
CLI_BIN=""
GATEWAY_PID=""
GATEWAY_LOG="${WORKDIR}/gateway.log"
GATEWAY_PID_FILE="${WORKDIR}/gateway.pid"
GATEWAY_ARGS_FILE="${WORKDIR}/gateway.args"
E2E_NAMESPACE=""
DOCKER_NETWORK_NAME=""
DOCKER_NETWORK_CONNECTED_CONTAINER=""
DOCKER_NETWORK_MANAGED=0
GPU_MODE="${OPENSHELL_E2E_DOCKER_GPU:-0}"

# Isolate CLI/SDK gateway metadata from the developer's real config.
export XDG_CONFIG_HOME="${WORKDIR}/config"
export XDG_DATA_HOME="${WORKDIR}/data"
# Docker e2e runs in a GitHub Actions container while talking to the host
# Docker daemon. Keep gateway state in the host-visible workdir so driver-owned
# bind mounts, including sandbox JWT files, resolve on both sides.
export XDG_STATE_HOME="${WORKDIR}/state"

cleanup() {
  local exit_code=$?

  e2e_stop_gateway "${GATEWAY_PID}" "${GATEWAY_PID_FILE}"

  if [ "${exit_code}" -ne 0 ] \
     && [ -n "${E2E_NAMESPACE}" ] \
     && command -v docker >/dev/null 2>&1; then
    local ids
    ids=$(docker ps -aq \
      --filter "label=openshell.ai/managed-by=openshell" \
      --filter "label=openshell.ai/sandbox-namespace=${E2E_NAMESPACE}" \
      2>/dev/null || true)
    if [ -n "${ids}" ]; then
      echo "=== sandbox container logs (preserved for debugging) ==="
      for id in ${ids}; do
        echo "--- container ${id} (inspect) ---"
        docker inspect --format '{{.Name}} state={{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}} error={{.State.Error}}' "${id}" 2>/dev/null || true
        echo "--- container ${id} (last 80 log lines) ---"
        docker logs --tail 80 "${id}" 2>&1 || true
      done
      echo "=== end sandbox container logs ==="
    fi
  fi

  if [ -n "${E2E_NAMESPACE}" ] && command -v docker >/dev/null 2>&1; then
    local stale
    stale=$(docker ps -aq \
      --filter "label=openshell.ai/managed-by=openshell" \
      --filter "label=openshell.ai/sandbox-namespace=${E2E_NAMESPACE}" \
      2>/dev/null || true)
    if [ -n "${stale}" ]; then
      # shellcheck disable=SC2086
      docker rm -f ${stale} >/dev/null 2>&1 || true
    fi
  fi

  if [ -n "${DOCKER_NETWORK_CONNECTED_CONTAINER}" ] \
     && [ -n "${DOCKER_NETWORK_NAME}" ] \
     && command -v docker >/dev/null 2>&1; then
    docker network disconnect -f \
      "${DOCKER_NETWORK_NAME}" \
      "${DOCKER_NETWORK_CONNECTED_CONTAINER}" >/dev/null 2>&1 || true
  fi

  if [ "${DOCKER_NETWORK_MANAGED}" = "1" ] \
     && [ -n "${DOCKER_NETWORK_NAME}" ] \
     && command -v docker >/dev/null 2>&1; then
    docker network rm "${DOCKER_NETWORK_NAME}" >/dev/null 2>&1 || true
  fi

  e2e_print_gateway_log_on_failure "${exit_code}" "${GATEWAY_LOG}"

  rm -rf "${WORKDIR}" 2>/dev/null || true
}
trap cleanup EXIT

ensure_e2e_docker_network() {
  local network=$1

  if docker network inspect "${network}" >/dev/null 2>&1; then
    return 0
  fi

  docker network create \
    --driver bridge \
    --attachable \
    --label openshell.ai/managed-by=openshell \
    --label "openshell.ai/sandbox-namespace=${E2E_NAMESPACE}" \
    "${network}" >/dev/null
  DOCKER_NETWORK_MANAGED=1
}

github_actions_container_id() {
  if [ "${GITHUB_ACTIONS:-}" != "true" ] || [ ! -f /.dockerenv ]; then
    return 1
  fi

  local container
  container="$(hostname)"
  if docker inspect "${container}" >/dev/null 2>&1; then
    printf '%s\n' "${container}"
    return 0
  fi

  return 1
}

connect_current_container_to_docker_network() {
  local network=$1
  local container

  if ! container="$(github_actions_container_id)"; then
    return 1
  fi

  local connect_err="${WORKDIR}/docker-network-connect.err"
  if ! docker network connect \
    --alias host.openshell.internal \
    "${network}" \
    "${container}" 2>"${connect_err}"; then
    if ! grep -qi "already exists" "${connect_err}"; then
      cat "${connect_err}" >&2
      return 1
    fi
  fi

  DOCKER_NETWORK_CONNECTED_CONTAINER="${container}"

  local container_ip
  container_ip="$(docker inspect \
    --format "{{with index .NetworkSettings.Networks \"${network}\"}}{{.IPAddress}}{{end}}" \
    "${container}")"
  if [ -z "${container_ip}" ]; then
    echo "ERROR: failed to resolve current job container IP on Docker network ${network}" >&2
    return 1
  fi

  GATEWAY_HOST_ALIAS_IP="${container_ip}"
}

if [ -n "${OPENSHELL_GATEWAY_ENDPOINT:-}" ]; then
  case "${OPENSHELL_GATEWAY_ENDPOINT}" in
    http://*) ;;
    https://*)
      echo "ERROR: OPENSHELL_GATEWAY_ENDPOINT endpoint mode is HTTP-only for e2e." >&2
      echo "       Register a named gateway with mTLS config instead of using a raw HTTPS endpoint." >&2
      exit 2
      ;;
    *)
      echo "ERROR: OPENSHELL_GATEWAY_ENDPOINT must start with http:// for e2e endpoint mode." >&2
      exit 2
      ;;
  esac

  GATEWAY_NAME="${OPENSHELL_GATEWAY:-openshell-e2e-endpoint}"
  e2e_register_plaintext_gateway \
    "${XDG_CONFIG_HOME}" \
    "${GATEWAY_NAME}" \
    "${OPENSHELL_GATEWAY_ENDPOINT}" \
    "$(e2e_endpoint_port "${OPENSHELL_GATEWAY_ENDPOINT}")"
  export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
  export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-180}"
  export OPENSHELL_E2E_DRIVER="docker"

  echo "Using existing e2e gateway endpoint: ${OPENSHELL_GATEWAY_ENDPOINT}"
  "$@"
  exit $?
fi

# ── Preflight for managed Docker gateway mode ────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker CLI is required to run Docker-backed e2e tests" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon is not reachable (docker info failed)" >&2
  exit 2
fi
if [ "${GPU_MODE}" = "1" ]; then
  DOCKER_CDI_SPEC_DIRS="$(docker info --format '{{json .CDISpecDirs}}' 2>/dev/null || true)"
  if [ -z "${DOCKER_CDI_SPEC_DIRS}" ] \
     || [ "${DOCKER_CDI_SPEC_DIRS}" = "null" ] \
     || [ "${DOCKER_CDI_SPEC_DIRS}" = "[]" ] \
     || [ "${DOCKER_CDI_SPEC_DIRS}" = "<no value>" ]; then
    echo "ERROR: Docker GPU e2e requires Docker CDI support." >&2
    echo "       Generate CDI specs and restart Docker, then verify docker info reports CDISpecDirs." >&2
    exit 2
  fi
fi

resolve_docker_supervisor_image() {
  if [ -n "${OPENSHELL_DOCKER_SUPERVISOR_IMAGE:-}" ]; then
    printf '%s\n' "${OPENSHELL_DOCKER_SUPERVISOR_IMAGE}"
    return 0
  fi

  if [ -n "${OPENSHELL_SUPERVISOR_IMAGE:-}" ]; then
    printf '%s\n' "${OPENSHELL_SUPERVISOR_IMAGE}"
    return 0
  fi

  if [ -n "${CI:-}" ]; then
    if [ -z "${IMAGE_TAG:-}" ]; then
      echo "ERROR: IMAGE_TAG must be set in CI when no Docker supervisor image override is provided." >&2
      exit 2
    fi

    local registry="${OPENSHELL_REGISTRY:-ghcr.io/nvidia/openshell}"
    printf '%s/supervisor:%s\n' "${registry%/}" "${IMAGE_TAG}"
    return 0
  fi

  printf '%s\n' "openshell/supervisor:dev"
}

docker_pull_with_retry() {
  local image=$1
  local attempts=4
  local delay=10
  local attempt=1

  while [ "${attempt}" -le "${attempts}" ]; do
    if [ "${attempt}" -gt 1 ]; then
      echo "Retrying Docker pull for ${image} (attempt ${attempt}/${attempts})..."
    fi

    if docker pull "${image}"; then
      return 0
    fi

    if [ "${attempt}" -lt "${attempts}" ]; then
      echo "Docker pull failed for ${image}; retrying in ${delay}s..." >&2
      sleep "${delay}"
    fi

    attempt=$((attempt + 1))
  done

  return 1
}

build_local_docker_supervisor_image_if_required() {
  local image=$1

  if [ "${image}" != "openshell/supervisor:dev" ]; then
    return 0
  fi

  local daemon_arch
  daemon_arch="$(ce_info_arch)"

  echo "Building local Docker supervisor image ${image} for linux/${daemon_arch}..."
  CONTAINER_ENGINE=docker DOCKER_PLATFORM="linux/${daemon_arch}" IMAGE_TAG=dev \
    bash "${ROOT}/tasks/scripts/docker-build-image.sh" supervisor
  if docker image inspect "${image}" >/dev/null 2>&1; then
    return 0
  fi

  echo "ERROR: expected supervisor image '${image}' after local build." >&2
  exit 2
}

ensure_docker_supervisor_image() {
  local image=$1

  if docker image inspect "${image}" >/dev/null 2>&1; then
    return 0
  fi

  echo "Pulling Docker supervisor image ${image}..."
  if docker_pull_with_retry "${image}"; then
    return 0
  fi

  echo "ERROR: supervisor image '${image}' is not available." >&2
  echo "       Build it, push it, or set OPENSHELL_SUPERVISOR_IMAGE to a pullable image." >&2
  exit 2
}

image_uses_latest_tag() {
  local image=$1
  local last_component

  # Digest references are immutable even if the tag portion says latest.
  if [[ "${image}" == *@* ]]; then
    return 1
  fi

  last_component="${image##*/}"
  # Docker treats an omitted tag as :latest.
  if [[ "${last_component}" != *:* ]]; then
    return 0
  fi

  [[ "${last_component}" == *:latest ]]
}

ensure_sandbox_image_available() {
  local image=$1

  if image_uses_latest_tag "${image}"; then
    echo "Refreshing latest sandbox image ${image}..."
    docker_pull_with_retry "${image}"
    return
  fi

  if docker image inspect "${image}" >/dev/null 2>&1; then
    return
  fi

  echo "Pulling ${image}..."
  docker_pull_with_retry "${image}"
}

e2e_build_gateway_binaries "${ROOT}" TARGET_DIR GATEWAY_BIN CLI_BIN

SUPERVISOR_IMAGE="$(resolve_docker_supervisor_image)"
build_local_docker_supervisor_image_if_required "${SUPERVISOR_IMAGE}"
ensure_docker_supervisor_image "${SUPERVISOR_IMAGE}"
echo "Using Docker supervisor image: ${SUPERVISOR_IMAGE}"

DEFAULT_SANDBOX_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
SANDBOX_IMAGE="${OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE:-${OPENSHELL_SANDBOX_IMAGE:-${DEFAULT_SANDBOX_IMAGE}}}"
SANDBOX_IMAGE_PULL_POLICY="${OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE_PULL_POLICY:-${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-IfNotPresent}}"
if ! ensure_sandbox_image_available "${SANDBOX_IMAGE}"; then
  echo "ERROR: sandbox image '${SANDBOX_IMAGE}' is not available." >&2
  exit 2
fi

PKI_DIR="${WORKDIR}/pki"
e2e_generate_pki "${GATEWAY_BIN}" "${PKI_DIR}"

HOST_PORT=$(e2e_pick_port)
STATE_DIR="${XDG_STATE_HOME}"
mkdir -p "${STATE_DIR}"
JWT_DIR="${PKI_DIR}/jwt"

GATEWAY_ENDPOINT="https://host.openshell.internal:${HOST_PORT}"
E2E_NAMESPACE="e2e-docker-$$-${HOST_PORT}"
DOCKER_NETWORK_NAME="${E2E_NAMESPACE}"
GATEWAY_HOST_ALIAS_IP=""

ensure_e2e_docker_network "${DOCKER_NETWORK_NAME}"
export OPENSHELL_E2E_DOCKER_NETWORK_NAME="${DOCKER_NETWORK_NAME}"
export OPENSHELL_E2E_NETWORK_NAME="${DOCKER_NETWORK_NAME}"
export OPENSHELL_E2E_SANDBOX_NAMESPACE="${E2E_NAMESPACE}"
export OPENSHELL_E2E_DRIVER="docker"
if connect_current_container_to_docker_network "${DOCKER_NETWORK_NAME}"; then
  echo "Connected CI job container to Docker network ${DOCKER_NETWORK_NAME} (${GATEWAY_HOST_ALIAS_IP})."
else
  GATEWAY_HOST_ALIAS_IP=""
fi

echo "Starting openshell-gateway on port ${HOST_PORT} (namespace: ${E2E_NAMESPACE})..."
echo "Using sandbox image: ${SANDBOX_IMAGE} (pull policy: ${SANDBOX_IMAGE_PULL_POLICY})"
# Driver-specific options moved from CLI flags into a TOML config table
# (commit 560550d2). Synthesize a minimal config here and pass --config.
# Quote a value as a TOML basic string: wrap in double quotes and escape
# any embedded backslashes / double quotes. Adequate for paths, image
# refs, and namespace identifiers — none of which contain TOML special
# characters in practice.
toml_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "${value}"
}

GATEWAY_CONFIG="${STATE_DIR}/gateway.toml"
{
  printf '[openshell]\nversion = 1\n\n'
  printf '[openshell.gateway]\nlog_level = "info"\n\n'
  e2e_write_gateway_jwt_config "${JWT_DIR}" "openshell-e2e-docker-${HOST_PORT}"
  e2e_write_gateway_mtls_auth_config
  printf '[openshell.drivers.docker]\n'
  printf 'sandbox_namespace = %s\n'    "$(toml_string "${E2E_NAMESPACE}")"
  printf 'network_name = %s\n'         "$(toml_string "${DOCKER_NETWORK_NAME}")"
  printf 'grpc_endpoint = %s\n'        "$(toml_string "${GATEWAY_ENDPOINT}")"
  printf 'default_image = %s\n'        "$(toml_string "${SANDBOX_IMAGE}")"
  printf 'image_pull_policy = %s\n'    "$(toml_string "${SANDBOX_IMAGE_PULL_POLICY}")"
  printf 'guest_tls_ca = %s\n'         "$(toml_string "${PKI_DIR}/ca.crt")"
  printf 'guest_tls_cert = %s\n'       "$(toml_string "${PKI_DIR}/client/tls.crt")"
  printf 'guest_tls_key = %s\n'        "$(toml_string "${PKI_DIR}/client/tls.key")"
  printf 'enable_bind_mounts = true\n'
  printf 'supervisor_image = %s\n'     "$(toml_string "${SUPERVISOR_IMAGE}")"
  if [ -n "${GATEWAY_HOST_ALIAS_IP}" ]; then
    printf 'host_gateway_ip = %s\n'    "$(toml_string "${GATEWAY_HOST_ALIAS_IP}")"
  fi
} > "${GATEWAY_CONFIG}"

GATEWAY_ARGS=(
  --config "${GATEWAY_CONFIG}"
  --bind-address 0.0.0.0
  --port "${HOST_PORT}"
  --drivers docker
  --tls-cert "${PKI_DIR}/server/tls.crt"
  --tls-key "${PKI_DIR}/server/tls.key"
  --tls-client-ca "${PKI_DIR}/ca.crt"
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
)

e2e_write_gateway_args_file "${GATEWAY_ARGS_FILE}" "${GATEWAY_ARGS[@]}"
e2e_export_gateway_restart_metadata \
  "${GATEWAY_BIN}" \
  "${GATEWAY_ARGS_FILE}" \
  "${GATEWAY_LOG}" \
  "${GATEWAY_PID_FILE}"

"${GATEWAY_BIN}" "${GATEWAY_ARGS[@]}" >"${GATEWAY_LOG}" 2>&1 &
GATEWAY_PID=$!
printf '%s\n' "${GATEWAY_PID}" >"${GATEWAY_PID_FILE}"

GATEWAY_NAME="openshell-e2e-docker-${HOST_PORT}"
CLI_GATEWAY_ENDPOINT="https://127.0.0.1:${HOST_PORT}"
e2e_register_mtls_gateway \
  "${XDG_CONFIG_HOME}" \
  "${GATEWAY_NAME}" \
  "${CLI_GATEWAY_ENDPOINT}" \
  "${HOST_PORT}" \
  "${PKI_DIR}"

export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-180}"

echo "Waiting for gateway to become healthy..."
elapsed=0
timeout=120
last_status_output=""
while [ "${elapsed}" -lt "${timeout}" ]; do
  if ! kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo "ERROR: openshell-gateway exited before becoming healthy"
    exit 1
  fi
  if last_status_output="$("${CLI_BIN}" status 2>&1)"; then
    echo "Gateway healthy after ${elapsed}s."
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
if [ "${elapsed}" -ge "${timeout}" ]; then
  echo "ERROR: gateway did not become healthy within ${timeout}s"
  echo "=== last openshell status output ==="
  if [ -n "${last_status_output}" ]; then
    printf '%s\n' "${last_status_output}"
  else
    echo "<no output>"
  fi
  echo "=== end openshell status output ==="
  exit 1
fi

echo "Running e2e command against ${CLI_GATEWAY_ENDPOINT}: $*"
"$@"
