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
# HTTPS endpoint-only mode is intentionally unsupported here. Use a named
# gateway config when mTLS materials are needed.
#
# Set OPENSHELL_E2E_PODMAN_STOP_TIMEOUT_SECS to override the managed gateway's
# Podman sandbox stop timeout. The harness default is intentionally shorter
# than the production driver default to keep CI teardown bounded.

set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: e2e/with-podman-gateway.sh <command> [args...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"
# shellcheck source=e2e/support/podman-gateway-config.sh
source "${ROOT}/e2e/support/podman-gateway-config.sh"

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

require_container_engine_lane podman Podman

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
if [ "${OPENSHELL_E2E_SPIFFE_FIXTURE:-0}" = "1" ]; then
  mkdir -p "${WORKDIR}/spiffe"
  export OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET="${OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET:-${WORKDIR}/spiffe/gateway.sock}"
  export OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET="${OPENSHELL_E2E_GATEWAY_SPIFFE_SOCKET}"
  if [ -z "${OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET:-}" ]; then
    OPENSHELL_E2E_PROVIDER_SPIFFE_PORT="$(e2e_pick_port)"
    export OPENSHELL_E2E_PROVIDER_SPIFFE_LISTEN="0.0.0.0:${OPENSHELL_E2E_PROVIDER_SPIFFE_PORT}"
    export OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET="tcp:169.254.1.2:${OPENSHELL_E2E_PROVIDER_SPIFFE_PORT}"
  fi
fi
GATEWAY_BIN=""
CLI_BIN=""
GATEWAY_PID=""
GATEWAY_LOG="${WORKDIR}/gateway.log"
export OPENSHELL_E2E_GATEWAY_LOG="${GATEWAY_LOG}"
GATEWAY_PID_FILE="${WORKDIR}/gateway.pid"
GATEWAY_ARGS_FILE="${WORKDIR}/gateway.args"
DRIVER_BIN=""
DRIVER_PID=""
DRIVER_LOG="${WORKDIR}/podman-driver.log"
DRIVER_SOCKET="${WORKDIR}/compute-driver.sock"
E2E_NAMESPACE=""
PODMAN_NETWORK_NAME=""
PODMAN_NETWORK_MANAGED=0
PODMAN_SERVICE_PID=""
PODMAN_SERVICE_LOG="${WORKDIR}/podman-service.log"
PODMAN_SOCKET=""
GPU_MODE="${OPENSHELL_E2E_PODMAN_GPU:-0}"
OIDC_MODE="${OPENSHELL_E2E_OIDC_GATEWAY:-0}"
OIDC_ISSUER="${OPENSHELL_E2E_OIDC_ISSUER:-}"

if [ "${OIDC_MODE}" = "1" ] && [ -z "${OIDC_ISSUER}" ]; then
  echo "ERROR: OPENSHELL_E2E_OIDC_ISSUER is required when OPENSHELL_E2E_OIDC_GATEWAY=1" >&2
  exit 2
fi

# Isolate CLI/SDK gateway metadata from the developer's real config.
export XDG_CONFIG_HOME="${WORKDIR}/config"

cleanup() {
  local exit_code=$?

  e2e_stop_gateway "${GATEWAY_PID}" "${GATEWAY_PID_FILE}"
  e2e_stop_process "${DRIVER_PID}" "external Podman compute driver"

  local sandbox_ids=""
  if command -v podman >/dev/null 2>&1; then
    if [ -n "${PODMAN_NETWORK_NAME}" ]; then
      sandbox_ids="$(podman_cmd ps -aq \
        --filter "label=openshell.managed=true" \
        --filter "network=${PODMAN_NETWORK_NAME}" \
        2>/dev/null || true)"
    elif [ -n "${E2E_NAMESPACE}" ]; then
      sandbox_ids="$(podman_cmd ps -aq \
        --filter "label=openshell.managed=true" \
        --filter "label=openshell.ai/sandbox-namespace=${E2E_NAMESPACE}" \
        2>/dev/null || true)"
    fi
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
      sandbox_id="$(podman_cmd inspect --format '{{ index .Config.Labels "openshell.ai/sandbox-id" }}' "${id}" 2>/dev/null || true)"
      podman_cmd rm -f "${id}" >/dev/null 2>&1 || true
      if [ -n "${sandbox_id}" ] && [ "${sandbox_id}" != "<no value>" ]; then
        podman_cmd volume rm -f "openshell-sandbox-${sandbox_id}-workspace" >/dev/null 2>&1 || true
      fi
    done
  fi

  if [ "${PODMAN_NETWORK_MANAGED}" = "1" ] \
     && [ -n "${PODMAN_NETWORK_NAME}" ] \
     && command -v podman >/dev/null 2>&1; then
    podman_cmd network rm "${PODMAN_NETWORK_NAME}" >/dev/null 2>&1 || true
  fi

  e2e_print_gateway_log_on_failure "${exit_code}" "${GATEWAY_LOG}"
  if [ "${exit_code}" -ne 0 ] && [ -f "${DRIVER_LOG}" ]; then
    echo "=== external Podman compute driver log ==="
    cat "${DRIVER_LOG}" || true
    echo "=== end external Podman compute driver log ==="
  fi
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
    --label "openshell.ai/sandbox-namespace=${E2E_NAMESPACE}" \
    "${network}" >/dev/null
  PODMAN_NETWORK_MANAGED=1
}

default_podman_socket_path() {
  case "$(uname -s)" in
    Darwin)
      # On macOS the podman client talks to a VM; the API socket path is
      # per-launch (under $TMPDIR) and reported by `podman machine inspect`.
      # The legacy ~/.local/share/containers/podman/machine/podman.sock path
      # is not created by podman >= 5.x with the applehv/libkrun providers.
      podman_cmd machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}' 2>/dev/null \
        | awk 'NF { print; exit }'
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
  if [ "${OPENSHELL_E2E_FORCE_TEMP_PODMAN_SERVICE:-0}" != 1 ]; then
    if [ -n "${OPENSHELL_PODMAN_SOCKET:-}" ]; then
      return 0
    fi

    local default_socket
    default_socket="$(default_podman_socket_path || true)"
    if [ -n "${default_socket}" ] \
       && [ -S "${default_socket}" ] \
       && podman_cmd --url "unix://${default_socket}" info >/dev/null 2>&1; then
      export OPENSHELL_PODMAN_SOCKET="${default_socket}"
      return 0
    fi
  else
    unset OPENSHELL_PODMAN_SOCKET
  fi

  # `podman system service` is a Linux-only subcommand — the macOS client
  # delegates the API service to the VM, so we can't spin one up locally.
  # If we got here on Darwin, the user's `podman machine` is either not
  # running or its socket isn't reachable; surface that directly.
  if [ "$(uname -s)" = "Darwin" ]; then
    echo "ERROR: could not reach the Podman API socket on macOS." >&2
    echo "       Expected socket from 'podman machine inspect': ${default_socket:-<none>}" >&2
    echo "       Ensure 'podman machine start' has been run, or set" >&2
    echo "       OPENSHELL_PODMAN_SOCKET to a reachable unix socket path." >&2
    exit 2
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

  if [ -n "${OPENSHELL_E2E_SUPERVISOR_BIN:-}" ]; then
    local dockerfile=${OPENSHELL_E2E_SUPERVISOR_DOCKERFILE:-${ROOT}/deploy/docker/Dockerfile.supervisor}
    local context="${WORKDIR}/supervisor-image" arch
    case "${image}" in
      *:dev|*:latest)
        echo "ERROR: supplied supervisor binaries require a unique versioned image tag, not ${image}." >&2
        exit 2
        ;;
      *:*) ;;
      *)
        echo "ERROR: supplied supervisor binaries require an explicit versioned image tag: ${image}." >&2
        exit 2
        ;;
    esac
    case "$(uname -m)" in
      x86_64|amd64) arch=amd64 ;;
      aarch64|arm64) arch=arm64 ;;
      *) echo "ERROR: unsupported supervisor image architecture: $(uname -m)" >&2; exit 2 ;;
    esac
    if [ ! -x "${OPENSHELL_E2E_SUPERVISOR_BIN}" ]; then
      echo "ERROR: supplied supervisor binary is not executable: ${OPENSHELL_E2E_SUPERVISOR_BIN}" >&2
      exit 2
    fi
    if [ ! -f "${dockerfile}" ]; then
      echo "ERROR: supervisor Dockerfile not found: ${dockerfile}" >&2
      exit 2
    fi
    mkdir -p "${context}/deploy/docker/.build/prebuilt-binaries/${arch}"
    install -m 0555 "${OPENSHELL_E2E_SUPERVISOR_BIN}" \
      "${context}/deploy/docker/.build/prebuilt-binaries/${arch}/openshell-sandbox"
    cp "${dockerfile}" "${context}/deploy/docker/Dockerfile.supervisor"
    echo "Building Podman supervisor image ${image} from supplied binary..."
    (
      cd "${context}"
      podman_cmd build \
        --build-arg "TARGETARCH=${arch}" \
        --file deploy/docker/Dockerfile.supervisor \
        --target supervisor \
        --tag "${image}" \
        .
    )
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

  if podman_cmd image exists "${image}" 2>/dev/null; then
    return 0
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
      echo "ERROR: OPENSHELL_GATEWAY_ENDPOINT endpoint mode is HTTP-only for e2e." >&2
      echo "       Register a named gateway with mTLS config instead of using a raw HTTPS endpoint." >&2
      exit 2
      ;;
    *)
      echo "ERROR: OPENSHELL_GATEWAY_ENDPOINT must start with http:// for e2e endpoint mode." >&2
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
  export OPENSHELL_E2E_DRIVER="podman"

  echo "Using existing Podman e2e gateway endpoint: ${OPENSHELL_GATEWAY_ENDPOINT}"
  "$@"
  exit $?
fi

# Validate the generated configuration dialect before creating runtime resources.
CONFIG_SCHEMA_VERSION="$(e2e_podman_config_schema_version)"
EXTERNAL_DRIVER_PULL_POLICY="$(e2e_podman_external_driver_pull_policy "${CONFIG_SCHEMA_VERSION}")"

# Validate the opt-in profile before building images or allocating runtime resources.
e2e_podman_option_profile >/dev/null

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
export OPENSHELL_BIN="${CLI_BIN}"
if [ "${OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER:-0}" = "1" ]; then
  e2e_build_external_driver \
    "${ROOT}" openshell-driver-podman openshell-driver-podman DRIVER_BIN
fi

SUPERVISOR_IMAGE="$(resolve_podman_supervisor_image)"
ensure_podman_supervisor_image "${SUPERVISOR_IMAGE}"
SUPERVISOR_IMAGE_ID="$(podman_cmd image inspect --format '{{.Id}}' "${SUPERVISOR_IMAGE}")"
SUPERVISOR_IMAGE_ID="${SUPERVISOR_IMAGE_ID#sha256:}"
SUPERVISOR_IMAGE_DIGEST="$(podman_cmd image inspect --format '{{.Digest}}' "${SUPERVISOR_IMAGE}")"
if ! [[ "${SUPERVISOR_IMAGE_ID}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "ERROR: could not resolve immutable supervisor image ID for ${SUPERVISOR_IMAGE}." >&2
  exit 2
fi
if ! [[ "${SUPERVISOR_IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: could not resolve supervisor image digest for ${SUPERVISOR_IMAGE}." >&2
  exit 2
fi
# The parity harness forces a temporary Podman API service into the same
# isolated XDG store where this image was built. Address the local image by its
# immutable manifest digest so policy=missing cannot resolve a mutable tag or
# contact a registry for a different artifact.
SUPERVISOR_IMAGE_REPOSITORY="${SUPERVISOR_IMAGE%:*}"
SUPERVISOR_RUNTIME_IMAGE="${SUPERVISOR_IMAGE_REPOSITORY}@${SUPERVISOR_IMAGE_DIGEST}"
if ! [[ "${SUPERVISOR_RUNTIME_IMAGE}" =~ ^[^@]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: supervisor runtime image is not digest-pinned: ${SUPERVISOR_RUNTIME_IMAGE}" >&2
  exit 2
fi
SUPERVISOR_BASE_IMAGE="$(awk '$1 == "FROM" { print $2; exit }' "${OPENSHELL_E2E_SUPERVISOR_DOCKERFILE:-${ROOT}/deploy/docker/Dockerfile.supervisor}")"
SUPERVISOR_BASE_IMAGE_ID="$(podman_cmd image inspect --format '{{.Id}}' "${SUPERVISOR_BASE_IMAGE}")"
SUPERVISOR_BASE_IMAGE_ID="${SUPERVISOR_BASE_IMAGE_ID#sha256:}"
SUPERVISOR_BASE_IMAGE_DIGEST="$(podman_cmd image inspect --format '{{.Digest}}' "${SUPERVISOR_BASE_IMAGE}")"
if ! [[ "${SUPERVISOR_BASE_IMAGE_ID}" =~ ^[0-9a-f]{64}$ ]] \
   || ! [[ "${SUPERVISOR_BASE_IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: could not resolve supervisor base-image provenance for ${SUPERVISOR_BASE_IMAGE}." >&2
  exit 2
fi
SUPERVISOR_PACKAGE_MANIFEST="${OPENSHELL_PARITY_SUPERVISOR_PACKAGE_CAPTURE:-${WORKDIR}/supervisor.packages.txt}"
mkdir -p "$(dirname "${SUPERVISOR_PACKAGE_MANIFEST}")"
podman_cmd run --rm --network none --entrypoint /sbin/apk \
  "${SUPERVISOR_RUNTIME_IMAGE}" info -v | LC_ALL=C sort >"${SUPERVISOR_PACKAGE_MANIFEST}"
SUPERVISOR_PACKAGE_MANIFEST_SHA256="$(sha256sum "${SUPERVISOR_PACKAGE_MANIFEST}" | cut -d' ' -f1)"
echo "Using Podman supervisor image: ${SUPERVISOR_RUNTIME_IMAGE} (ID ${SUPERVISOR_IMAGE_ID}, digest ${SUPERVISOR_IMAGE_DIGEST}, base ${SUPERVISOR_BASE_IMAGE} ID ${SUPERVISOR_BASE_IMAGE_ID} digest ${SUPERVISOR_BASE_IMAGE_DIGEST}, packages ${SUPERVISOR_PACKAGE_MANIFEST_SHA256})"

DEFAULT_SANDBOX_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
SANDBOX_IMAGE_REQUEST="${OPENSHELL_E2E_PODMAN_SANDBOX_IMAGE:-${OPENSHELL_SANDBOX_IMAGE:-${DEFAULT_SANDBOX_IMAGE}}}"
PODMAN_STOP_TIMEOUT_SECS="${OPENSHELL_E2E_PODMAN_STOP_TIMEOUT_SECS:-15}"
if ! [[ "${PODMAN_STOP_TIMEOUT_SECS}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: OPENSHELL_E2E_PODMAN_STOP_TIMEOUT_SECS must be a non-negative integer." >&2
  exit 2
fi
if ! podman_cmd image exists "${SANDBOX_IMAGE_REQUEST}" 2>/dev/null; then
  echo "Pulling ${SANDBOX_IMAGE_REQUEST}..."
  podman_cmd pull "${SANDBOX_IMAGE_REQUEST}"
fi
SANDBOX_IMAGE_ID="$(podman_cmd image inspect --format '{{.Id}}' "${SANDBOX_IMAGE_REQUEST}")"
SANDBOX_IMAGE_ID="${SANDBOX_IMAGE_ID#sha256:}"
SANDBOX_IMAGE_DIGEST="$(podman_cmd image inspect --format '{{.Digest}}' "${SANDBOX_IMAGE_REQUEST}")"
SANDBOX_IMAGE_REPOSITORY="${SANDBOX_IMAGE_REQUEST%%@*}"
case "${SANDBOX_IMAGE_REPOSITORY##*/}" in
  *:*) SANDBOX_IMAGE_REPOSITORY="${SANDBOX_IMAGE_REPOSITORY%:*}" ;;
esac
SANDBOX_RUNTIME_IMAGE="${SANDBOX_IMAGE_REPOSITORY}@${SANDBOX_IMAGE_DIGEST}"
if ! [[ "${SANDBOX_IMAGE_ID}" =~ ^[0-9a-f]{64}$ ]] \
   || ! [[ "${SANDBOX_RUNTIME_IMAGE}" =~ ^[^@]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: could not resolve an immutable sandbox image for ${SANDBOX_IMAGE_REQUEST}." >&2
  exit 2
fi
echo "Using Podman sandbox image: ${SANDBOX_RUNTIME_IMAGE} (ID ${SANDBOX_IMAGE_ID}, digest ${SANDBOX_IMAGE_DIGEST})"

PKI_DIR="${WORKDIR}/pki"
e2e_generate_pki "${GATEWAY_BIN}" "${PKI_DIR}" "host.containers.internal"
export OPENSHELL_E2E_GATEWAY_CA_CERT="${PKI_DIR}/ca.crt"

HOST_PORT=$(e2e_pick_port)
HEALTH_PORT=$(e2e_pick_port)
if [ "$(uname -s)" = "Darwin" ]; then
  # Podman Machine reserves IPv4 loopback for its callback-only listener.
  PRIMARY_BIND_IP="::1"
  CLI_ENDPOINT_HOST="localhost"
  HEALTH_ENDPOINT_HOST="[::1]"
else
  PRIMARY_BIND_IP="127.0.0.1"
  CLI_ENDPOINT_HOST="127.0.0.1"
  HEALTH_ENDPOINT_HOST="127.0.0.1"
fi
STATE_DIR="${WORKDIR}/state"
mkdir -p "${STATE_DIR}"
export XDG_STATE_HOME="${STATE_DIR}"
JWT_DIR="${STATE_DIR}/jwt"

E2E_NAMESPACE="e2e-podman-$$-${HOST_PORT}"
PODMAN_NETWORK_NAME="${E2E_NAMESPACE}"
ensure_e2e_podman_network "${PODMAN_NETWORK_NAME}"

export OPENSHELL_E2E_DRIVER="podman"
export OPENSHELL_E2E_NETWORK_NAME="${PODMAN_NETWORK_NAME}"
export OPENSHELL_E2E_SANDBOX_NAMESPACE="${E2E_NAMESPACE}"

echo "Starting openshell-gateway on port ${HOST_PORT} (namespace: ${E2E_NAMESPACE})..."
e2e_generate_gateway_jwt "${JWT_DIR}"

GATEWAY_CONFIG="${STATE_DIR}/gateway.toml"
e2e_write_podman_gateway_config \
  "${GATEWAY_CONFIG}" \
  "${CONFIG_SCHEMA_VERSION}" \
  "${ROOT}" \
  "${PKI_DIR}" \
  "${JWT_DIR}" \
  "openshell-e2e-podman-${HOST_PORT}" \
  "${OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER:-0}" \
  "${DRIVER_SOCKET}" \
  "${PODMAN_NETWORK_NAME}" \
  "${HOST_PORT}" \
  "${SANDBOX_RUNTIME_IMAGE}" \
  "${PODMAN_STOP_TIMEOUT_SECS}" \
  "${SUPERVISOR_RUNTIME_IMAGE}" \
  "${OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET:-}" \
  "${OPENSHELL_PODMAN_SOCKET:-}" \
  "${OIDC_MODE}" \
  "${OPENSHELL_OIDC_ISSUER:-}"
if [ -n "${OPENSHELL_PARITY_GATEWAY_CONFIG_CAPTURE:-}" ]; then
  cp "${GATEWAY_CONFIG}" "${OPENSHELL_PARITY_GATEWAY_CONFIG_CAPTURE}"
fi
if [ -n "${OPENSHELL_PARITY_LAUNCH_MANIFEST_CAPTURE:-}" ]; then
  driver_transport=in_tree
  if [ "${OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER:-0}" = "1" ]; then
    driver_transport=remote_uds
  fi
  printf '{"schema_version":%s,"external_compute_driver":%s,"compute_driver_transport":"%s","external_driver_pull_policy":"%s","supervisor_image":"%s","supervisor_image_id":"%s","supervisor_image_digest":"%s","supervisor_runtime_image":"%s","supervisor_base_image":"%s","supervisor_base_image_id":"%s","supervisor_base_image_digest":"%s","supervisor_package_manifest_sha256":"%s","sandbox_image_request":"%s","sandbox_image_id":"%s","sandbox_image_digest":"%s","sandbox_runtime_image":"%s"}\n' \
    "${CONFIG_SCHEMA_VERSION}" \
    "$([ "${OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER:-0}" = "1" ] && printf true || printf false)" \
    "${driver_transport}" \
    "${EXTERNAL_DRIVER_PULL_POLICY}" \
    "${SUPERVISOR_IMAGE}" \
    "${SUPERVISOR_IMAGE_ID}" \
    "${SUPERVISOR_IMAGE_DIGEST}" \
    "${SUPERVISOR_RUNTIME_IMAGE}" \
    "${SUPERVISOR_BASE_IMAGE}" \
    "${SUPERVISOR_BASE_IMAGE_ID}" \
    "${SUPERVISOR_BASE_IMAGE_DIGEST}" \
    "${SUPERVISOR_PACKAGE_MANIFEST_SHA256}" \
    "${SANDBOX_IMAGE_REQUEST}" \
    "${SANDBOX_IMAGE_ID}" \
    "${SANDBOX_IMAGE_DIGEST}" \
    "${SANDBOX_RUNTIME_IMAGE}" \
    >"${OPENSHELL_PARITY_LAUNCH_MANIFEST_CAPTURE}"
fi

if [ "${OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER:-0}" = "1" ]; then
  OPENSHELL_COMPUTE_DRIVER_SOCKET="${DRIVER_SOCKET}" \
  OPENSHELL_PODMAN_SOCKET="${OPENSHELL_PODMAN_SOCKET:-}" \
  OPENSHELL_SANDBOX_IMAGE="${SANDBOX_RUNTIME_IMAGE}" \
  OPENSHELL_SANDBOX_IMAGE_PULL_POLICY="${EXTERNAL_DRIVER_PULL_POLICY}" \
  OPENSHELL_HEALTH_CHECK_INTERVAL_SECS=10 \
  OPENSHELL_GATEWAY_PORT="${HOST_PORT}" \
  OPENSHELL_NETWORK_NAME="${PODMAN_NETWORK_NAME}" \
  OPENSHELL_STOP_TIMEOUT="${PODMAN_STOP_TIMEOUT_SECS}" \
  OPENSHELL_SUPERVISOR_IMAGE="${SUPERVISOR_RUNTIME_IMAGE}" \
  OPENSHELL_PODMAN_TLS_CA="${PKI_DIR}/ca.crt" \
  OPENSHELL_PODMAN_TLS_CERT="${PKI_DIR}/client/tls.crt" \
  OPENSHELL_PODMAN_TLS_KEY="${PKI_DIR}/client/tls.key" \
  OPENSHELL_ENABLE_BIND_MOUNTS=true \
    "${DRIVER_BIN}" >"${DRIVER_LOG}" 2>&1 &
  DRIVER_PID=$!
  e2e_wait_for_socket \
    "${DRIVER_SOCKET}" "${DRIVER_PID}" "external Podman compute driver"
fi

GATEWAY_ARGS=(
  --config "${GATEWAY_CONFIG}"
  # compute_driver comes from the RPM template. Override the loopback address
  # and port so Podman Machine can keep its IPv4 callback listener distinct.
  --bind-address "${PRIMARY_BIND_IP}"
  --port "${HOST_PORT}"
  --health-port "${HEALTH_PORT}"
  --tls-cert "${PKI_DIR}/server/tls.crt"
  --tls-key "${PKI_DIR}/server/tls.key"
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
  --log-level info
)

if [ "${OIDC_MODE}" = "1" ]; then
  GATEWAY_ARGS+=(
    --oidc-issuer "${OIDC_ISSUER}"
    --oidc-audience openshell-cli
    --oidc-scopes-claim scope
  )
else
  GATEWAY_ARGS+=(
    --tls-client-ca "${PKI_DIR}/ca.crt"
  )
fi

e2e_write_gateway_args_file "${GATEWAY_ARGS_FILE}" "${GATEWAY_ARGS[@]}"
e2e_export_gateway_restart_metadata \
  "${GATEWAY_BIN}" \
  "${GATEWAY_ARGS_FILE}" \
  "${GATEWAY_LOG}" \
  "${GATEWAY_PID_FILE}"

OPENSHELL_LOCAL_TLS_DIR="${PKI_DIR}" \
OPENSHELL_SUPERVISOR_IMAGE="${SUPERVISOR_RUNTIME_IMAGE}" \
OPENSHELL_NETWORK_NAME="${PODMAN_NETWORK_NAME}" \
  "${GATEWAY_BIN}" "${GATEWAY_ARGS[@]}" >"${GATEWAY_LOG}" 2>&1 &
GATEWAY_PID=$!
printf '%s\n' "${GATEWAY_PID}" >"${GATEWAY_PID_FILE}"

GATEWAY_NAME="openshell-e2e-podman-${HOST_PORT}"
if [ "${OIDC_MODE}" = "1" ]; then
  CLI_GATEWAY_ENDPOINT="https://${CLI_ENDPOINT_HOST}:${HOST_PORT}"
  export OPENSHELL_E2E_OIDC_GATEWAY_ENDPOINT="${CLI_GATEWAY_ENDPOINT}"
else
  CLI_GATEWAY_ENDPOINT="https://${CLI_ENDPOINT_HOST}:${HOST_PORT}"
  e2e_register_mtls_gateway \
    "${XDG_CONFIG_HOME}" \
    "${GATEWAY_NAME}" \
    "${CLI_GATEWAY_ENDPOINT}" \
    "${HOST_PORT}" \
    "${PKI_DIR}" \
    "${OPENSHELL_OIDC_ISSUER:-}"
fi

export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-300}"

if [ "${OIDC_MODE}" = "1" ] || [ -n "${OPENSHELL_OIDC_ISSUER:-}" ]; then
  export OPENSHELL_E2E_OIDC=1
  export OPENSHELL_E2E_OIDC_SCOPES=1
fi

echo "Waiting for gateway to become healthy..."
elapsed=0
timeout=120
while [ "${elapsed}" -lt "${timeout}" ]; do
  if ! kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo "ERROR: openshell-gateway exited before becoming healthy"
    exit 1
  fi
  # Keep this loopback probe direct even when ::1 is absent from NO_PROXY.
  if curl --noproxy '*' -sf "http://${HEALTH_ENDPOINT_HOST}:${HEALTH_PORT}/healthz" >/dev/null 2>&1; then
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
