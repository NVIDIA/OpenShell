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

set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: e2e/with-docker-gateway.sh <command> [args...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cargo_target_dir() {
  if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    case "${CARGO_TARGET_DIR}" in
      /*) printf '%s\n' "${CARGO_TARGET_DIR}" ;;
      *) printf '%s\n' "${ROOT}/${CARGO_TARGET_DIR}" ;;
    esac
    return 0
  fi

  cargo metadata --format-version=1 --no-deps \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
}

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
WORKDIR_PARENT="${WORKDIR_PARENT%/}"
WORKDIR="$(mktemp -d "${WORKDIR_PARENT}/openshell-e2e-gateway.XXXXXX")"
GATEWAY_BIN=""
CLI_BIN=""
GATEWAY_PID=""
GATEWAY_LOG="${WORKDIR}/gateway.log"
GATEWAY_PID_FILE="${WORKDIR}/gateway.pid"
GATEWAY_ARGS_FILE="${WORKDIR}/gateway.args"
GATEWAY_CONFIG_DIR=""
E2E_NAMESPACE=""
DOCKER_NETWORK_NAME=""
DOCKER_NETWORK_CONNECTED_CONTAINER=""
DOCKER_NETWORK_MANAGED=0
GPU_MODE="${OPENSHELL_E2E_DOCKER_GPU:-0}"

# Isolate CLI/SDK gateway metadata from the developer's real config.
export XDG_CONFIG_HOME="${WORKDIR}/config"

cleanup() {
  local exit_code=$?

  local gateway_pid="${GATEWAY_PID}"
  if [ -f "${GATEWAY_PID_FILE}" ]; then
    gateway_pid="$(cat "${GATEWAY_PID_FILE}" 2>/dev/null || true)"
  fi
  if [ -n "${gateway_pid}" ] && kill -0 "${gateway_pid}" 2>/dev/null; then
    echo "Stopping openshell-gateway (pid ${gateway_pid})..."
    kill "${gateway_pid}" 2>/dev/null || true
    wait "${gateway_pid}" 2>/dev/null || true
  fi

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

  if [ "${exit_code}" -ne 0 ] && [ -f "${GATEWAY_LOG}" ]; then
    echo "=== gateway log (preserved for debugging) ==="
    cat "${GATEWAY_LOG}"
    echo "=== end gateway log ==="
  fi

  rm -rf "${WORKDIR}" 2>/dev/null || true
}
trap cleanup EXIT

register_plaintext_gateway() {
  local name=$1
  local endpoint=$2
  local port=$3

  GATEWAY_CONFIG_DIR="${XDG_CONFIG_HOME}/openshell/gateways/${name}"
  mkdir -p "${GATEWAY_CONFIG_DIR}"
  cat >"${GATEWAY_CONFIG_DIR}/metadata.json" <<EOF
{
  "name": "${name}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${port},
  "auth_mode": "plaintext"
}
EOF
  printf '%s' "${name}" >"${XDG_CONFIG_HOME}/openshell/active_gateway"
}

register_mtls_gateway() {
  local name=$1
  local endpoint=$2
  local port=$3
  local pki_dir=$4

  GATEWAY_CONFIG_DIR="${XDG_CONFIG_HOME}/openshell/gateways/${name}"
  mkdir -p "${GATEWAY_CONFIG_DIR}/mtls"
  cp "${pki_dir}/ca.crt"     "${GATEWAY_CONFIG_DIR}/mtls/ca.crt"
  cp "${pki_dir}/client.crt" "${GATEWAY_CONFIG_DIR}/mtls/tls.crt"
  cp "${pki_dir}/client.key" "${GATEWAY_CONFIG_DIR}/mtls/tls.key"
  cat >"${GATEWAY_CONFIG_DIR}/metadata.json" <<EOF
{
  "name": "${name}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${port}
}
EOF
  printf '%s' "${name}" >"${XDG_CONFIG_HOME}/openshell/active_gateway"
}

endpoint_port() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlparse

parsed = urlparse(sys.argv[1])
print(parsed.port or (443 if parsed.scheme == "https" else 80))
PY
}

pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}

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
  register_plaintext_gateway "${GATEWAY_NAME}" "${OPENSHELL_GATEWAY_ENDPOINT}" "$(endpoint_port "${OPENSHELL_GATEWAY_ENDPOINT}")"
  export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
  export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-180}"

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
if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is required to generate ephemeral PKI" >&2
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

normalize_arch() {
  case "$1" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "$1" ;;
  esac
}

linux_target_triple() {
  case "$1" in
    amd64) echo "x86_64-unknown-linux-gnu" ;;
    arm64) echo "aarch64-unknown-linux-gnu" ;;
    *)
      echo "ERROR: unsupported Docker daemon architecture '$1'" >&2
      exit 2
      ;;
  esac
}

DAEMON_ARCH="$(normalize_arch "$(docker info --format '{{.Architecture}}' 2>/dev/null || true)")"
SUPERVISOR_TARGET="$(linux_target_triple "${DAEMON_ARCH}")"
HOST_OS="$(uname -s)"
HOST_ARCH="$(normalize_arch "$(uname -m)")"
SUPERVISOR_OUT_DIR="${WORKDIR}/supervisor/${DAEMON_ARCH}"
SUPERVISOR_BIN="${SUPERVISOR_OUT_DIR}/openshell-sandbox"

CARGO_BUILD_JOBS_ARG=()
if [ -n "${CARGO_BUILD_JOBS:-}" ]; then
  CARGO_BUILD_JOBS_ARG=(-j "${CARGO_BUILD_JOBS}")
fi

TARGET_DIR="$(cargo_target_dir)"
GATEWAY_BIN="${TARGET_DIR}/debug/openshell-gateway"
CLI_BIN="${TARGET_DIR}/debug/openshell"

echo "Building openshell-gateway..."
cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
  -p openshell-server --bin openshell-gateway \
  --features openshell-core/dev-settings

echo "Building openshell-cli..."
cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
  -p openshell-cli --bin openshell \
  --features openshell-core/dev-settings

if [ ! -x "${GATEWAY_BIN}" ]; then
  echo "ERROR: expected openshell-gateway binary at ${GATEWAY_BIN}" >&2
  exit 1
fi
if [ ! -x "${CLI_BIN}" ]; then
  echo "ERROR: expected openshell CLI binary at ${CLI_BIN}" >&2
  exit 1
fi

echo "Building openshell-sandbox for ${SUPERVISOR_TARGET}..."
mkdir -p "${SUPERVISOR_OUT_DIR}"
if [ "${HOST_OS}" = "Linux" ] && [ "${HOST_ARCH}" = "${DAEMON_ARCH}" ]; then
  rustup target add "${SUPERVISOR_TARGET}" >/dev/null 2>&1 || true
  cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
    --release -p openshell-sandbox --target "${SUPERVISOR_TARGET}"
  cp "${TARGET_DIR}/${SUPERVISOR_TARGET}/release/openshell-sandbox" "${SUPERVISOR_BIN}"
else
  CONTAINER_ENGINE=docker \
  DOCKER_PLATFORM="linux/${DAEMON_ARCH}" \
  DOCKER_OUTPUT="type=local,dest=${SUPERVISOR_OUT_DIR}" \
    bash "${ROOT}/tasks/scripts/docker-build-image.sh" supervisor-output
fi

if [ ! -f "${SUPERVISOR_BIN}" ]; then
  echo "ERROR: expected supervisor binary at ${SUPERVISOR_BIN}" >&2
  exit 1
fi
chmod +x "${SUPERVISOR_BIN}"

DEFAULT_SANDBOX_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
SANDBOX_IMAGE="${OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE:-${OPENSHELL_SANDBOX_IMAGE:-${DEFAULT_SANDBOX_IMAGE}}}"
if ! docker image inspect "${SANDBOX_IMAGE}" >/dev/null 2>&1; then
  echo "Pulling ${SANDBOX_IMAGE}..."
  docker pull "${SANDBOX_IMAGE}"
fi

PKI_DIR="${WORKDIR}/pki"
mkdir -p "${PKI_DIR}"
cd "${PKI_DIR}"

cat > openssl.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = openshell-server
[san_server]
subjectAltName = @alt_server
[alt_server]
DNS.1 = localhost
DNS.2 = host.openshell.internal
DNS.3 = host.docker.internal
IP.1 = 127.0.0.1
IP.2 = ::1
[san_client]
subjectAltName = DNS:openshell-client
EOF

openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout ca.key -out ca.crt -subj "/CN=openshell-e2e-ca" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -config openssl.cnf >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 30 -extfile openssl.cnf -extensions san_server >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=openshell-client" >/dev/null 2>&1
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 30 -extfile openssl.cnf -extensions san_client >/dev/null 2>&1

cd "${ROOT}"

HOST_PORT=$(pick_port)
STATE_DIR="${WORKDIR}/state"
mkdir -p "${STATE_DIR}"

GATEWAY_ENDPOINT="https://host.openshell.internal:${HOST_PORT}"
E2E_NAMESPACE="e2e-docker-$$-${HOST_PORT}"
DOCKER_NETWORK_NAME="${E2E_NAMESPACE}"
GATEWAY_HOST_ALIAS_IP=""

ensure_e2e_docker_network "${DOCKER_NETWORK_NAME}"
export OPENSHELL_E2E_DOCKER_NETWORK_NAME="${DOCKER_NETWORK_NAME}"
if connect_current_container_to_docker_network "${DOCKER_NETWORK_NAME}"; then
  echo "Connected CI job container to Docker network ${DOCKER_NETWORK_NAME} (${GATEWAY_HOST_ALIAS_IP})."
else
  GATEWAY_HOST_ALIAS_IP=""
fi

echo "Starting openshell-gateway on port ${HOST_PORT} (namespace: ${E2E_NAMESPACE})..."
GATEWAY_ARGS=(
  --bind-address 0.0.0.0 \
  --port "${HOST_PORT}" \
  --drivers docker \
  --sandbox-namespace "${E2E_NAMESPACE}" \
  --docker-network-name "${DOCKER_NETWORK_NAME}" \
  --tls-cert "${PKI_DIR}/server.crt" \
  --tls-key "${PKI_DIR}/server.key" \
  --tls-client-ca "${PKI_DIR}/ca.crt" \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc" \
  --grpc-endpoint "${GATEWAY_ENDPOINT}" \
  --docker-supervisor-bin "${SUPERVISOR_BIN}" \
  --docker-tls-ca "${PKI_DIR}/ca.crt" \
  --docker-tls-cert "${PKI_DIR}/client.crt" \
  --docker-tls-key "${PKI_DIR}/client.key" \
  --sandbox-image "${SANDBOX_IMAGE}" \
  --sandbox-image-pull-policy IfNotPresent
)
if [ -n "${GATEWAY_HOST_ALIAS_IP}" ]; then
  GATEWAY_ARGS+=(--host-gateway-ip "${GATEWAY_HOST_ALIAS_IP}")
fi

: >"${GATEWAY_ARGS_FILE}"
for arg in "${GATEWAY_ARGS[@]}"; do
  printf '%s\0' "${arg}" >>"${GATEWAY_ARGS_FILE}"
done
export OPENSHELL_E2E_GATEWAY_BIN="${GATEWAY_BIN}"
export OPENSHELL_E2E_GATEWAY_ARGS_FILE="${GATEWAY_ARGS_FILE}"
export OPENSHELL_E2E_GATEWAY_LOG="${GATEWAY_LOG}"
export OPENSHELL_E2E_GATEWAY_PID_FILE="${GATEWAY_PID_FILE}"

"${GATEWAY_BIN}" "${GATEWAY_ARGS[@]}" >"${GATEWAY_LOG}" 2>&1 &
GATEWAY_PID=$!
printf '%s\n' "${GATEWAY_PID}" >"${GATEWAY_PID_FILE}"

GATEWAY_NAME="openshell-e2e-docker-${HOST_PORT}"
CLI_GATEWAY_ENDPOINT="https://127.0.0.1:${HOST_PORT}"
register_mtls_gateway "${GATEWAY_NAME}" "${CLI_GATEWAY_ENDPOINT}" "${HOST_PORT}" "${PKI_DIR}"

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
