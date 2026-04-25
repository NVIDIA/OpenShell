#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone openshell-gateway backed by the bundled Docker compute
# driver for local manual testing.
#
# Defaults:
# - Plaintext HTTP on 127.0.0.1:18080 (falls back to a free port if occupied)
# - No dedicated health listener unless OPENSHELL_HEALTH_PORT is set
# - Dedicated sandbox namespace "docker-dev"
# - Persistent state under .cache/gateway-docker
#
# Common overrides:
#   OPENSHELL_SERVER_PORT=19080 mise run gateway:docker
#   OPENSHELL_SANDBOX_NAMESPACE=my-ns mise run gateway:docker
#   OPENSHELL_SANDBOX_IMAGE=ghcr.io/... mise run gateway:docker

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEFAULT_PORT=18080
PORT="${OPENSHELL_SERVER_PORT:-${DEFAULT_PORT}}"
HEALTH_PORT="${OPENSHELL_HEALTH_PORT:-}"
STATE_DIR="${OPENSHELL_DOCKER_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-docker}"
SANDBOX_NAMESPACE="${OPENSHELL_SANDBOX_NAMESPACE:-docker-dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
SANDBOX_IMAGE_PULL_POLICY="${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-IfNotPresent}"
SSH_GATEWAY_HOST="${OPENSHELL_SSH_GATEWAY_HOST:-127.0.0.1}"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
SECRET_FILE="${STATE_DIR}/ssh-handshake-secret"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"

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

pick_random_port() {
  local lower=20000
  local upper=60999
  local attempts=256
  local port

  for _ in $(seq 1 "${attempts}"); do
    port=$((RANDOM % (upper - lower + 1) + lower))
    if ! port_is_in_use "${port}"; then
      echo "${port}"
      return 0
    fi
  done

  echo "ERROR: could not find a free port after ${attempts} attempts" >&2
  exit 2
}

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker CLI is required" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon is not reachable" >&2
  exit 2
fi

PORT_WAS_DEFAULT=1
if [[ -n "${OPENSHELL_SERVER_PORT:-}" ]]; then
  PORT_WAS_DEFAULT=0
fi

PORT_AUTO_SELECTED=0

if [[ "${PORT_WAS_DEFAULT}" == "0" ]] && port_is_in_use "${PORT}"; then
  echo "ERROR: OPENSHELL_SERVER_PORT ${PORT} is already in use" >&2
  exit 2
fi
if [[ "${PORT_WAS_DEFAULT}" == "1" ]] && port_is_in_use "${PORT}"; then
  PORT="$(pick_random_port)"
  PORT_AUTO_SELECTED=1
fi

if [[ -n "${HEALTH_PORT}" ]] && [[ "${HEALTH_PORT}" != "0" ]] && port_is_in_use "${HEALTH_PORT}"; then
  echo "ERROR: OPENSHELL_HEALTH_PORT ${HEALTH_PORT} is already in use" >&2
  exit 2
fi
if [[ -n "${HEALTH_PORT}" ]] && [[ "${HEALTH_PORT}" != "0" ]] && [[ "${PORT}" == "${HEALTH_PORT}" ]]; then
  echo "ERROR: OPENSHELL_SERVER_PORT and OPENSHELL_HEALTH_PORT must differ" >&2
  exit 2
fi

GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-http://host.openshell.internal:${PORT}}"
SSH_GATEWAY_PORT="${OPENSHELL_SSH_GATEWAY_PORT:-${PORT}}"

DAEMON_ARCH="$(normalize_arch "$(docker info --format '{{.Architecture}}' 2>/dev/null || true)")"
HOST_OS="$(uname -s)"
HOST_ARCH="$(normalize_arch "$(uname -m)")"
SUPERVISOR_TARGET="$(linux_target_triple "${DAEMON_ARCH}")"
# Cache the supervisor binary alongside the gateway state. Reuses the same
# Docker pipeline that builds the cluster supervisor image, so the cross-
# compile happens inside Linux containers — sidestepping macOS's per-process
# file-descriptor cap that breaks zig/ld for this many rlibs.
SUPERVISOR_OUT_DIR="${STATE_DIR}/supervisor/${DAEMON_ARCH}"
SUPERVISOR_BIN="${SUPERVISOR_OUT_DIR}/openshell-sandbox"

CARGO_BUILD_JOBS_ARG=()
if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
  CARGO_BUILD_JOBS_ARG=(-j "${CARGO_BUILD_JOBS}")
fi

echo "Building openshell-gateway..."
cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
  -p openshell-server --bin openshell-gateway

echo "Building openshell-sandbox for ${SUPERVISOR_TARGET}..."
if [[ "${HOST_OS}" == "Linux" && "${HOST_ARCH}" == "${DAEMON_ARCH}" ]]; then
  # Native Linux build — no cross-toolchain required.
  rustup target add "${SUPERVISOR_TARGET}" >/dev/null 2>&1 || true
  cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
    -p openshell-sandbox --target "${SUPERVISOR_TARGET}"
  CARGO_SUPERVISOR_BIN="${ROOT}/target/${SUPERVISOR_TARGET}/debug/openshell-sandbox"
  mkdir -p "${SUPERVISOR_OUT_DIR}"
  cp "${CARGO_SUPERVISOR_BIN}" "${SUPERVISOR_BIN}"
else
  # Cross-compile via the existing Docker pipeline. The supervisor-output
  # stage in deploy/docker/Dockerfile.images extracts just the openshell-
  # sandbox binary, with the actual link happening inside Linux containers
  # where FD limits are not a problem.
  #
  # This task is gated on a working Docker daemon above, so pin the
  # container-engine helper to docker — otherwise it auto-detects podman
  # whenever the binary happens to be on PATH.
  mkdir -p "${SUPERVISOR_OUT_DIR}"
  CONTAINER_ENGINE=docker \
  DOCKER_PLATFORM="linux/${DAEMON_ARCH}" \
  DOCKER_OUTPUT="type=local,dest=${SUPERVISOR_OUT_DIR}" \
    bash "${ROOT}/tasks/scripts/docker-build-image.sh" supervisor-output
fi

if [[ ! -f "${SUPERVISOR_BIN}" ]]; then
  echo "ERROR: expected supervisor binary at ${SUPERVISOR_BIN}" >&2
  exit 1
fi
chmod +x "${SUPERVISOR_BIN}"

mkdir -p "${STATE_DIR}"
if [[ ! -f "${SECRET_FILE}" ]]; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl is required to generate the SSH handshake secret" >&2
    exit 2
  fi
  openssl rand -hex 32 > "${SECRET_FILE}"
  chmod 600 "${SECRET_FILE}" 2>/dev/null || true
fi
SSH_HANDSHAKE_SECRET="$(tr -d '\n' < "${SECRET_FILE}")"

if [[ "${PORT_AUTO_SELECTED}" == "1" ]]; then
  echo "Default port ${DEFAULT_PORT} is in use; using ${PORT} instead."
fi

echo "Starting standalone Docker gateway..."
echo "  endpoint: http://127.0.0.1:${PORT}"
if [[ -n "${HEALTH_PORT}" ]] && [[ "${HEALTH_PORT}" != "0" ]]; then
  echo "  health:   http://127.0.0.1:${HEALTH_PORT}/healthz"
fi
echo "  namespace: ${SANDBOX_NAMESPACE}"
echo "  state dir: ${STATE_DIR}"
echo
echo "Example CLI commands:"
echo "  OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:${PORT} openshell status"
echo "  OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:${PORT} openshell sandbox create --name docker-smoke -- echo smoke-ok"
echo

ARGS=(
  --port "${PORT}"
  --log-level "${LOG_LEVEL}"
  --drivers docker
  --disable-tls
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
  --sandbox-namespace "${SANDBOX_NAMESPACE}"
  --sandbox-image "${SANDBOX_IMAGE}"
  --sandbox-image-pull-policy "${SANDBOX_IMAGE_PULL_POLICY}"
  --grpc-endpoint "${GRPC_ENDPOINT}"
  --docker-supervisor-bin "${SUPERVISOR_BIN}"
  --ssh-handshake-secret "${SSH_HANDSHAKE_SECRET}"
  --ssh-gateway-host "${SSH_GATEWAY_HOST}"
  --ssh-gateway-port "${SSH_GATEWAY_PORT}"
)

if [[ -n "${HEALTH_PORT}" ]] && [[ "${HEALTH_PORT}" != "0" ]]; then
  ARGS+=(--health-port "${HEALTH_PORT}")
fi

exec "${GATEWAY_BIN}" \
  "${ARGS[@]}"
