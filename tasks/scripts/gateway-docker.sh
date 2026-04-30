#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone openshell-gateway backed by the Docker compute driver for
# local manual testing.
#
# Defaults:
# - Plaintext HTTP on 127.0.0.1:18080
# - Dedicated sandbox namespace "docker-dev"
# - Persistent state under .cache/gateway-docker
#
# Common overrides:
#   OPENSHELL_SERVER_PORT=19080 mise run gateway:docker
#   OPENSHELL_DOCKER_GATEWAY_NAME=my-docker-gateway mise run gateway:docker
#   OPENSHELL_SANDBOX_NAMESPACE=my-ns mise run gateway:docker
#   OPENSHELL_SANDBOX_IMAGE=ghcr.io/... mise run gateway:docker
#
# After the gateway is running, point the CLI at it with either:
#   openshell --gateway docker-dev <command>
#   openshell gateway use docker-dev   # then plain `openshell <command>`

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${OPENSHELL_SERVER_PORT:-18080}"
GATEWAY_NAME="${OPENSHELL_DOCKER_GATEWAY_NAME:-docker-dev}"
STATE_DIR="${OPENSHELL_DOCKER_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-docker}"
SANDBOX_NAMESPACE="${OPENSHELL_SANDBOX_NAMESPACE:-docker-dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
SANDBOX_IMAGE_PULL_POLICY="${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-IfNotPresent}"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
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
}

if [[ ! "${GATEWAY_NAME}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: OPENSHELL_DOCKER_GATEWAY_NAME must contain only letters, numbers, dots, underscores, or dashes" >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker CLI is required" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon is not reachable" >&2
  exit 2
fi

if port_is_in_use "${PORT}"; then
  echo "ERROR: port ${PORT} is already in use; free it or set OPENSHELL_SERVER_PORT" >&2
  exit 2
fi

GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-http://host.openshell.internal:${PORT}}"

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
  mkdir -p "${SUPERVISOR_OUT_DIR}"
  cp "${ROOT}/target/${SUPERVISOR_TARGET}/debug/openshell-sandbox" "${SUPERVISOR_BIN}"
else
  # Cross-compile through the prebuilt-binary staging helper, then use the
  # supervisor stage to extract just the openshell-sandbox binary.
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

GATEWAY_ENDPOINT="http://127.0.0.1:${PORT}"
register_gateway_metadata "${GATEWAY_NAME}" "${GATEWAY_ENDPOINT}" "${PORT}"

echo "Starting standalone Docker gateway..."
echo "  gateway:   ${GATEWAY_NAME}"
echo "  endpoint:  ${GATEWAY_ENDPOINT}"
echo "  namespace: ${SANDBOX_NAMESPACE}"
echo "  state dir: ${STATE_DIR}"
echo
echo "Point the CLI at this gateway with one of:"
echo "  openshell --gateway ${GATEWAY_NAME} status"
echo "  openshell gateway select ${GATEWAY_NAME}"
echo

exec "${GATEWAY_BIN}" \
  --port "${PORT}" \
  --log-level "${LOG_LEVEL}" \
  --drivers docker \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc" \
  --sandbox-namespace "${SANDBOX_NAMESPACE}" \
  --sandbox-image "${SANDBOX_IMAGE}" \
  --sandbox-image-pull-policy "${SANDBOX_IMAGE_PULL_POLICY}" \
  --grpc-endpoint "${GRPC_ENDPOINT}" \
  --docker-supervisor-bin "${SUPERVISOR_BIN}"
