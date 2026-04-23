#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone openshell-gateway backed by the bundled Docker compute
# driver for local manual testing.
#
# Defaults:
# - Plaintext HTTP on 127.0.0.1:18080
# - Dedicated sandbox namespace "docker-dev"
# - Persistent state under .cache/gateway-docker
#
# Common overrides:
#   OPENSHELL_SERVER_PORT=19080 mise run gateway:docker
#   OPENSHELL_SANDBOX_NAMESPACE=my-ns mise run gateway:docker
#   OPENSHELL_SANDBOX_IMAGE=ghcr.io/... mise run gateway:docker

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${OPENSHELL_SERVER_PORT:-18080}"
HEALTH_PORT="${OPENSHELL_HEALTH_PORT:-18081}"
STATE_DIR="${OPENSHELL_DOCKER_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-docker}"
SANDBOX_NAMESPACE="${OPENSHELL_SANDBOX_NAMESPACE:-docker-dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
SANDBOX_IMAGE_PULL_POLICY="${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-IfNotPresent}"
GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-http://host.openshell.internal:${PORT}}"
SSH_GATEWAY_HOST="${OPENSHELL_SSH_GATEWAY_HOST:-127.0.0.1}"
SSH_GATEWAY_PORT="${OPENSHELL_SSH_GATEWAY_PORT:-${PORT}}"
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

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker CLI is required" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon is not reachable" >&2
  exit 2
fi
if [[ "${PORT}" == "${HEALTH_PORT}" ]]; then
  echo "ERROR: OPENSHELL_SERVER_PORT and OPENSHELL_HEALTH_PORT must differ" >&2
  exit 2
fi

DAEMON_ARCH="$(normalize_arch "$(docker info --format '{{.Architecture}}' 2>/dev/null || true)")"
HOST_OS="$(uname -s)"
HOST_ARCH="$(normalize_arch "$(uname -m)")"
SUPERVISOR_TARGET="$(linux_target_triple "${DAEMON_ARCH}")"
SUPERVISOR_BIN="${ROOT}/target/${SUPERVISOR_TARGET}/debug/openshell-sandbox"

CARGO_BUILD_JOBS_ARG=()
if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
  CARGO_BUILD_JOBS_ARG=(-j "${CARGO_BUILD_JOBS}")
fi

echo "Building openshell-gateway..."
cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
  -p openshell-server --bin openshell-gateway

echo "Building openshell-sandbox for ${SUPERVISOR_TARGET}..."
rustup target add "${SUPERVISOR_TARGET}" >/dev/null 2>&1 || true
if [[ "${HOST_OS}" == "Linux" && "${HOST_ARCH}" == "${DAEMON_ARCH}" ]]; then
  cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
    -p openshell-sandbox --target "${SUPERVISOR_TARGET}"
else
  if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    cargo install --locked cargo-zigbuild
  fi
  cargo zigbuild ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
    -p openshell-sandbox --target "${SUPERVISOR_TARGET}"
fi

if [[ ! -f "${SUPERVISOR_BIN}" ]]; then
  echo "ERROR: expected supervisor binary at ${SUPERVISOR_BIN}" >&2
  exit 1
fi

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

echo "Starting standalone Docker gateway..."
echo "  endpoint: http://127.0.0.1:${PORT}"
echo "  health:   http://127.0.0.1:${HEALTH_PORT}/healthz"
echo "  namespace: ${SANDBOX_NAMESPACE}"
echo "  state dir: ${STATE_DIR}"
echo
echo "Example CLI commands:"
echo "  OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:${PORT} openshell status"
echo "  OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:${PORT} openshell sandbox create --name docker-smoke -- echo smoke-ok"
echo

exec "${GATEWAY_BIN}" \
  --port "${PORT}" \
  --health-port "${HEALTH_PORT}" \
  --log-level "${LOG_LEVEL}" \
  --drivers docker \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc" \
  --sandbox-namespace "${SANDBOX_NAMESPACE}" \
  --sandbox-image "${SANDBOX_IMAGE}" \
  --sandbox-image-pull-policy "${SANDBOX_IMAGE_PULL_POLICY}" \
  --grpc-endpoint "${GRPC_ENDPOINT}" \
  --docker-supervisor-bin "${SUPERVISOR_BIN}" \
  --ssh-handshake-secret "${SSH_HANDSHAKE_SECRET}" \
  --ssh-gateway-host "${SSH_GATEWAY_HOST}" \
  --ssh-gateway-port "${SSH_GATEWAY_PORT}"
