#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e smoke test against a standalone gateway running the
# bundled Docker compute driver.
#
# Unlike the Kubernetes driver (which deploys a k3s cluster) or the VM
# driver (which boots libkrun), the Docker driver runs in-process inside
# the gateway binary and uses the local Docker daemon to run sandbox
# containers. This script:
#
#   1. Builds openshell-gateway, openshell-cli, and a Linux ELF
#      openshell-sandbox binary (cross-compiled so it can run inside
#      Docker containers on macOS hosts).
#   2. Ensures the supervisor image (openshell/supervisor:dev) exists
#      locally — the sandbox containers launch from it, with the
#      cross-compiled openshell-sandbox binary bind-mounted over the
#      image-provided copy.
#   3. Generates an ephemeral mTLS PKI (CA, server cert, client cert).
#   4. Starts openshell-gateway with --drivers=docker, binding to a
#      random free host port.
#   5. Installs the client cert into the CLI gateway config dir and
#      runs the Rust smoke test.
#   6. Tears the gateway process down on exit.
#
# Usage: mise run e2e:docker

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d "/tmp/openshell-e2e-docker.XXXXXX")"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"
CLI_BIN="${ROOT}/target/debug/openshell"
STATE_DIR=""
GATEWAY_CONFIG_DIR=""
GATEWAY_PID=""
GATEWAY_LOG="${WORKDIR}/gateway.log"

cleanup() {
  local exit_code=$?
  if [ -n "${GATEWAY_PID}" ] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo "Stopping openshell-gateway (pid ${GATEWAY_PID})..."
    kill "${GATEWAY_PID}" 2>/dev/null || true
    wait "${GATEWAY_PID}" 2>/dev/null || true
  fi

  # Remove any lingering sandbox containers the gateway failed to clean
  # up. The driver labels its containers with openshell.ai/managed-by.
  if command -v docker >/dev/null 2>&1; then
    local stale
    stale=$(docker ps -aq --filter "label=openshell.ai/managed-by=openshell" 2>/dev/null || true)
    if [ -n "${stale}" ]; then
      # shellcheck disable=SC2086
      docker rm -f ${stale} >/dev/null 2>&1 || true
    fi
  fi

  if [ "${exit_code}" -ne 0 ] && [ -f "${GATEWAY_LOG}" ]; then
    echo "=== gateway log (preserved for debugging) ==="
    cat "${GATEWAY_LOG}"
    echo "=== end gateway log ==="
  fi

  # Remove gateway CLI config we created so repeated runs don't
  # accumulate stale gateway entries.
  if [ -n "${GATEWAY_CONFIG_DIR}" ] && [ -d "${GATEWAY_CONFIG_DIR}" ]; then
    rm -rf "${GATEWAY_CONFIG_DIR}"
  fi

  rm -rf "${WORKDIR}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Preflight ────────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker CLI is required to run e2e:docker" >&2
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

# Detect Linux arch of the Docker daemon so we build the matching
# openshell-sandbox binary.
DAEMON_ARCH=$(docker info --format '{{.Architecture}}' 2>/dev/null || true)
case "${DAEMON_ARCH}" in
  aarch64|arm64) SUPERVISOR_TARGET="aarch64-unknown-linux-gnu" ;;
  x86_64|amd64)  SUPERVISOR_TARGET="x86_64-unknown-linux-gnu" ;;
  *)
    echo "ERROR: unsupported Docker daemon architecture '${DAEMON_ARCH}'" >&2
    exit 2
    ;;
esac
SUPERVISOR_BIN="${ROOT}/target/${SUPERVISOR_TARGET}/release/openshell-sandbox"

# ── Build binaries ───────────────────────────────────────────────────
echo "Building openshell-gateway and openshell-cli..."
cargo build -p openshell-server --bin openshell-gateway
cargo build -p openshell-cli --features openshell-core/dev-settings

echo "Cross-compiling openshell-sandbox for ${SUPERVISOR_TARGET}..."
if ! command -v cargo-zigbuild >/dev/null 2>&1; then
  cargo install --locked cargo-zigbuild
fi
rustup target add "${SUPERVISOR_TARGET}" >/dev/null 2>&1 || true
cargo zigbuild --release -p openshell-sandbox --target "${SUPERVISOR_TARGET}"

if [ ! -f "${SUPERVISOR_BIN}" ]; then
  echo "ERROR: expected supervisor binary at ${SUPERVISOR_BIN}" >&2
  exit 1
fi

# ── Ensure supervisor image is available locally ─────────────────────
SANDBOX_IMAGE="${OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE:-openshell/supervisor:dev}"
if ! docker image inspect "${SANDBOX_IMAGE}" >/dev/null 2>&1; then
  echo "Building ${SANDBOX_IMAGE}..."
  mise run build:docker:supervisor
fi

# ── Generate ephemeral mTLS PKI ──────────────────────────────────────
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

# ── Pick free ports ──────────────────────────────────────────────────
pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}
HOST_PORT=$(pick_port)
HEALTH_PORT=$(pick_port)
while [ "${HEALTH_PORT}" = "${HOST_PORT}" ]; do
  HEALTH_PORT=$(pick_port)
done

STATE_DIR="${WORKDIR}/state"
mkdir -p "${STATE_DIR}"

SSH_HANDSHAKE_SECRET=$(openssl rand -hex 32)

# Containers started by the docker driver reach the host gateway via
# host.openshell.internal (mapped to host-gateway by the driver). The
# gateway itself binds to 0.0.0.0:${HOST_PORT}.
GATEWAY_ENDPOINT="https://host.openshell.internal:${HOST_PORT}"

echo "Starting openshell-gateway on port ${HOST_PORT} (health :${HEALTH_PORT})..."
# shellcheck disable=SC2086
"${GATEWAY_BIN}" \
  --port "${HOST_PORT}" \
  --health-port "${HEALTH_PORT}" \
  --drivers docker \
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
  --sandbox-image-pull-policy IfNotPresent \
  --ssh-handshake-secret "${SSH_HANDSHAKE_SECRET}" \
  --ssh-gateway-host 127.0.0.1 \
  --ssh-gateway-port "${HOST_PORT}" \
  >"${GATEWAY_LOG}" 2>&1 &
GATEWAY_PID=$!

# ── Install mTLS material for the CLI ────────────────────────────────
GATEWAY_NAME="openshell-e2e-docker-${HOST_PORT}"
GATEWAY_CONFIG_DIR="${HOME}/.config/openshell/gateways/${GATEWAY_NAME}"
mkdir -p "${GATEWAY_CONFIG_DIR}/mtls"
cp "${PKI_DIR}/ca.crt"     "${GATEWAY_CONFIG_DIR}/mtls/ca.crt"
cp "${PKI_DIR}/client.crt" "${GATEWAY_CONFIG_DIR}/mtls/tls.crt"
cp "${PKI_DIR}/client.key" "${GATEWAY_CONFIG_DIR}/mtls/tls.key"

export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
export OPENSHELL_GATEWAY_ENDPOINT="https://127.0.0.1:${HOST_PORT}"
export OPENSHELL_PROVISION_TIMEOUT=180

# ── Wait for gateway readiness ───────────────────────────────────────
echo "Waiting for gateway to become healthy..."
elapsed=0
timeout=120
while [ "${elapsed}" -lt "${timeout}" ]; do
  if ! kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo "ERROR: openshell-gateway exited before becoming healthy"
    exit 1
  fi
  if "${CLI_BIN}" status >/dev/null 2>&1; then
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

# ── Run the smoke test ───────────────────────────────────────────────
echo "Running e2e smoke test (gateway: ${OPENSHELL_GATEWAY}, endpoint: ${OPENSHELL_GATEWAY_ENDPOINT})..."
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e --test smoke -- --nocapture

echo "Smoke test passed."
