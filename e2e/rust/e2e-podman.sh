#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e smoke test against a Podman-backed gateway.
#
# Usage:
#   mise run e2e:podman                     # start a gateway with Podman driver
#   mise run e2e:podman -- --port=9090      # use a specific port
#
# Options:
#   --port=PORT   Gateway listen port (default: random free port).
#
# The script:
#   1. Verifies Podman is available and the socket is reachable
#   2. Starts openshell-gateway with --drivers podman --disable-tls
#   3. Waits for the gateway to become healthy
#   4. Runs the Rust smoke test
#   5. Cleans up the gateway process and any leftover sandbox containers
#
# Prerequisites:
#   - Rootless Podman service running (systemctl --user start podman.socket)
#   - Supervisor sideload image built (mise run build:docker:supervisor-sideload)
#   - Sandbox base image available locally

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"
TIMEOUT=120

# ── Parse arguments ──────────────────────────────────────────────────
PORT=""
for arg in "$@"; do
  case "$arg" in
    --port=*) PORT="${arg#--port=}" ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

if [ -z "${PORT}" ]; then
  PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
fi

# ── Pre-flight checks ───────────────────────────────────────────────

if ! command -v podman &>/dev/null; then
  echo "ERROR: podman is not installed or not in PATH"
  exit 1
fi

if ! podman info &>/dev/null; then
  echo "ERROR: podman service is not reachable. Start it with:"
  echo "  systemctl --user start podman.socket"
  exit 1
fi

if [ ! -f "${GATEWAY_BIN}" ]; then
  echo "Building openshell-gateway..."
  cargo build -p openshell-server --features openshell-core/dev-settings
fi

# ── Resolve images ───────────────────────────────────────────────────
# Use the same image defaults as the driver, allowing env overrides.
SUPERVISOR_IMAGE="${OPENSHELL_SUPERVISOR_IMAGE:-openshell/supervisor:dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-}"

# Verify the supervisor image exists locally.
if ! podman image exists "${SUPERVISOR_IMAGE}" 2>/dev/null; then
  echo "ERROR: supervisor image '${SUPERVISOR_IMAGE}' not found locally."
  echo "Build it with: mise run build:docker:supervisor-sideload"
  exit 1
fi

# ── Generate a unique handshake secret ───────────────────────────────
HANDSHAKE_SECRET="e2e-podman-$(head -c 16 /dev/urandom | xxd -p)"

# ── Start the gateway ────────────────────────────────────────────────
GW_LOG=$(mktemp /tmp/openshell-gw-podman-e2e.XXXXXX)
GW_PID=""

cleanup() {
  local exit_code=$?

  # Kill the gateway process.
  if [ -n "${GW_PID:-}" ] && kill -0 "${GW_PID}" 2>/dev/null; then
    echo "Stopping gateway (pid ${GW_PID})..."
    kill "${GW_PID}" 2>/dev/null || true
    wait "${GW_PID}" 2>/dev/null || true
  fi

  # Clean up any leftover sandbox containers, volumes, and secrets.
  echo "Cleaning up Podman resources..."
  for cid in $(podman ps -a --filter label=openshell.managed=true --format '{{.ID}}' 2>/dev/null); do
    podman rm -f "${cid}" 2>/dev/null || true
  done
  for vid in $(podman volume ls --filter label=openshell.managed=true --format '{{.Name}}' 2>/dev/null); do
    podman volume rm -f "${vid}" 2>/dev/null || true
  done
  # Secrets created by the driver use the openshell-handshake- prefix.
  for sid in $(podman secret ls --format '{{.Name}}' 2>/dev/null | grep '^openshell-handshake-'); do
    podman secret rm "${sid}" 2>/dev/null || true
  done

  if [ "${exit_code}" -ne 0 ] && [ -f "${GW_LOG}" ]; then
    echo "=== Gateway log (preserved for debugging) ==="
    cat "${GW_LOG}"
    echo "=== end gateway log ==="
  fi

  rm -f "${GW_LOG}" 2>/dev/null || true
}
trap cleanup EXIT

echo "Starting openshell-gateway on port ${PORT} with Podman driver..."

OPENSHELL_SSH_HANDSHAKE_SECRET="${HANDSHAKE_SECRET}" \
OPENSHELL_SUPERVISOR_IMAGE="${SUPERVISOR_IMAGE}" \
  "${GATEWAY_BIN}" \
    --port "${PORT}" \
    --drivers podman \
    --disable-tls \
    --db-url "sqlite::memory:" \
    ${SANDBOX_IMAGE:+--sandbox-image "${SANDBOX_IMAGE}"} \
    --log-level info \
  >"${GW_LOG}" 2>&1 &
GW_PID=$!

# ── Wait for health ─────────────────────────────────────────────────
echo "Waiting for gateway to become healthy (timeout ${TIMEOUT}s)..."
elapsed=0
healthy=false
while [ "${elapsed}" -lt "${TIMEOUT}" ]; do
  if ! kill -0 "${GW_PID}" 2>/dev/null; then
    echo "ERROR: gateway exited before becoming ready"
    cat "${GW_LOG}"
    exit 1
  fi

  # Use curl to check the gateway's gRPC health endpoint.
  # The gateway serves both gRPC and HTTP on the same port.
  if curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    healthy=true
    break
  fi

  sleep 2
  elapsed=$((elapsed + 2))
done

if [ "${healthy}" != "true" ]; then
  echo "ERROR: gateway did not become healthy after ${TIMEOUT}s"
  cat "${GW_LOG}"
  exit 1
fi
echo "Gateway is ready (${elapsed}s)."

# ── Run the smoke test ───────────────────────────────────────────────
export OPENSHELL_GATEWAY_ENDPOINT="http://127.0.0.1:${PORT}"
# Use a synthetic gateway name so the CLI does not require stored mTLS creds.
export OPENSHELL_GATEWAY="e2e-podman"
export OPENSHELL_PROVISION_TIMEOUT=300

echo "Running e2e smoke test (gateway: ${OPENSHELL_GATEWAY}, endpoint: ${OPENSHELL_GATEWAY_ENDPOINT})..."
cargo build -p openshell-cli --features openshell-core/dev-settings
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e --test smoke -- --nocapture

echo "Smoke test passed."
