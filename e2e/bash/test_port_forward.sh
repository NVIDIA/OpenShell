#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Integration test for port forwarding through a sandbox.
#
# Prerequisites:
#   - A running nemoclaw cluster (nemoclaw cluster admin deploy)
#   - The `nemoclaw` binary on PATH (or set NAV_BIN)
#
# Usage:
#   ./e2e/bash/test_port_forward.sh

set -euo pipefail

###############################################################################
# Configuration
###############################################################################

# Resolve the nemoclaw binary: prefer NAV_BIN, then target/debug, then PATH.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ -n "${NAV_BIN:-}" ]]; then
  NAV="${NAV_BIN}"
elif [[ -x "${PROJECT_ROOT}/target/debug/nemoclaw" ]]; then
  NAV="${PROJECT_ROOT}/target/debug/nemoclaw"
else
  NAV="nemoclaw"
fi

FORWARD_PORT="${FORWARD_PORT:-19876}"
TIMEOUT_FORWARD="${TIMEOUT_FORWARD:-30}"
SANDBOX_NAME=""
FORWARD_PID=""
CREATE_PID=""

###############################################################################
# Helpers
###############################################################################

info()  { printf '==> %s\n' "$*" >&2; }
error() { printf 'ERROR: %s\n' "$*" >&2; }

# Strip ANSI escape codes from stdin.
strip_ansi() {
  sed $'s/\x1b\\[[0-9;]*m//g'
}

# Wait for a TCP port to accept connections.
wait_for_port() {
  local host=$1 port=$2 timeout=$3
  local i
  for i in $(seq 1 "${timeout}"); do
    if (echo >/dev/tcp/"${host}"/"${port}") 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Kill a process and all of its children.
kill_tree() {
  local pid=$1
  # Kill children first (best-effort).
  pkill -P "${pid}" 2>/dev/null || true
  kill "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  local exit_code=$?

  if [[ -n "${FORWARD_PID}" ]]; then
    info "Stopping port-forward (pid ${FORWARD_PID})"
    kill_tree "${FORWARD_PID}"
  fi

  if [[ -n "${CREATE_PID}" ]]; then
    info "Stopping sandbox create (pid ${CREATE_PID})"
    kill_tree "${CREATE_PID}"
  fi

  if [[ -n "${SANDBOX_NAME}" ]]; then
    info "Deleting sandbox ${SANDBOX_NAME}"
    "${NAV}" sandbox delete "${SANDBOX_NAME}" 2>/dev/null || true
  fi

  if [[ ${exit_code} -eq 0 ]]; then
    info "PASS"
  else
    error "FAIL (exit ${exit_code})"
  fi
  exit "${exit_code}"
}

trap cleanup EXIT

# Verify the test port is not already in use.
if (echo >/dev/tcp/127.0.0.1/"${FORWARD_PORT}") 2>/dev/null; then
  error "Port ${FORWARD_PORT} is already in use; choose a different FORWARD_PORT"
  exit 1
fi

###############################################################################
# Step 1 — Create a sandbox with a long-running TCP echo server.
#
# The echo server runs as the foreground process of `sandbox create --keep`.
# This ensures it stays alive for the duration of the test. We run the
# create command in the background and parse its output for the sandbox name.
###############################################################################

info "Creating sandbox with TCP echo server on port ${FORWARD_PORT}"

CREATE_LOG=$(mktemp)

"${NAV}" sandbox create --keep -- \
  python3 -c "
import socket, sys, signal, os
signal.signal(signal.SIGHUP, signal.SIG_IGN)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
port = ${FORWARD_PORT}
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', port))
sock.listen(1)
sock.settimeout(300)
print('echo-server-ready', flush=True)
try:
    while True:
        conn, _ = sock.accept()
        data = conn.recv(4096)
        if data:
            conn.sendall(b'echo:' + data)
        conn.close()
except (socket.timeout, OSError):
    pass
finally:
    sock.close()
" > "${CREATE_LOG}" 2>&1 &

CREATE_PID=$!

# Wait for the sandbox to be created and the echo server to start.
# We poll the log file for the sandbox name and the ready marker.
info "Waiting for sandbox to be ready"
for i in $(seq 1 120); do
  if [[ -f "${CREATE_LOG}" ]] && grep -q 'echo-server-ready' "${CREATE_LOG}" 2>/dev/null; then
    break
  fi
  if ! kill -0 "${CREATE_PID}" 2>/dev/null; then
    error "Sandbox create exited prematurely"
    cat "${CREATE_LOG}" >&2
    exit 1
  fi
  sleep 1
done

if ! grep -q 'echo-server-ready' "${CREATE_LOG}" 2>/dev/null; then
  error "Echo server did not become ready within 120s"
  cat "${CREATE_LOG}" >&2
  exit 1
fi

# Parse sandbox name from the create log.
SANDBOX_NAME=$(
  strip_ansi < "${CREATE_LOG}" | awk '/Name:/ { print $NF }'
)

if [[ -z "${SANDBOX_NAME}" ]]; then
  error "Could not parse sandbox name from create output"
  cat "${CREATE_LOG}" >&2
  exit 1
fi

info "Sandbox created: ${SANDBOX_NAME}"

###############################################################################
# Step 2 — Start port forwarding in the background.
###############################################################################

info "Starting port forward ${FORWARD_PORT} -> ${SANDBOX_NAME}"

"${NAV}" sandbox forward start "${FORWARD_PORT}" "${SANDBOX_NAME}" &
FORWARD_PID=$!

# Wait for the local port to become available.
info "Waiting for local port ${FORWARD_PORT} to open"
if ! wait_for_port 127.0.0.1 "${FORWARD_PORT}" "${TIMEOUT_FORWARD}"; then
  if ! kill -0 "${FORWARD_PID}" 2>/dev/null; then
    error "Port-forward process exited prematurely"
  else
    error "Local port ${FORWARD_PORT} did not open within ${TIMEOUT_FORWARD}s"
  fi
  exit 1
fi

info "Port ${FORWARD_PORT} is open"

# Give the SSH tunnel a moment to fully establish the direct-tcpip channel.
sleep 2

###############################################################################
# Step 3 — Send data through the forwarded port and verify the response.
#
# We retry a few times to handle transient tunnel setup delays.
###############################################################################

info "Sending test payload through forwarded port"

EXPECTED="echo:hello-nav"
RESPONSE_TRIMMED=""

for attempt in $(seq 1 5); do
  RESPONSE=$(
    python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(('127.0.0.1', ${FORWARD_PORT}))
    s.sendall(b'hello-nav\n')
    data = s.recv(4096)
    sys.stdout.write(data.decode())
except Exception:
    pass
finally:
    s.close()
" 2>/dev/null
  ) || true

  RESPONSE_TRIMMED=$(printf '%s' "${RESPONSE}" | tr -d '\r\n')

  if [[ "${RESPONSE_TRIMMED}" == "${EXPECTED}"* ]]; then
    break
  fi

  info "Attempt ${attempt}: no valid response yet, retrying in 2s..."
  sleep 2
done

if [[ "${RESPONSE_TRIMMED}" != "${EXPECTED}"* ]]; then
  error "Unexpected response: '${RESPONSE_TRIMMED}' (expected '${EXPECTED}')"
  exit 1
fi

info "Received expected response: '${RESPONSE_TRIMMED}'"

###############################################################################
# Cleanup is handled by the EXIT trap.
###############################################################################
