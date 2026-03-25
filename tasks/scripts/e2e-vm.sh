#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e smoke test against an openshell-vm gateway.
#
# Usage:
#   mise run e2e:vm                                          # start new named VM on random port
#   mise run e2e:vm -- --vm-port=30051                       # reuse existing VM on port 30051
#   mise run e2e:vm -- --vm-port=30051 --vm-name=my-vm       # reuse existing named VM and run exec check
#
# Options:
#   --vm-port=PORT  Skip VM startup and test against this port.
#   --vm-name=NAME  VM instance name. Auto-generated for fresh VMs.
#
# When --vm-port is omitted:
#   1. Picks a random free host port
#   2. Starts the VM with --name <auto> --port <random>:30051
#   3. Waits for the gRPC port to become reachable
#   4. Verifies `openshell-vm exec` works
#   5. Runs the Rust smoke test
#   6. Tears down the VM
#
# When --vm-port is given the script assumes the VM is already running
# on that port and runs the smoke test. The VM exec check runs only when
# --vm-name is provided (so the script can target the correct instance).
#
# Prerequisites (when starting a new VM): `mise run vm:build:binary`,
# codesign, bundle-runtime, ensure-rootfs, and sync-rootfs must already
# be done (the e2e:vm mise task handles these via depends).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="${ROOT}/target/debug/openshell-vm.runtime"
GATEWAY_BIN="${ROOT}/target/debug/openshell-vm"
GUEST_PORT=30051
TIMEOUT=180

# ── Parse arguments ──────────────────────────────────────────────────
VM_PORT=""
VM_NAME=""
for arg in "$@"; do
  case "$arg" in
    --vm-port=*) VM_PORT="${arg#--vm-port=}" ;;
    --vm-name=*) VM_NAME="${arg#--vm-name=}" ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

# ── Determine mode ───────────────────────────────────────────────────
if [ -n "${VM_PORT}" ]; then
  # Point at an already-running VM.
  HOST_PORT="${VM_PORT}"
  echo "Using existing VM on port ${HOST_PORT}."
else
  # Pick a random free port and start a new VM.
  HOST_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
  if [ -z "${VM_NAME}" ]; then
    VM_NAME="e2e-${HOST_PORT}-$$"
  fi

  cleanup() {
    if [ -n "${VM_PID:-}" ] && kill -0 "$VM_PID" 2>/dev/null; then
      echo "Stopping openshell-vm (pid ${VM_PID})..."
      kill "$VM_PID" 2>/dev/null || true
      wait "$VM_PID" 2>/dev/null || true
    fi
  }
  trap cleanup EXIT

  echo "Starting openshell-vm '${VM_NAME}' on port ${HOST_PORT}..."
  if [ "$(uname -s)" = "Darwin" ]; then
    export DYLD_FALLBACK_LIBRARY_PATH="${RUNTIME_DIR}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
  fi

  "${GATEWAY_BIN}" --name "${VM_NAME}" --port "${HOST_PORT}:${GUEST_PORT}" &
  VM_PID=$!

  # ── Wait for gRPC port ─────────────────────────────────────────────
  echo "Waiting for gRPC port ${HOST_PORT} (timeout ${TIMEOUT}s)..."
  elapsed=0
  while ! nc -z 127.0.0.1 "${HOST_PORT}" 2>/dev/null; do
    if ! kill -0 "$VM_PID" 2>/dev/null; then
      echo "ERROR: openshell-vm exited before gRPC port became reachable"
      exit 1
    fi
    if [ "$elapsed" -ge "$TIMEOUT" ]; then
      echo "ERROR: openshell-vm gRPC port not reachable after ${TIMEOUT}s"
      exit 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "Gateway is ready (${elapsed}s)."
fi

# ── Exec into the VM (when instance name is known) ───────────────────
if [ -n "${VM_NAME}" ]; then
  echo "Verifying openshell-vm exec for '${VM_NAME}'..."
  exec_elapsed=0
  exec_timeout=60
  until "${GATEWAY_BIN}" --name "${VM_NAME}" exec -- /bin/true; do
    if [ "$exec_elapsed" -ge "$exec_timeout" ]; then
      echo "ERROR: openshell-vm exec did not become ready after ${exec_timeout}s"
      exit 1
    fi
    sleep 2
    exec_elapsed=$((exec_elapsed + 2))
  done
  echo "VM exec succeeded."
else
  echo "Skipping openshell-vm exec check (provide --vm-name for existing VMs)."
fi

# ── Run the smoke test ───────────────────────────────────────────────
# The openshell CLI reads OPENSHELL_GATEWAY_ENDPOINT to connect to the
# gateway directly, and OPENSHELL_GATEWAY to resolve mTLS certs from
# ~/.config/openshell/gateways/<name>/mtls/.
export OPENSHELL_GATEWAY_ENDPOINT="https://127.0.0.1:${HOST_PORT}"
if [ -n "${VM_NAME}" ]; then
  export OPENSHELL_GATEWAY="openshell-vm-${VM_NAME}"
else
  export OPENSHELL_GATEWAY="openshell-vm"
fi

echo "Running e2e smoke test (gateway: ${OPENSHELL_GATEWAY}, endpoint: ${OPENSHELL_GATEWAY_ENDPOINT})..."
cargo build -p openshell-cli --features openshell-core/dev-settings
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e --test smoke -- --nocapture

echo "Smoke test passed."
