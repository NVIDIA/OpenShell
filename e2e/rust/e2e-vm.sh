#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e smoke test against an openshell-gateway running the
# standalone VM compute driver (`openshell-driver-vm`).
#
# Architecture (post supervisor-initiated relay, PR #867):
#   * The gateway never dials the sandbox. Instead, the in-guest
#     supervisor opens an outbound `ConnectSupervisor` gRPC stream to
#     the gateway on startup and keeps it alive for the sandbox
#     lifetime. SSH (`/connect/ssh`) and `ExecSandbox` traffic ride the
#     same TCP+TLS+HTTP/2 connection as multiplexed HTTP/2 streams.
#   * There is no host-side SSH port forward. gvproxy still provides
#     guest egress so the supervisor can reach the gateway, but it no
#     longer forwards any TCP port back to the guest.
#   * Readiness is authoritative on the gateway: a sandbox's phase
#     flips to `Ready` the moment `ConnectSupervisor` registers, and
#     back to `Provisioning` when the session drops. The VM driver
#     only reports `Error` conditions for dead launcher processes.
#
# Usage:
#   mise run e2e:vm
#
# What the script does:
#   1. Ensures the VM runtime (libkrun + gvproxy) and bundled supervisor are staged.
#   2. Builds `openshell-gateway`, `openshell-driver-vm`, and the
#      `openshell` CLI with the embedded runtime.
#   3. On macOS, codesigns the VM driver (libkrun needs the
#      `com.apple.security.hypervisor` entitlement).
#   4. Starts the gateway with `--drivers vm --disable-tls
#      --disable-gateway-auth --db-url sqlite::memory:` on a random
#      free port, waits for `Server listening`, then runs the
#      cluster-agnostic Rust smoke test.
#   5. Tears the gateway down and (on failure) preserves the gateway
#      log and every VM serial console log for post-mortem.
#
# Prerequisites (handled automatically by this script if missing):
#   - `mise run vm:setup`      — downloads / builds the libkrun runtime.
#   - `mise run vm:supervisor` — builds the bundled sandbox supervisor.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPRESSED_DIR="${ROOT}/target/vm-runtime-compressed"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"
DRIVER_BIN="${ROOT}/target/debug/openshell-driver-vm"

# The VM driver places `compute-driver.sock` under --vm-driver-state-dir.
# AF_UNIX SUN_LEN is 104 bytes on macOS (108 on Linux), so paths anchored
# in the workspace's `target/` blow the limit on typical developer
# machines — e.g. a ~100-char `~/.superset/worktrees/.../target/...`
# prefix plus the `compute-driver.sock` leaf leaves no room. macOS'
# per-user `$TMPDIR` (`/var/folders/xx/.../T/`) can be 50+ chars too,
# so root state under `/tmp` unconditionally to keep UDS paths short.
STATE_DIR_ROOT="/tmp"

# Smoke test timeouts. First boot extracts the embedded libkrun runtime
# (~60-90MB of zstd per architecture) and prepares a sandbox rootfs from the
# configured image. The guest then runs k3s-free sandbox supervisor startup; a
# cold microVM is typically ready within ~15s after image preparation.
GATEWAY_READY_TIMEOUT=60
SANDBOX_PROVISION_TIMEOUT=180

# ── Build prerequisites ──────────────────────────────────────────────

mkdir -p "${COMPRESSED_DIR}"

if ! find "${COMPRESSED_DIR}" -maxdepth 1 -name 'libkrun*.zst' | grep -q .; then
  echo "==> Preparing embedded VM runtime (mise run vm:setup)"
  mise run vm:setup
fi

if [ ! -f "${COMPRESSED_DIR}/openshell-sandbox.zst" ]; then
  echo "==> Building bundled VM supervisor (mise run vm:supervisor)"
  mise run vm:supervisor
fi

export OPENSHELL_VM_RUNTIME_COMPRESSED_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${COMPRESSED_DIR}}"

echo "==> Building openshell-gateway, openshell-driver-vm, openshell (CLI)"
cargo build \
  -p openshell-server \
  -p openshell-driver-vm \
  -p openshell-cli \
  --features openshell-core/dev-settings

if [ "$(uname -s)" = "Darwin" ]; then
  echo "==> Codesigning openshell-driver-vm (Hypervisor entitlement)"
  codesign \
    --entitlements "${ROOT}/crates/openshell-driver-vm/entitlements.plist" \
    --force \
    -s - \
    "${DRIVER_BIN}"
fi

# ── Pick a random free host port for the gateway ─────────────────────

HOST_PORT="$(python3 -c 'import socket
s = socket.socket()
s.bind(("", 0))
print(s.getsockname()[1])
s.close()')"

# Per-run state dir so concurrent e2e runs don't collide on the UDS or
# sandbox state. The VM driver creates `<state_dir>/compute-driver.sock`
# and `<state_dir>/sandboxes/<id>/rootfs/` under here. Keep the
# basename short — see the SUN_LEN comment above.
RUN_STATE_DIR="${STATE_DIR_ROOT}/os-vm-e2e-${HOST_PORT}-$$"
mkdir -p "${RUN_STATE_DIR}"

GATEWAY_LOG="$(mktemp /tmp/openshell-gateway-e2e.XXXXXX)"

# ── Cleanup (trap) ───────────────────────────────────────────────────

cleanup() {
  local exit_code=$?

  if [ -n "${GATEWAY_PID:-}" ] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo "Stopping openshell-gateway (pid ${GATEWAY_PID})..."
    # SIGTERM first; gateway drops ManagedDriverProcess which SIGKILLs
    # the driver and removes the UDS. Wait briefly, then force-kill.
    kill -TERM "${GATEWAY_PID}" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "${GATEWAY_PID}" 2>/dev/null || break
      sleep 0.5
    done
    kill -KILL "${GATEWAY_PID}" 2>/dev/null || true
    wait "${GATEWAY_PID}" 2>/dev/null || true
  fi

  # On failure, keep the VM console log for debugging. We deliberately
  # print it instead of leaving it on disk because the state dir gets
  # wiped on success.
  if [ "${exit_code}" -ne 0 ]; then
    echo "=== gateway log (preserved for debugging) ==="
    cat "${GATEWAY_LOG}" 2>/dev/null || true
    echo "=== end gateway log ==="

    local console
    while IFS= read -r -d '' console; do
      echo "=== VM console log: ${console} ==="
      cat "${console}" 2>/dev/null || true
      echo "=== end VM console log ==="
    done < <(find "${RUN_STATE_DIR}/sandboxes" -name 'rootfs-console.log' -print0 2>/dev/null)
  fi

  rm -f "${GATEWAY_LOG}" 2>/dev/null || true
  # Only wipe the per-run state dir on success. On failure, leave it for
  # post-mortem (serial console logs, gvproxy logs, rootfs dumps).
  if [ "${exit_code}" -eq 0 ]; then
    rm -rf "${RUN_STATE_DIR}" 2>/dev/null || true
  else
    echo "NOTE: preserving ${RUN_STATE_DIR} for debugging"
  fi
}
trap cleanup EXIT

# ── Launch the gateway + VM driver ───────────────────────────────────

SSH_HANDSHAKE_SECRET="$(openssl rand -hex 32)"

echo "==> Starting openshell-gateway on 127.0.0.1:${HOST_PORT} (state: ${RUN_STATE_DIR})"

# Pin --driver-dir to the workspace `target/debug/` so we always pick up
# the driver we just cargo-built. Without this, the gateway's
# `resolve_compute_driver_bin` fallback prefers
# `~/.local/libexec/openshell/openshell-driver-vm` when present,
# which silently shadows development builds — a subtle source of
# stale-binary bugs in e2e runs.
# --grpc-endpoint is the URL the VM driver passes into each guest as
# OPENSHELL_ENDPOINT. The supervisor inside the VM dials this address.
# Use `host.containers.internal` rather than `127.0.0.1` so gvproxy's
# host-loopback proxy carries the connection — gvproxy's bare gateway IP
# (192.168.127.1) does NOT forward arbitrary host ports. The driver also
# rewrites loopback URLs to this hostname as a safety net, so this matches
# what the guest will actually see and aligns with `tasks/scripts/gateway-vm.sh`.
"${GATEWAY_BIN}" \
  --drivers vm \
  --disable-tls \
  --disable-gateway-auth \
  --db-url 'sqlite::memory:' \
  --port "${HOST_PORT}" \
  --grpc-endpoint "http://host.containers.internal:${HOST_PORT}" \
  --ssh-handshake-secret "${SSH_HANDSHAKE_SECRET}" \
  --driver-dir "${ROOT}/target/debug" \
  --vm-driver-state-dir "${RUN_STATE_DIR}" \
  >"${GATEWAY_LOG}" 2>&1 &
GATEWAY_PID=$!

# ── Wait for gateway readiness ───────────────────────────────────────
#
# The gateway logs `INFO openshell_server: Server listening
# address=0.0.0.0:<port>` after its tonic listener is up. That is the
# only signal the smoke test needs — the VM driver is spawned eagerly
# but sandboxes are created on demand, so "Server listening" is the
# right gate here.

echo "==> Waiting for gateway readiness (timeout ${GATEWAY_READY_TIMEOUT}s)"
elapsed=0
while ! grep -q 'Server listening' "${GATEWAY_LOG}" 2>/dev/null; do
  if ! kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo "ERROR: openshell-gateway exited before becoming ready"
    exit 1
  fi
  if [ "${elapsed}" -ge "${GATEWAY_READY_TIMEOUT}" ]; then
    echo "ERROR: openshell-gateway did not become ready after ${GATEWAY_READY_TIMEOUT}s"
    exit 1
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

echo "==> Gateway ready after ${elapsed}s"

# ── Run the smoke test ───────────────────────────────────────────────
#
# The CLI takes OPENSHELL_GATEWAY_ENDPOINT directly; no gateway
# metadata lookup needed when TLS is disabled.

export OPENSHELL_GATEWAY_ENDPOINT="http://127.0.0.1:${HOST_PORT}"

# The VM driver creates each sandbox VM from scratch — the embedded
# rootfs is extracted per sandbox, and the guest's sandbox supervisor
# then initializes policy, netns, Landlock, and sshd. On a cold host
# this is ~15s; allow 180s for slower CI runners.
export OPENSHELL_PROVISION_TIMEOUT="${SANDBOX_PROVISION_TIMEOUT}"

echo "==> Running e2e smoke test (endpoint: ${OPENSHELL_GATEWAY_ENDPOINT})"
cargo test \
  --manifest-path "${ROOT}/e2e/rust/Cargo.toml" \
  --features e2e \
  --test smoke \
  -- --nocapture

echo "==> Smoke test passed."
