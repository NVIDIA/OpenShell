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
#   4. Writes a per-run gateway config with `[openshell.drivers.vm]`
#      settings, starts the gateway with `--config <run-state>/gateway.toml`
#      on a random free port, waits for `Server listening`, then runs the
#      selected Rust e2e test (`smoke` by default).
#   5. Tears the gateway down and (on failure) preserves the gateway
#      log and every VM serial console log for post-mortem.
#
# Prerequisites (handled automatically by this script if missing):
#   - `mise run vm:setup`      — downloads / builds the libkrun runtime.
#   - `mise run vm:supervisor` — builds the bundled sandbox supervisor.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT}/e2e/support/gateway-common.sh"

COMPRESSED_DIR="${ROOT}/target/vm-runtime-compressed"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"
DRIVER_BIN="${ROOT}/target/debug/openshell-driver-vm"
E2E_TEST="${OPENSHELL_E2E_VM_TEST:-smoke}"
E2E_FEATURES="${OPENSHELL_E2E_VM_FEATURES:-e2e-vm}"

# The VM driver places `compute-driver.sock` under `[openshell.drivers.vm].state_dir`.
# AF_UNIX SUN_LEN is 104 bytes on macOS (108 on Linux), so paths anchored
# in the workspace's `target/` blow the limit on typical developer
# machines — e.g. a ~100-char `~/.superset/worktrees/.../target/...`
# prefix plus the `compute-driver.sock` leaf leaves no room. macOS'
# per-user `$TMPDIR` (`/var/folders/xx/.../T/`) can be 50+ chars too,
# so root state under `/tmp` unconditionally to keep UDS paths short.
STATE_DIR_ROOT="/tmp"

# Smoke test timeouts. First boot extracts the embedded libkrun runtime
# (~60-90MB of zstd per architecture) and prepares an ext4 root disk from the
# configured image. The guest then starts the sandbox supervisor directly; a cold
# microVM is typically ready within ~15s after image preparation.
GATEWAY_READY_TIMEOUT=60
SANDBOX_PROVISION_TIMEOUT=180

# ── Build prerequisites ──────────────────────────────────────────────

if [ -n "${RUSTC_WRAPPER:-}" ] && [ "${OPENSHELL_E2E_VM_ALLOW_RUSTC_WRAPPER:-0}" != "1" ]; then
  echo "==> Building without RUSTC_WRAPPER=${RUSTC_WRAPPER} (set OPENSHELL_E2E_VM_ALLOW_RUSTC_WRAPPER=1 to keep it)"
  unset RUSTC_WRAPPER
fi

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
  -p openshell-cli

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
# and `<state_dir>/sandboxes/<id>/overlay.ext4` under here. Keep the
# basename short — see the SUN_LEN comment above.
RUN_STATE_DIR="${STATE_DIR_ROOT}/os-vm-e2e-${HOST_PORT}-$$"
mkdir -p "${RUN_STATE_DIR}"
export XDG_CONFIG_HOME="${RUN_STATE_DIR}/config"
export XDG_DATA_HOME="${RUN_STATE_DIR}/data"

GATEWAY_LOG="$(mktemp /tmp/openshell-gateway-e2e.XXXXXX)"
GATEWAY_PID_FILE="${RUN_STATE_DIR}/gateway.pid"
GATEWAY_ARGS_FILE="${RUN_STATE_DIR}/gateway.args"
GATEWAY_CONFIG="${RUN_STATE_DIR}/gateway.toml"
GATEWAY_DB="${RUN_STATE_DIR}/gateway.db"
PKI_DIR="${RUN_STATE_DIR}/pki"
JWT_DIR="${PKI_DIR}/jwt"
GATEWAY_NAME="openshell-e2e-vm-${HOST_PORT}"

# ── Cleanup (trap) ───────────────────────────────────────────────────

cleanup() {
  local exit_code=$?

  local gateway_pid="${GATEWAY_PID:-}"
  if [ -f "${GATEWAY_PID_FILE:-}" ]; then
    gateway_pid="$(cat "${GATEWAY_PID_FILE}" 2>/dev/null || true)"
  fi

  if [ -n "${gateway_pid}" ] && kill -0 "${gateway_pid}" 2>/dev/null; then
    echo "Stopping openshell-gateway (pid ${gateway_pid})..."
    # SIGTERM first; gateway drops ManagedDriverProcess which SIGKILLs
    # the driver and removes the UDS. Wait briefly, then force-kill.
    kill -TERM "${gateway_pid}" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "${gateway_pid}" 2>/dev/null || break
      sleep 0.5
    done
    kill -KILL "${gateway_pid}" 2>/dev/null || true
    wait "${gateway_pid}" 2>/dev/null || true
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
  # post-mortem (serial console logs, gvproxy logs, root disk images).
  if [ "${exit_code}" -eq 0 ]; then
    rm -rf "${RUN_STATE_DIR}" 2>/dev/null || true
  else
    echo "NOTE: preserving ${RUN_STATE_DIR} for debugging"
  fi
}
trap cleanup EXIT

# ── Launch the gateway + VM driver ───────────────────────────────────

echo "==> Starting openshell-gateway on 127.0.0.1:${HOST_PORT} (state: ${RUN_STATE_DIR})"

# Pin `driver_dir` to the workspace `target/debug/` so we always pick up
# the driver we just cargo-built. Without this, the gateway's
# `resolve_compute_driver_bin` fallback prefers
# `~/.local/libexec/openshell/openshell-driver-vm` when present,
# which silently shadows development builds — a subtle source of
# stale-binary bugs in e2e runs.
# `grpc_endpoint` is the URL the VM driver passes into each guest as
# OPENSHELL_ENDPOINT. The supervisor inside the VM dials this address.
# Use `host.openshell.internal` rather than `127.0.0.1` so gvproxy's
# host-loopback proxy carries the connection while keeping the endpoint aligned
# with package-managed gateway certificates. gvproxy's bare gateway IP
# (192.168.127.1) does NOT forward arbitrary host ports.
e2e_generate_pki "${GATEWAY_BIN}" "${PKI_DIR}"

cat >"${GATEWAY_CONFIG}" <<EOF
[openshell]
version = 1

[openshell.gateway]
bind_address = "127.0.0.1:${HOST_PORT}"
compute_drivers = ["vm"]

[openshell.gateway.tls]
cert_path = "${PKI_DIR}/server/tls.crt"
key_path = "${PKI_DIR}/server/tls.key"
client_ca_path = "${PKI_DIR}/ca.crt"

[openshell.gateway.mtls_auth]
enabled = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${JWT_DIR}/signing.pem"
public_key_path = "${JWT_DIR}/public.pem"
kid_path = "${JWT_DIR}/kid"
gateway_id = "${GATEWAY_NAME}"
# Local VM e2e gateways exercise the single-player default: sandbox JWTs
# identify the supervisor and do not expire.
ttl_secs = 0

[openshell.drivers.vm]
grpc_endpoint = "https://host.openshell.internal:${HOST_PORT}"
driver_dir = "${ROOT}/target/debug"
state_dir = "${RUN_STATE_DIR}"
guest_tls_ca = "${PKI_DIR}/ca.crt"
guest_tls_cert = "${PKI_DIR}/client/tls.crt"
guest_tls_key = "${PKI_DIR}/client/tls.key"
EOF

GATEWAY_ARGS=(
  --config "${GATEWAY_CONFIG}"
  --db-url "sqlite:${GATEWAY_DB}?mode=rwc"
)
e2e_write_gateway_args_file "${GATEWAY_ARGS_FILE}" "${GATEWAY_ARGS[@]}"

"${GATEWAY_BIN}" "${GATEWAY_ARGS[@]}" \
  >"${GATEWAY_LOG}" 2>&1 &
GATEWAY_PID=$!
printf '%s\n' "${GATEWAY_PID}" >"${GATEWAY_PID_FILE}"

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
# The CLI uses the raw endpoint but still resolves matching metadata so it
# can find the mTLS client bundle.

CLI_GATEWAY_ENDPOINT="https://127.0.0.1:${HOST_PORT}"
e2e_register_mtls_gateway \
  "${XDG_CONFIG_HOME}" \
  "${GATEWAY_NAME}" \
  "${CLI_GATEWAY_ENDPOINT}" \
  "${HOST_PORT}" \
  "${PKI_DIR}"

export OPENSHELL_GATEWAY_ENDPOINT="${CLI_GATEWAY_ENDPOINT}"
export OPENSHELL_E2E_EXPECT_VM_OVERLAY=1
export OPENSHELL_E2E_DRIVER="vm"
export OPENSHELL_E2E_VM_STATE_DIR="${RUN_STATE_DIR}"
e2e_export_gateway_restart_metadata \
  "${GATEWAY_BIN}" \
  "${GATEWAY_ARGS_FILE}" \
  "${GATEWAY_LOG}" \
  "${GATEWAY_PID_FILE}"

# The VM driver creates each sandbox VM from a cached read-only ext4 root disk
# plus a writable overlay disk. The guest's sandbox supervisor then initializes
# policy, netns, Landlock, and sshd. On a cold host this is ~15s after image
# preparation; allow 180s for slower CI runners.
export OPENSHELL_PROVISION_TIMEOUT="${SANDBOX_PROVISION_TIMEOUT}"

echo "==> Running e2e ${E2E_TEST} test (features: ${E2E_FEATURES}, endpoint: ${OPENSHELL_GATEWAY_ENDPOINT})"
cargo test \
  --manifest-path "${ROOT}/e2e/rust/Cargo.toml" \
  --features "${E2E_FEATURES}" \
  --test "${E2E_TEST}" \
  -- --nocapture

echo "==> ${E2E_TEST} test passed."
