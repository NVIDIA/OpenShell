#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a plaintext local gateway backed by the experimental external
# Firecracker compute driver. The logical openshell-sandbox supervisor runs on
# the host; each workload runs in a no-NIC Firecracker VM.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${OPENSHELL_SERVER_PORT:-18082}"
GATEWAY_NAME="${OPENSHELL_FIRECRACKER_GATEWAY_NAME:-firecracker-dev}"
STATE_DIR="${OPENSHELL_FIRECRACKER_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-firecracker}"
FIXTURE_DIR="${OPENSHELL_FIRECRACKER_FIXTURE_DIR:-/tmp/openshell-firecracker-e2e-fixtures}"
FIRECRACKER_BIN="${OPENSHELL_FIRECRACKER_BINARY:-${FIXTURE_DIR}/release/release-v1.16.1-aarch64/firecracker-v1.16.1-aarch64}"
KERNEL_IMAGE="${OPENSHELL_FIRECRACKER_KERNEL_IMAGE:-${FIXTURE_DIR}/vmlinux-6.1.155}"
ROOT_DISK="${OPENSHELL_FIRECRACKER_ROOT_DISK:-${FIXTURE_DIR}/openshell-ubuntu-24.04.ext4}"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"
DRIVER_BIN="${ROOT}/target/debug/openshell-driver-firecracker"
SUPERVISOR_BIN="${ROOT}/target/debug/openshell-sandbox"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
STATE_LABEL="$(printf '%s' "${GATEWAY_NAME}" | tr -cs '[:alnum:]._-' '-')"
DRIVER_STATE_DIR="${OPENSHELL_FIRECRACKER_STATE_DIR:-/tmp/openshell-firecracker-${USER:-user}-${STATE_LABEL}}"
DRIVER_SOCKET="${DRIVER_STATE_DIR}/compute-driver.sock"
DRIVER_LOG="${DRIVER_STATE_DIR}/driver.log"
GATEWAY_ENDPOINT="http://127.0.0.1:${PORT}"
DRIVER_PID=""

ensure_kvm_access() {
  [ -e /dev/kvm ] || fail "/dev/kvm does not exist; enable KVM on this host"
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    return 0
  fi
  if [ "${OPENSHELL_FIRECRACKER_KVM_REEXEC:-0}" != "1" ] \
      && command -v sg >/dev/null 2>&1 \
      && [[ " $(id -nG "$(id -un)") " == *" kvm "* ]]; then
    echo "==> Entering the configured kvm group for the Firecracker gateway"
    export OPENSHELL_FIRECRACKER_KVM_REEXEC=1
    export OPENSHELL_FIRECRACKER_GATEWAY_SCRIPT="${ROOT}/tasks/scripts/gateway-firecracker.sh"
    exec sg kvm -c 'exec "$OPENSHELL_FIRECRACKER_GATEWAY_SCRIPT"'
  fi
  fail "/dev/kvm is not readable and writable; add $(id -un) to the kvm group"
}

configure_bindgen_include() {
  local gcc_include
  command -v gcc >/dev/null 2>&1 || return 0
  gcc_include="$(gcc -print-file-name=include)"
  [ -f "${gcc_include}/stdbool.h" ] || return 0
  case " ${BINDGEN_EXTRA_CLANG_ARGS:-} " in
    *" -isystem ${gcc_include} "*) ;;
    *)
      export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:+${BINDGEN_EXTRA_CLANG_ARGS} }-isystem ${gcc_include}"
      ;;
  esac
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
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

cleanup() {
  local exit_code=$?
  if [ -n "${DRIVER_PID}" ] && kill -0 "${DRIVER_PID}" 2>/dev/null; then
    kill -TERM "${DRIVER_PID}" 2>/dev/null || true
    wait "${DRIVER_PID}" 2>/dev/null || true
  fi
  exit "${exit_code}"
}
trap cleanup EXIT

register_gateway() {
  local config_home gateway_dir
  config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"
  gateway_dir="${config_home}/openshell/gateways/${GATEWAY_NAME}"
  mkdir -p "${gateway_dir}"
  chmod 700 "${gateway_dir}" 2>/dev/null || true
  cat >"${gateway_dir}/metadata.json" <<EOF
{
  "name": "${GATEWAY_NAME}",
  "gateway_endpoint": "${GATEWAY_ENDPOINT}",
  "is_remote": false,
  "gateway_port": ${PORT},
  "auth_mode": "plaintext",
  "firecracker_driver_state_dir": "${DRIVER_STATE_DIR}"
}
EOF
  chmod 600 "${gateway_dir}/metadata.json" 2>/dev/null || true
  printf '%s' "${GATEWAY_NAME}" >"${config_home}/openshell/active_gateway"
}

[ "$(uname -s)" = "Linux" ] || fail "gateway:firecracker requires Linux"
ensure_kvm_access
configure_bindgen_include
[ -x "${FIRECRACKER_BIN}" ] || fail "Firecracker binary is not executable: ${FIRECRACKER_BIN}"
[ -f "${KERNEL_IMAGE}" ] || fail "kernel image not found: ${KERNEL_IMAGE}"
[ -f "${ROOT_DISK}" ] || fail "root disk fixture not found: ${ROOT_DISK}"
command -v debugfs >/dev/null 2>&1 || fail "debugfs is required"
port_is_in_use "${PORT}" && fail "port ${PORT} is already in use; set OPENSHELL_SERVER_PORT"

echo "==> Building gateway, host supervisor, and Firecracker driver"
cargo build -p openshell-server -p openshell-sandbox -p openshell-driver-firecracker

mkdir -p "${STATE_DIR}" "${DRIVER_STATE_DIR}"
chmod 700 "${DRIVER_STATE_DIR}"
TLS_DIR="${STATE_DIR}/tls"
echo "==> Generating local gateway credentials"
"${GATEWAY_BIN}" generate-certs \
  --output-dir "${TLS_DIR}" \
  --server-san 127.0.0.1 \
  --server-san localhost

CONFIG_PATH="${STATE_DIR}/gateway.toml"
install -m 600 /dev/null "${CONFIG_PATH}"
cat >"${CONFIG_PATH}" <<EOF
[openshell]
version = 1

[openshell.gateway]
compute_drivers = ["firecracker"]
disable_tls = true

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${TLS_DIR}/jwt/signing.pem"
public_key_path = "${TLS_DIR}/jwt/public.pem"
kid_path = "${TLS_DIR}/jwt/kid"
gateway_id = "${GATEWAY_NAME}"
ttl_secs = 3600

[openshell.drivers.firecracker]
socket_path = "${DRIVER_SOCKET}"
EOF

echo "==> Starting Firecracker compute driver"
"${DRIVER_BIN}" compute-driver \
  --bind-socket "${DRIVER_SOCKET}" \
  --gateway-endpoint "${GATEWAY_ENDPOINT}" \
  --state-dir "${DRIVER_STATE_DIR}" \
  --firecracker-binary "${FIRECRACKER_BIN}" \
  --kernel-image "${KERNEL_IMAGE}" \
  --root-disk "${ROOT_DISK}" \
  --supervisor-binary "${SUPERVISOR_BIN}" \
  >"${DRIVER_LOG}" 2>&1 &
DRIVER_PID=$!

for _ in $(seq 1 100); do
  [ -S "${DRIVER_SOCKET}" ] && break
  kill -0 "${DRIVER_PID}" 2>/dev/null || {
    tail -n 200 "${DRIVER_LOG}" >&2 || true
    fail "Firecracker compute driver exited before creating its socket"
  }
  sleep 0.1
done
[ -S "${DRIVER_SOCKET}" ] || fail "timed out waiting for ${DRIVER_SOCKET}"

register_gateway
echo "Starting standalone Firecracker gateway..."
echo "  gateway: ${GATEWAY_NAME}"
echo "  endpoint: ${GATEWAY_ENDPOINT}"
echo "  driver socket: ${DRIVER_SOCKET}"
echo "  driver log: ${DRIVER_LOG}"
echo "  topology: host supervisor + no-NIC Firecracker workload VM"
echo

exec "${GATEWAY_BIN}" \
  --config "${CONFIG_PATH}" \
  --port "${PORT}" \
  --log-level "${LOG_LEVEL}" \
  --drivers firecracker \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
