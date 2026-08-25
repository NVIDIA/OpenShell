#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Boot the host-supervised Firecracker backend and exercise its RFC 0012
# lifecycle against the current process supervisor implementation in the guest.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE_DIR="${OPENSHELL_FIRECRACKER_FIXTURE_DIR:-/tmp/openshell-firecracker-e2e-fixtures}"
DRIVER_BIN="${OPENSHELL_FIRECRACKER_DRIVER_BIN:-${ROOT}/target/debug/openshell-driver-firecracker}"
FIRECRACKER_BIN="${OPENSHELL_FIRECRACKER_BINARY:-${FIXTURE_DIR}/release/release-v1.16.1-aarch64/firecracker-v1.16.1-aarch64}"
KERNEL_IMAGE="${OPENSHELL_FIRECRACKER_KERNEL_IMAGE:-${FIXTURE_DIR}/vmlinux-6.1.155}"
ROOT_DISK_FIXTURE="${OPENSHELL_FIRECRACKER_ROOT_DISK:-${FIXTURE_DIR}/openshell-ubuntu-24.04.ext4}"
BOOT_TIMEOUT_SECONDS="${OPENSHELL_FIRECRACKER_BOOT_TIMEOUT_SECONDS:-60}"
KEEP_STATE="${OPENSHELL_FIRECRACKER_KEEP_STATE:-0}"
CONTROL_PORT="${OPENSHELL_FIRECRACKER_CONTROL_PORT:-5500}"

RUN_DIR="$(mktemp -d /tmp/openshell-firecracker-e2e.XXXXXX)"
ROOT_DISK="${RUN_DIR}/root.ext4"
TOKEN_FILE="${RUN_DIR}/bootstrap.token"
GUEST_CONFIG="${RUN_DIR}/firecracker.json"
CONSOLE_LOG="${RUN_DIR}/console.log"
LAUNCHER_LOG="${RUN_DIR}/launcher.log"
SUPERVISOR_LOG="${RUN_DIR}/supervisor.log"
VSOCK_SOCKET="${RUN_DIR}/firecracker-vsock.sock"
LAUNCHER_PID=""

BOUNDARY_ID="firecracker-e2e-$$"
VSOCK_CID=$(( ($$ % 60000) + 1024 ))
SMOKE_MARKER="openshell-firecracker-e2e-ok-${BOUNDARY_ID}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

launcher_is_running() {
  [ -n "${LAUNCHER_PID}" ] && kill -0 "${LAUNCHER_PID}" 2>/dev/null
}

print_logs() {
  local log
  for log in "${LAUNCHER_LOG}" "${SUPERVISOR_LOG}" "${CONSOLE_LOG}"; do
    if [ -s "${log}" ]; then
      echo "=== ${log} ===" >&2
      tail -n 200 "${log}" >&2 || true
      echo "=== end ${log} ===" >&2
    fi
  done
}

cleanup() {
  local exit_code=$?
  set +e
  if launcher_is_running; then
    kill -TERM "${LAUNCHER_PID}" 2>/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      launcher_is_running || break
      sleep 0.2
    done
    launcher_is_running && kill -KILL "${LAUNCHER_PID}" 2>/dev/null
  fi
  [ -n "${LAUNCHER_PID}" ] && wait "${LAUNCHER_PID}" 2>/dev/null
  [ "${exit_code}" -eq 0 ] || print_logs
  if [ "${KEEP_STATE}" = "1" ]; then
    echo "Firecracker E2E state preserved at ${RUN_DIR}" >&2
  else
    case "${RUN_DIR}" in
      /tmp/openshell-firecracker-e2e.*) rm -rf -- "${RUN_DIR}" ;;
      *) echo "Refusing to remove unexpected run directory: ${RUN_DIR}" >&2 ;;
    esac
  fi
  exit "${exit_code}"
}
trap cleanup EXIT

wait_for_console_marker() {
  local marker="$1"
  local label="$2"
  local deadline=$(( SECONDS + BOOT_TIMEOUT_SECONDS ))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    grep -Fq -- "${marker}" "${CONSOLE_LOG}" 2>/dev/null && return 0
    launcher_is_running || fail "Firecracker exited while waiting for ${label}"
    sleep 0.2
  done
  fail "timed out after ${BOOT_TIMEOUT_SECONDS}s waiting for ${label}"
}

inject_file() {
  local source="$1"
  local destination="$2"
  debugfs -w -R "rm ${destination}" "${ROOT_DISK}" >/dev/null 2>&1 || true
  debugfs -w -R "write ${source} ${destination}" "${ROOT_DISK}" >/dev/null
}

[ "$(uname -s)" = "Linux" ] || fail "Firecracker E2E requires Linux"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || \
  fail "/dev/kvm is not readable and writable; start a login session with the kvm supplementary group"
[ -x "${FIRECRACKER_BIN}" ] || fail "Firecracker binary is not executable: ${FIRECRACKER_BIN}"
[ -f "${KERNEL_IMAGE}" ] || fail "kernel image not found: ${KERNEL_IMAGE}"
[ -f "${ROOT_DISK_FIXTURE}" ] || fail "root disk fixture not found: ${ROOT_DISK_FIXTURE}"
[[ "${BOOT_TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]] || fail "boot timeout must be positive"
[[ "${CONTROL_PORT}" =~ ^[1-9][0-9]*$ ]] || fail "control port must be positive"

for tool in cargo cp debugfs grep jq openssl tail; do
  command -v "${tool}" >/dev/null 2>&1 || fail "required host tool not found: ${tool}"
done

if [ -n "${RUSTC_WRAPPER:-}" ] && [ "${OPENSHELL_E2E_FIRECRACKER_ALLOW_RUSTC_WRAPPER:-0}" != "1" ]; then
  unset RUSTC_WRAPPER
fi
if [ -z "${OPENSHELL_FIRECRACKER_DRIVER_BIN:-}" ]; then
  echo "==> Building standalone Firecracker driver"
  cargo build --package openshell-driver-firecracker
fi
[ -x "${DRIVER_BIN}" ] || fail "driver binary not found: ${DRIVER_BIN}"

echo "==> Preparing an isolated guest disk"
cp --reflink=auto "${ROOT_DISK_FIXTURE}" "${ROOT_DISK}"
umask 077
openssl rand -hex 32 >"${TOKEN_FILE}"
jq -n \
  --arg boundary_id "${BOUNDARY_ID}" \
  --arg bootstrap_token "$(tr -d '\n' <"${TOKEN_FILE}")" \
  --argjson control_port "${CONTROL_PORT}" \
  '{boundary_id: $boundary_id, bootstrap_token: $bootstrap_token, control_port: $control_port}' \
  >"${GUEST_CONFIG}"

debugfs -w -R "mkdir /etc/openshell" "${ROOT_DISK}" >/dev/null 2>&1 || true
inject_file "${GUEST_CONFIG}" /etc/openshell/firecracker.json
inject_file "${DRIVER_BIN}" /opt/openshell/bin/openshell-driver-firecracker
debugfs -w -R \
  "set_inode_field /opt/openshell/bin/openshell-driver-firecracker mode 0100755" \
  "${ROOT_DISK}" >/dev/null

echo "==> Starting Firecracker guest ${BOUNDARY_ID} (vsock only, no NIC)"
"${DRIVER_BIN}" launch \
  --firecracker-binary "${FIRECRACKER_BIN}" \
  --kernel-image "${KERNEL_IMAGE}" \
  --root-disk "${ROOT_DISK}" \
  --run-dir "${RUN_DIR}" \
  --console-output "${CONSOLE_LOG}" \
  --vsock-cid "${VSOCK_CID}" \
  >"${LAUNCHER_LOG}" 2>&1 &
LAUNCHER_PID=$!

wait_for_console_marker \
  "Firecracker process supervisor leaf listening on vsock port ${CONTROL_PORT}" \
  "guest process leaf"
[ -S "${VSOCK_SOCKET}" ] || fail "Firecracker vsock UDS was not created: ${VSOCK_SOCKET}"

echo "==> Driving attach, confirm, start_agent, and wait from the host"
"${DRIVER_BIN}" supervise \
  --boundary-id "${BOUNDARY_ID}" \
  --vsock-uds-path "${VSOCK_SOCKET}" \
  --vsock-port "${CONTROL_PORT}" \
  --bootstrap-token-file "${TOKEN_FILE}" \
  --workdir /sandbox \
  --timeout-seconds 30 \
  -- /bin/sh -lc "printf '%s\\n' '${SMOKE_MARKER}'" \
  >"${SUPERVISOR_LOG}" 2>&1

grep -Fq 'agent exited: Exited(0)' "${SUPERVISOR_LOG}" || \
  fail "host supervisor did not observe a successful agent exit"
wait_for_console_marker "${SMOKE_MARKER}" "agent output"

echo "==> Firecracker host-supervisor E2E passed"
echo "    boundary: ${BOUNDARY_ID}"
echo "    lifecycle: attach -> confirm -> start_agent -> wait"
echo "    process leaf: openshell-supervisor-process"
echo "    transport: authenticated Firecracker virtio-vsock"
echo "    network: no guest NIC"
