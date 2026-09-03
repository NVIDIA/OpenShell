#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Paired process-level checks for gateway-wide options that do not require a
# sandbox. The caller supplies immutable baseline and candidate gateway builds.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASELINE_GATEWAY="${OPENSHELL_PARITY_BASELINE_GATEWAY_BIN:-}"
CANDIDATE_GATEWAY="${OPENSHELL_PARITY_CANDIDATE_GATEWAY_BIN:-}"
RESULTS_DIR="${OPENSHELL_PARITY_RESULTS_DIR:-${ROOT}/target/parity/gateway-options}"
BASELINE_SHA="74960ebfaeec4673885089ed995fad902459749f"
CANDIDATE_SHA="$(git -C "${ROOT}" rev-parse HEAD)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-gateway-options.XXXXXX")"
PIDS=()

cleanup() {
  local status=$? pid
  for pid in "${PIDS[@]}"; do
    kill -INT "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  done
  rm -rf "${WORKDIR}"
  exit "${status}"
}
trap cleanup EXIT

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

for binary in "${BASELINE_GATEWAY}" "${CANDIDATE_GATEWAY}"; do
  [ -x "${binary}" ] || fail "gateway binary is not executable: ${binary:-<unset>}"
done
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v podman >/dev/null 2>&1 || fail "podman is required"
podman info >/dev/null 2>&1 || fail "podman service is not reachable"

PODMAN_SOCKET="${OPENSHELL_PODMAN_SOCKET:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock}"
[ -S "${PODMAN_SOCKET}" ] || fail "Podman API socket is unavailable: ${PODMAN_SOCKET}"
mkdir -p "${RESULTS_DIR}"

pick_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

write_config() {
  local output=$1 schema=$2 variant=$3 file_port=$4 health_port=$5 metrics_port=$6
  cat >"${output}" <<EOF
[openshell]
version = ${schema}

[openshell.gateway]
name = "${variant}-file"
bind_address = "127.0.0.1:${file_port}"
health_bind_address = "127.0.0.1:${health_port}"
metrics_bind_address = "127.0.0.1:${metrics_port}"
log_level = "info"
disable_tls = true
EOF
  if [ "${schema}" = 1 ]; then
    printf 'compute_drivers = ["podman"]\n' >>"${output}"
  else
    printf 'compute_driver = "podman"\n' >>"${output}"
  fi
  cat >>"${output}" <<'EOF'

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.drivers.podman]
EOF
}

wait_for_url() {
  local pid=$1 url=$2 log=$3 elapsed=0
  while [ "${elapsed}" -lt 100 ]; do
    if curl --noproxy '*' --max-time 1 -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      echo "=== gateway log ===" >&2
      cat "${log}" >&2 || true
      return 1
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
  done
  echo "timed out waiting for ${url}" >&2
  cat "${log}" >&2 || true
  return 1
}

stop_gateway() {
  local pid=$1
  kill -INT "${pid}" >/dev/null 2>&1 || true
  wait "${pid}" >/dev/null 2>&1 || true
  PIDS=()
}

run_variant() {
  local variant=$1 schema=$2 sha=$3 gateway=$4
  local dir="${WORKDIR}/${variant}"
  local config="${dir}/gateway.toml" db="${dir}/gateway.db" log="${dir}/gateway.log"
  local file_port env_port primary_port health_port metrics_port second_primary
  mkdir -p "${dir}/state"
  file_port="$(pick_port)"
  env_port="$(pick_port)"
  primary_port="$(pick_port)"
  health_port="$(pick_port)"
  metrics_port="$(pick_port)"
  second_primary="$(pick_port)"
  write_config "${config}" "${schema}" "${variant}" "${file_port}" "${health_port}" "${metrics_port}"

  echo "==> ${variant}: precedence, listeners, and initial SQLite open"
  XDG_CONFIG_HOME="${dir}/config" \
  XDG_STATE_HOME="${dir}/state" \
  OPENSHELL_PODMAN_SOCKET="${PODMAN_SOCKET}" \
  OPENSHELL_SERVER_PORT="${env_port}" \
    "${gateway}" \
      --config "${config}" \
      --db-url "sqlite:${db}?mode=rwc" \
      --name "${variant}-cli" \
      --port "${primary_port}" \
      --log-level debug >"${log}" 2>&1 &
  local pid=$!
  PIDS=("${pid}")
  wait_for_url "${pid}" "http://127.0.0.1:${health_port}/healthz" "${log}" \
    || fail "${variant} health listener did not start"
  curl --noproxy '*' --max-time 2 -fsS "http://127.0.0.1:${metrics_port}/metrics" >/dev/null \
    || fail "${variant} metrics listener is unavailable"
  # A plain HTTP request to the gRPC listener returns 404; successful TCP/HTTP
  # exchange is sufficient to prove that the selected primary port is bound.
  curl --noproxy '*' --max-time 2 -sS "http://127.0.0.1:${primary_port}/" >/dev/null \
    || fail "${variant} primary listener is unavailable"
  if curl --noproxy '*' --max-time 1 -sS "http://127.0.0.1:${file_port}/" >/dev/null 2>&1; then
    fail "${variant} file port unexpectedly beat the CLI port"
  fi
  if curl --noproxy '*' --max-time 1 -sS "http://127.0.0.1:${env_port}/" >/dev/null 2>&1; then
    fail "${variant} environment port unexpectedly beat the CLI port"
  fi
  grep -F "127.0.0.1:${primary_port}" "${log}" >/dev/null \
    || fail "${variant} startup log did not identify the effective primary bind"
  [ -s "${db}" ] || fail "${variant} SQLite database was not created"
  stop_gateway "${pid}"

  echo "==> ${variant}: SQLite reopen and health-port zero override"
  : >"${log}"
  XDG_CONFIG_HOME="${dir}/config" \
  XDG_STATE_HOME="${dir}/state" \
  OPENSHELL_PODMAN_SOCKET="${PODMAN_SOCKET}" \
    "${gateway}" \
      --config "${config}" \
      --db-url "sqlite:${db}?mode=rwc" \
      --port "${second_primary}" \
      --health-port 0 >"${log}" 2>&1 &
  pid=$!
  PIDS=("${pid}")
  wait_for_url "${pid}" "http://127.0.0.1:${metrics_port}/metrics" "${log}" \
    || fail "${variant} did not reopen its SQLite database"
  if curl --noproxy '*' --max-time 1 -fsS "http://127.0.0.1:${health_port}/healthz" >/dev/null 2>&1; then
    fail "${variant} health listener remained active after --health-port 0"
  fi
  stop_gateway "${pid}"

  echo "==> ${variant}: database URL in TOML is rejected without value disclosure"
  local invalid="${dir}/invalid.toml" secret="parity-secret-${variant}"
  awk -v secret="${secret}" '
    /^name =/ { print "database_url = \"postgres://user:" secret "@127.0.0.1/db\"" }
    { print }
  ' "${config}" >"${invalid}"
  if OPENSHELL_PODMAN_SOCKET="${PODMAN_SOCKET}" \
    "${gateway}" --config "${invalid}" >"${dir}/invalid.log" 2>&1; then
    fail "${variant} accepted database_url in gateway TOML"
  fi
  grep -F 'database_url' "${dir}/invalid.log" >/dev/null \
    || fail "${variant} database rejection did not identify the field"
  if grep -F "${secret}" "${dir}/invalid.log" >/dev/null; then
    fail "${variant} database rejection disclosed the configured secret"
  fi

  cat >"${RESULTS_DIR}/gateway-options-${variant}.json" <<EOF
{"variant":"${variant}","source_sha":"${sha}","schema_version":${schema},"listeners":true,"precedence":true,"sqlite_reopen":true,"database_toml_rejected_without_disclosure":true,"success":true}
EOF
}

run_variant baseline 1 "${BASELINE_SHA}" "${BASELINE_GATEWAY}"
run_variant candidate 2 "${CANDIDATE_SHA}" "${CANDIDATE_GATEWAY}"
cat >"${RESULTS_DIR}/gateway-options-comparison.json" <<'EOF'
{"profile":"gateway-options","baseline_success":true,"candidate_success":true,"parity":true}
EOF

echo "Gateway option parity passed."
