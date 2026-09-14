#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared helpers for local gateway-backed e2e wrappers. Driver-specific setup,
# cleanup, and runtime behavior stay in the Docker/Podman wrapper scripts.

# E2E traffic is synthetic and must not contribute to product usage metrics.
# Keep an explicit override so telemetry-specific tests can opt back in.
export OPENSHELL_TELEMETRY_ENABLED="${OPENSHELL_TELEMETRY_ENABLED:-false}"

e2e_cargo_target_dir() {
  local root=$1
  shift
  local cargo_command=(cargo)

  if [ "$#" -gt 0 ]; then
    cargo_command=("$@")
  fi

  if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    case "${CARGO_TARGET_DIR}" in
      /*) printf '%s\n' "${CARGO_TARGET_DIR}" ;;
      *) printf '%s\n' "${root}/${CARGO_TARGET_DIR}" ;;
    esac
    return 0
  fi

  "${cargo_command[@]}" metadata --format-version=1 --no-deps \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
}

e2e_endpoint_port() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlparse

parsed = urlparse(sys.argv[1])
print(parsed.port or (443 if parsed.scheme == "https" else 80))
PY
}

e2e_pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}

e2e_generate_pki() {
  local gateway_bin=$1
  local pki_dir=$2
  shift 2
  # Remaining args are extra --server-san values (e.g. host.containers.internal).
  # host.docker.internal and localhost are already in the default SAN list.

  local san_args=()
  san_args+=(--server-san host.openshell.internal)
  for san in "$@"; do
    san_args+=(--server-san "${san}")
  done

  "${gateway_bin}" generate-certs --output-dir "${pki_dir}" "${san_args[@]}"
}

e2e_preserve_mise_dirs() {
  if ! command -v mise >/dev/null 2>&1; then
    return 0
  fi

  if [ -z "${MISE_DATA_DIR:-}" ]; then
    export MISE_DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/mise"
  fi

  if [ -z "${MISE_CACHE_DIR:-}" ]; then
    case "$(uname -s)" in
      Darwin) export MISE_CACHE_DIR="${HOME}/Library/Caches/mise" ;;
      *) export MISE_CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/mise" ;;
    esac
  fi

  if [ -z "${MISE_STATE_DIR:-}" ]; then
    export MISE_STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}/mise"
  fi
}

e2e_align_docker_host_with_cli_context() {
  if [ -n "${DOCKER_HOST:-}" ] || ! command -v docker >/dev/null 2>&1; then
    return 0
  fi

  local endpoint
  endpoint="$(docker context inspect --format '{{ .Endpoints.docker.Host }}' 2>/dev/null || true)"
  if [ -z "${endpoint}" ] || [ "${endpoint}" = "<no value>" ]; then
    return 0
  fi

  export DOCKER_HOST="${endpoint}"
  echo "Using Docker endpoint from active context: ${DOCKER_HOST}"
}

e2e_register_plaintext_gateway() {
  local config_home=$1
  local name=$2
  local endpoint=$3
  local port=$4
  local gateway_config_dir="${config_home}/openshell/gateways/${name}"

  mkdir -p "${gateway_config_dir}"
  cat >"${gateway_config_dir}/metadata.json" <<EOF
{
  "name": "${name}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${port},
  "auth_mode": "plaintext"
}
EOF
  printf '%s' "${name}" >"${config_home}/openshell/active_gateway"
}

e2e_register_mtls_gateway() {
  local config_home=$1
  local name=$2
  local endpoint=$3
  local port=$4
  local pki_dir=$5
  local oidc_issuer="${6:-}"
  local gateway_config_dir="${config_home}/openshell/gateways/${name}"

  mkdir -p "${gateway_config_dir}/mtls"
  cp "${pki_dir}/ca.crt"         "${gateway_config_dir}/mtls/ca.crt"
  cp "${pki_dir}/client/tls.crt" "${gateway_config_dir}/mtls/tls.crt"
  cp "${pki_dir}/client/tls.key" "${gateway_config_dir}/mtls/tls.key"

  local oidc_line=""
  if [ -n "${oidc_issuer}" ]; then
    oidc_line="$(printf ',\n  "oidc_issuer": "%s"' "${oidc_issuer}")"
  fi

  cat >"${gateway_config_dir}/metadata.json" <<EOF
{
  "name": "${name}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${port}${oidc_line}
}
EOF
  printf '%s' "${name}" >"${config_home}/openshell/active_gateway"
}

e2e_toml_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "${value}"
}

e2e_generate_gateway_jwt() {
  local jwt_dir=$1

  mkdir -p "${jwt_dir}"
  (
    umask 077
    openssl genpkey -algorithm Ed25519 -out "${jwt_dir}/signing.pem" >/dev/null 2>&1
  )
  openssl pkey -in "${jwt_dir}/signing.pem" -pubout -out "${jwt_dir}/public.pem" >/dev/null 2>&1
  openssl rand -hex 16 >"${jwt_dir}/kid"
}

e2e_write_gateway_jwt_config() {
  local jwt_dir=$1
  local gateway_id=$2

  printf '[openshell.gateway.gateway_jwt]\n'
  printf 'signing_key_path = %s\n' "$(e2e_toml_string "${jwt_dir}/signing.pem")"
  printf 'public_key_path = %s\n'  "$(e2e_toml_string "${jwt_dir}/public.pem")"
  printf 'kid_path = %s\n'         "$(e2e_toml_string "${jwt_dir}/kid")"
  printf 'gateway_id = %s\n'       "$(e2e_toml_string "${gateway_id}")"
  # Local Docker/Podman e2e gateways exercise the single-player default:
  # sandbox JWTs identify the supervisor and do not expire.
  printf 'ttl_secs = 0\n\n'
}

e2e_write_gateway_mtls_auth_config() {
  printf '[openshell.gateway.mtls_auth]\n'
  printf 'enabled = true\n\n'
}

e2e_write_gateway_oidc_config() {
  local issuer=$1
  local scopes_claim="${2:-scope}"

  printf '[openshell.gateway.oidc]\n'
  printf 'issuer = %s\n'         "$(e2e_toml_string "${issuer}")"
  printf 'audience = "openshell-cli"\n'
  printf 'jwks_ttl_secs = 60\n'
  printf 'roles_claim = "realm_access.roles"\n'
  printf 'admin_role = "openshell-admin"\n'
  printf 'user_role = "openshell-user"\n'
  printf 'scopes_claim = %s\n\n' "$(e2e_toml_string "${scopes_claim}")"
}

e2e_build_gateway_binaries() {
  local root=$1
  local target_var=$2
  local gateway_var=$3
  local cli_var=$4
  local target_dir
  local jobs=()

  if [ -n "${CARGO_BUILD_JOBS:-}" ]; then
    jobs=(-j "${CARGO_BUILD_JOBS}")
  fi

  target_dir="$(e2e_cargo_target_dir "${root}")"
  printf -v "${target_var}" '%s' "${target_dir}"
  printf -v "${gateway_var}" '%s' "${OPENSHELL_GATEWAY_BIN:-${target_dir}/debug/openshell-gateway}"
  printf -v "${cli_var}" '%s' "${OPENSHELL_BIN:-${target_dir}/debug/openshell}"

  if [ -z "${OPENSHELL_GATEWAY_BIN:-}" ]; then
    echo "Building openshell-gateway..."
    if [ "${OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER:-0}" = "1" ]; then
      cargo build "${jobs[@]}" \
        -p openshell-server --bin openshell-gateway \
        --no-default-features
    else
      cargo build "${jobs[@]}" \
        -p openshell-server --bin openshell-gateway
    fi
  else
    echo "Using prebuilt openshell gateway at ${OPENSHELL_GATEWAY_BIN}"
  fi

  if [ -z "${OPENSHELL_BIN:-}" ]; then
    echo "Building openshell-cli..."
    cargo build "${jobs[@]}" \
      -p openshell-cli
  else
    echo "Using prebuilt openshell CLI at ${OPENSHELL_BIN}"
  fi

  if [ ! -x "${!gateway_var}" ]; then
    echo "ERROR: expected openshell-gateway binary at ${!gateway_var}" >&2
    exit 1
  fi
  if [ ! -x "${!cli_var}" ]; then
    echo "ERROR: expected openshell CLI binary at ${!cli_var}" >&2
    exit 1
  fi
}

e2e_build_external_driver() {
  local root=$1
  local package=$2
  local binary=$3
  local output_var=$4
  local target_dir
  local jobs=()

  if [ -n "${CARGO_BUILD_JOBS:-}" ]; then
    jobs=(-j "${CARGO_BUILD_JOBS}")
  fi
  target_dir="$(e2e_cargo_target_dir "${root}")"
  if [ -n "${OPENSHELL_EXTERNAL_DRIVER_BIN:-}" ]; then
    printf -v "${output_var}" '%s' "${OPENSHELL_EXTERNAL_DRIVER_BIN}"
    echo "Using prebuilt external driver at ${OPENSHELL_EXTERNAL_DRIVER_BIN}"
  else
    printf -v "${output_var}" '%s' "${target_dir}/debug/${binary}"
    echo "Building external ${binary}..."
    cargo build "${jobs[@]}" -p "${package}" --bin "${binary}"
  fi
  if [ ! -x "${!output_var}" ]; then
    echo "ERROR: expected external driver binary at ${!output_var}" >&2
    exit 1
  fi
}

e2e_wait_for_socket() {
  local socket_path=$1
  local process_pid=$2
  local process_label=$3
  local timeout="${4:-30}"
  local elapsed=0

  while [ "${elapsed}" -lt "${timeout}" ]; do
    if [ -S "${socket_path}" ]; then
      return 0
    fi
    if ! kill -0 "${process_pid}" 2>/dev/null; then
      echo "ERROR: ${process_label} exited before creating ${socket_path}" >&2
      return 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "ERROR: ${process_label} did not create ${socket_path} within ${timeout}s" >&2
  return 1
}

e2e_stop_process() {
  local process_pid=$1
  local process_label=$2
  if [ -n "${process_pid}" ] && kill -0 "${process_pid}" 2>/dev/null; then
    echo "Stopping ${process_label} (pid ${process_pid})..."
    kill "${process_pid}" 2>/dev/null || true
    wait "${process_pid}" 2>/dev/null || true
  fi
}

e2e_write_gateway_args_file() {
  local args_file=$1
  shift

  : >"${args_file}"
  for arg in "$@"; do
    printf '%s\0' "${arg}" >>"${args_file}"
  done
}

e2e_export_gateway_restart_metadata() {
  local gateway_bin=$1
  local args_file=$2
  local log_file=$3
  local pid_file=$4

  export OPENSHELL_E2E_GATEWAY_BIN="${gateway_bin}"
  export OPENSHELL_E2E_GATEWAY_ARGS_FILE="${args_file}"
  export OPENSHELL_E2E_GATEWAY_LOG="${log_file}"
  export OPENSHELL_E2E_GATEWAY_PID_FILE="${pid_file}"
}

e2e_stop_gateway() {
  local gateway_pid=$1
  local gateway_pid_file=$2

  if [ -f "${gateway_pid_file}" ]; then
    gateway_pid="$(cat "${gateway_pid_file}" 2>/dev/null || true)"
  fi
  if [ -n "${gateway_pid}" ] && kill -0 "${gateway_pid}" 2>/dev/null; then
    echo "Stopping openshell-gateway (pid ${gateway_pid})..."
    kill "${gateway_pid}" 2>/dev/null || true

    # A Rust E2E test may have restarted the gateway and updated the PID file.
    # That replacement process is not a child of this shell, so `wait` returns
    # immediately even though gateway shutdown (including its sandbox stop
    # sweep) is still in progress. Poll until either the process exits or a
    # child process becomes a zombie that the final `wait` can reap.
    local attempts=0
    local process_state=""
    while kill -0 "${gateway_pid}" 2>/dev/null && [ "${attempts}" -lt 120 ]; do
      process_state="$(ps -p "${gateway_pid}" -o stat= 2>/dev/null || true)"
      case "${process_state}" in
        *Z*) break ;;
      esac
      sleep 0.5
      attempts=$((attempts + 1))
    done
    if kill -0 "${gateway_pid}" 2>/dev/null; then
      process_state="$(ps -p "${gateway_pid}" -o stat= 2>/dev/null || true)"
      case "${process_state}" in
        *Z*) ;;
        *) kill -KILL "${gateway_pid}" 2>/dev/null || true ;;
      esac
    fi
    wait "${gateway_pid}" 2>/dev/null || true
  fi
}

e2e_print_gateway_log_on_failure() {
  local exit_code=$1
  local gateway_log=$2

  if [ "${exit_code}" -ne 0 ] && [ -f "${gateway_log}" ]; then
    echo "=== gateway log (preserved for debugging) ==="
    cat "${gateway_log}"
    echo "=== end gateway log ==="
  fi
}
