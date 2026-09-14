#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLE_DIR="$ROOT/examples/supervisor-middleware-content-guard"
RUN_TEST_SUITE=0
PRINT_CONFIG=0

usage() {
  cat <<EOF
usage: $0 [--test-suite|--test|--print-config]

Without flags, starts a local gateway and content-guard service, creates an
example sandbox, and keeps the stack running for interactive use.

Options:
  --test-suite, --test  Run guarded and unguarded request checks, then stop.
  --print-config        Print the generated middleware gateway config, then stop.
  -h, --help            Show this help.

Environment:
  CONTENT_GUARD_SMOKE_HOST  Non-loopback host address reachable from both the
                            gateway and sandbox containers.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --test-suite | --test)
      RUN_TEST_SUITE=1
      shift
      ;;
    --print-config)
      PRINT_CONFIG=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

detect_service_host() {
  local interface address

  if [[ -n "${CONTENT_GUARD_SMOKE_HOST:-}" ]]; then
    printf '%s\n' "$CONTENT_GUARD_SMOKE_HOST"
    return
  fi

  if [[ "$(uname -s)" == "Darwin" ]] && command -v route >/dev/null 2>&1 && command -v ipconfig >/dev/null 2>&1; then
    interface="$(route -n get default 2>/dev/null | awk '/interface:/ { print $2; exit }')"
    if [[ -n "$interface" ]]; then
      address="$(ipconfig getifaddr "$interface" 2>/dev/null || true)"
      if [[ -n "$address" ]]; then
        printf '%s\n' "$address"
        return
      fi
    fi

    if command -v ifconfig >/dev/null 2>&1; then
      for interface in $(ifconfig -l 2>/dev/null); do
        if [[ "$interface" != en* ]]; then
          continue
        fi
        address="$(ipconfig getifaddr "$interface" 2>/dev/null || true)"
        if [[ -n "$address" ]]; then
          printf '%s\n' "$address"
          return
        fi
      done
    fi
  fi

  if command -v ip >/dev/null 2>&1; then
    address="$(ip route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }')"
    if [[ -n "$address" ]]; then
      printf '%s\n' "$address"
      return
    fi
  fi

  if command -v hostname >/dev/null 2>&1; then
    address="$(hostname -I 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i !~ /^127\./ && $i !~ /:/) { print $i; exit } }')"
    if [[ -n "$address" ]]; then
      printf '%s\n' "$address"
      return
    fi
  fi

  echo "could not detect a non-loopback host address" >&2
  echo "set CONTENT_GUARD_SMOKE_HOST to an address reachable from sandbox containers" >&2
  exit 1
}

SERVICE_HOST="$(detect_service_host)"
if [[ "$SERVICE_HOST" == "localhost" || "$SERVICE_HOST" == "::1" || "$SERVICE_HOST" == 127.* || "$SERVICE_HOST" == *:* ]]; then
  echo "CONTENT_GUARD_SMOKE_HOST must be a non-loopback IPv4 address: $SERVICE_HOST" >&2
  exit 1
fi

TMPDIR="$(mktemp -d)"
LOG_DIR="$TMPDIR/logs"
JWT_DIR="$TMPDIR/jwt"
GATEWAY_CONFIG="$TMPDIR/gateway.toml"
SETUP_LOG="$LOG_DIR/setup.log"
GATEWAY_LOG="$LOG_DIR/gateway.log"
MIDDLEWARE_LOG="$LOG_DIR/middleware.log"
RUN_ID="content-guard-smoke-$$-$RANDOM"
# Sandbox names are capped at 19 characters. Use a short prefix with
# the PID for uniqueness; keep the full RUN_ID for gateway identity.
SANDBOX_NAME="cg-$$-$RANDOM"
SANDBOX_CREATED=0

mkdir -p "$LOG_DIR"

cleanup() {
  local status=$?
  trap - EXIT

  if [[ "$SANDBOX_CREATED" -eq 1 && -n "${CLI+x}" ]]; then
    "${CLI[@]}" sandbox delete "$SANDBOX_NAME" >>"$SETUP_LOG" 2>&1 || true
  fi

  if [[ -n "${GATEWAY_PID:-}" ]]; then
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
  fi

  if [[ -n "${MIDDLEWARE_PID:-}" ]]; then
    kill "$MIDDLEWARE_PID" 2>/dev/null || true
    wait "$MIDDLEWARE_PID" 2>/dev/null || true
  fi

  if [[ "$status" -eq 0 ]]; then
    rm -rf "$TMPDIR"
  else
    echo "logs retained in $LOG_DIR" >&2
  fi

  exit "$status"
}
trap cleanup EXIT

port_is_free() {
  local port="$1"

  if command -v lsof >/dev/null 2>&1; then
    ! lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return
  fi

  if command -v nc >/dev/null 2>&1; then
    ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1
    return
  fi

  return 0
}

choose_port_block() {
  local count="$1"
  local start offset ok

  for _ in {1..200}; do
    start=$((20000 + RANDOM % 20000))
    ok=1
    for ((offset = 0; offset < count; offset++)); do
      if ! port_is_free "$((start + offset))"; then
        ok=0
        break
      fi
    done
    if [[ "$ok" == "1" ]]; then
      printf '%s\n' "$start"
      return
    fi
  done

  echo "failed to find free local ports for content guard launcher" >&2
  exit 1
}

PORT_BASE="$(choose_port_block 3)"
MIDDLEWARE_PORT="$PORT_BASE"
GATEWAY_PORT="$((PORT_BASE + 1))"
HEALTH_PORT="$((PORT_BASE + 2))"
GATEWAY_ENDPOINT="http://127.0.0.1:$GATEWAY_PORT"

write_gateway_config() {
  cat >"$GATEWAY_CONFIG" <<EOF
[openshell]
version = 1

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$JWT_DIR/signing.pem"
public_key_path = "$JWT_DIR/public.pem"
kid_path = "$JWT_DIR/kid"
gateway_id = "$RUN_ID"
ttl_secs = 0

[[openshell.supervisor.middleware]]
name = "content-guard-example"
grpc_endpoint = "http://$SERVICE_HOST:$MIDDLEWARE_PORT"
max_payload_bytes = 262144
timeout = "500ms"
EOF
}

write_gateway_config
if [[ "$PRINT_CONFIG" -eq 1 ]]; then
  cat "$GATEWAY_CONFIG"
  exit 0
fi

generate_gateway_jwt_bundle() {
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate local smoke-test gateway JWT keys" >&2
    exit 1
  fi

  mkdir -p "$JWT_DIR"
  openssl genpkey -algorithm ed25519 -out "$JWT_DIR/signing.pem" >/dev/null 2>&1
  openssl pkey -in "$JWT_DIR/signing.pem" -pubout -out "$JWT_DIR/public.pem" >/dev/null 2>&1
  printf '%s\n' "$RUN_ID" >"$JWT_DIR/kid"
}

dump_logs() {
  local label path
  for label in setup gateway middleware; do
    case "$label" in
      setup) path="$SETUP_LOG" ;;
      gateway) path="$GATEWAY_LOG" ;;
      middleware) path="$MIDDLEWARE_LOG" ;;
    esac
    printf '\n--- %s log: %s ---\n' "$label" "$path" >&2
    if [[ -f "$path" ]]; then
      cat "$path" >&2
    else
      printf '(missing)\n' >&2
    fi
  done
}

fail() {
  printf 'FAIL %s\n' "$1" >&2
  dump_logs
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

run_setup_step() {
  local label="$1"
  shift
  printf 'INFO %s\n' "$label"
  printf '\n== %s ==\n+' "$label" >>"$SETUP_LOG"
  printf ' %q' "$@" >>"$SETUP_LOG"
  printf '\n' >>"$SETUP_LOG"
  if ! "$@" >>"$SETUP_LOG" 2>&1; then
    fail "$label"
  fi
}

cargo_target_dir() {
  local manifest_path="$1"

  cargo metadata \
    --format-version=1 \
    --no-deps \
    --manifest-path "$manifest_path" \
    | jq -er '.target_directory'
}

start_middleware() {
  printf 'INFO starting content guard service at %s:%s\n' "$SERVICE_HOST" "$MIDDLEWARE_PORT"
  "$MIDDLEWARE_BIN" \
    --bind "0.0.0.0:$MIDDLEWARE_PORT" >"$MIDDLEWARE_LOG" 2>&1 &
  MIDDLEWARE_PID=$!
}

middleware_port_is_ready() {
  if command -v nc >/dev/null 2>&1; then
    nc -z "$SERVICE_HOST" "$MIDDLEWARE_PORT" >/dev/null 2>&1
    return
  fi

  (exec 3<>"/dev/tcp/$SERVICE_HOST/$MIDDLEWARE_PORT") 2>/dev/null
}

wait_for_middleware() {
  for _ in {1..60}; do
    if ! kill -0 "$MIDDLEWARE_PID" 2>/dev/null; then
      fail "content guard service starts"
    fi
    if middleware_port_is_ready; then
      printf 'INFO content guard service is ready\n'
      return
    fi
    sleep 1
  done
  fail "content guard service is reachable at $SERVICE_HOST:$MIDDLEWARE_PORT"
}

start_gateway() {
  printf 'INFO starting gateway\n'
  env -u OPENSHELL_DRIVERS "$GATEWAY_BIN" \
    --config "$GATEWAY_CONFIG" \
    --bind-address 127.0.0.1 \
    --port "$GATEWAY_PORT" \
    --health-port "$HEALTH_PORT" \
    --metrics-port 0 \
    --log-level info \
    --disable-tls \
    --db-url "sqlite://$TMPDIR/gateway.db" >"$GATEWAY_LOG" 2>&1 &
  GATEWAY_PID=$!
}

wait_for_gateway() {
  for _ in {1..60}; do
    if ! kill -0 "$MIDDLEWARE_PID" 2>/dev/null; then
      fail "content guard service starts"
    fi
    if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
      fail "gateway starts with content guard"
    fi
    if curl -fsS "http://127.0.0.1:$HEALTH_PORT/healthz" >/dev/null 2>&1; then
      printf 'INFO gateway starts with content guard\n'
      return
    fi
    sleep 1
  done
  fail "gateway starts with content guard"
}

create_sandbox() {
  CLI=(
    env
    -u OPENSHELL_SANDBOX_POLICY
    "$CLI_BIN"
    --gateway-endpoint "$GATEWAY_ENDPOINT"
  )
  run_setup_step \
    "creating content guard sandbox" \
    "${CLI[@]}" sandbox create --name "$SANDBOX_NAME" --policy "$EXAMPLE_DIR/policy.yaml" --keep --no-tty -- /bin/sh -lc true
  SANDBOX_CREATED=1
}

request() {
  local host="$1"
  "${CLI[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- \
    curl -sS --max-time 20 "https://$host/anything" \
    --header 'content-type: application/json' \
    --data '{"note":"prototype-secret"}'
}

run_suite() {
  local guarded_output="$LOG_DIR/guarded.out"
  local unguarded_output="$LOG_DIR/unguarded.out"

  printf 'INFO sending guarded request to httpbin.org\n'
  if ! request httpbin.org >"$guarded_output" 2>>"$SETUP_LOG"; then
    fail "guarded request completes"
  fi
  if grep -Fq '[FILTERED]' "$guarded_output" && ! grep -Fq 'prototype-secret' "$guarded_output"; then
    printf 'PASS guarded request is filtered\n'
  else
    cat "$guarded_output" >>"$SETUP_LOG"
    fail "guarded request is filtered"
  fi

  printf 'INFO sending unguarded request to httpbingo.org\n'
  if ! request httpbingo.org >"$unguarded_output" 2>>"$SETUP_LOG"; then
    fail "unguarded request completes"
  fi
  if grep -Fq 'prototype-secret' "$unguarded_output" && ! grep -Fq '[FILTERED]' "$unguarded_output"; then
    printf 'PASS unguarded request is unchanged\n'
  else
    cat "$unguarded_output" >>"$SETUP_LOG"
    fail "unguarded request is unchanged"
  fi

  "${CLI[@]}" sandbox delete "$SANDBOX_NAME" >>"$SETUP_LOG" 2>&1
  SANDBOX_CREATED=0
  echo "ALL PASS content guard smoke"
}

print_ready() {
  cat <<EOF

READY supervisor middleware content guard

Gateway endpoint:   $GATEWAY_ENDPOINT
Middleware endpoint: http://$SERVICE_HOST:$MIDDLEWARE_PORT
Sandbox:            $SANDBOX_NAME
Gateway config:     $GATEWAY_CONFIG
Setup log:          $SETUP_LOG
Gateway log:        $GATEWAY_LOG
Middleware log:     $MIDDLEWARE_LOG

Guarded request, selected by the httpbin.org middleware endpoint selector:
  ${CLI[*]} sandbox exec --name $SANDBOX_NAME --no-tty -- curl -sS https://httpbin.org/anything --header 'content-type: application/json' --data '{"note":"prototype-secret"}'

Unguarded request, allowed by policy but outside the middleware selector:
  ${CLI[*]} sandbox exec --name $SANDBOX_NAME --no-tty -- curl -sS https://httpbingo.org/anything --header 'content-type: application/json' --data '{"note":"prototype-secret"}'

Press Ctrl-C to delete the sandbox and stop the gateway and middleware.
EOF
}

wait_until_stopped() {
  while true; do
    if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
      fail "gateway process exited"
    fi
    if ! kill -0 "$MIDDLEWARE_PID" 2>/dev/null; then
      fail "content guard process exited"
    fi
    sleep 1
  done
}

cd "$ROOT"
require_command cargo
require_command curl
require_command jq
require_command openssl
ROOT_TARGET_DIR="$(cargo_target_dir "$ROOT/Cargo.toml")"
EXAMPLE_TARGET_DIR="$(cargo_target_dir "$EXAMPLE_DIR/Cargo.toml")"
GATEWAY_BIN="$ROOT_TARGET_DIR/debug/openshell-gateway"
CLI_BIN="$ROOT_TARGET_DIR/debug/openshell"
MIDDLEWARE_BIN="$EXAMPLE_TARGET_DIR/debug/supervisor-middleware-content-guard"
run_setup_step "building gateway" cargo build --quiet -p openshell-server --bin openshell-gateway
run_setup_step "building content guard" cargo build --quiet --manifest-path "$EXAMPLE_DIR/Cargo.toml"
run_setup_step "building CLI" cargo build --quiet -p openshell-cli --bin openshell
generate_gateway_jwt_bundle
start_middleware
wait_for_middleware
start_gateway
wait_for_gateway
create_sandbox

if [[ "$RUN_TEST_SUITE" -eq 1 ]]; then
  run_suite
else
  print_ready
  wait_until_stopped
fi
