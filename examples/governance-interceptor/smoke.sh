#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLE_DIR="$ROOT/examples/governance-interceptor"
TMPDIR="$(mktemp -d)"
LOG_DIR="$TMPDIR/logs"
JWT_DIR="$TMPDIR/jwt"
GATEWAY_CONFIG="$TMPDIR/gateway.toml"
SMOKE_LOG="$LOG_DIR/smoke.log"
GATEWAY_LOG="$LOG_DIR/gateway.log"
INTERCEPTOR_LOG="$LOG_DIR/interceptor.log"
RUN_ID="governance-smoke-$$-$RANDOM"
SANDBOX_NAME="$RUN_ID-sandbox"

mkdir -p "$LOG_DIR"

cleanup() {
  local status=$?
  trap - EXIT

  if [[ -n "${INTERCEPTOR_PID:-}" ]]; then
    kill "$INTERCEPTOR_PID" 2>/dev/null || true
    wait "$INTERCEPTOR_PID" 2>/dev/null || true
  fi

  if [[ -n "${GATEWAY_PID:-}" ]]; then
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
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

  echo "failed to find free local ports for smoke test" >&2
  exit 1
}

PORT_BASE="$(choose_port_block 3)"
INTERCEPTOR_ADDR="127.0.0.1:$PORT_BASE"
GATEWAY_PORT="$((PORT_BASE + 1))"
HEALTH_PORT="$((PORT_BASE + 2))"
GATEWAY_ADDR="127.0.0.1:$GATEWAY_PORT"
HEALTH_ADDR="127.0.0.1:$HEALTH_PORT"
GATEWAY_ENDPOINT="http://$GATEWAY_ADDR"

dump_log_file() {
  local label="$1"
  local path="$2"

  printf '\n--- %s: %s ---\n' "$label" "$path" >&2
  if [[ -f "$path" ]]; then
    cat "$path" >&2
  else
    printf '(missing)\n' >&2
  fi
}

dump_logs() {
  dump_log_file "smoke log" "$SMOKE_LOG"
  dump_log_file "gateway log" "$GATEWAY_LOG"
  dump_log_file "interceptor log" "$INTERCEPTOR_LOG"
}

pass() {
  printf 'PASS %s\n' "$1"
}

fail() {
  printf 'FAIL %s\n' "$1" >&2
  dump_logs
  exit 1
}

log_command() {
  local label="$1"
  shift

  {
    printf '\n== %s ==\n' "$label"
    printf '+'
    printf ' %q' "$@"
    printf '\n'
  } >>"$SMOKE_LOG"
}

run_setup_step() {
  local label="$1"
  shift

  printf 'INFO %s\n' "$label"
  log_command "$label" "$@"
  if ! "$@" >>"$SMOKE_LOG" 2>&1; then
    fail "$label"
  fi
}

run_step() {
  local label="$1"
  shift

  log_command "$label" "$@"
  if "$@" >>"$SMOKE_LOG" 2>&1; then
    pass "$label"
  else
    fail "$label"
  fi
}

expect_failure() {
  local label="$1"
  shift

  log_command "$label" "$@"
  if "$@" >>"$SMOKE_LOG" 2>&1; then
    fail "$label"
  else
    pass "$label"
  fi
}

expect_output_contains() {
  local label="$1"
  local needle="$2"
  shift 2
  local output_file="$LOG_DIR/${label//[^A-Za-z0-9_]/_}.out"

  log_command "$label" "$@"
  if "$@" >"$output_file" 2>>"$SMOKE_LOG" && grep -Fq -- "$needle" "$output_file"; then
    pass "$label"
  else
    cat "$output_file" >>"$SMOKE_LOG" 2>/dev/null || true
    fail "$label"
  fi
}

expect_log_contains() {
  local label="$1"
  local needle="$2"
  local path="$3"

  if grep -Fq -- "$needle" "$path"; then
    pass "$label"
  else
    fail "$label"
  fi
}

wait_for_profile() {
  local profile_id="$1"
  local label="loads $profile_id provider profile"

  {
    printf '\n== %s ==\n' "$label"
    printf '+ wait for provider profile %q\n' "$profile_id"
  } >>"$SMOKE_LOG"

  for _ in {1..60}; do
    if "${CLI[@]}" provider profile export "$profile_id" -o yaml >>"$SMOKE_LOG" 2>&1; then
      pass "$label"
      return
    fi
    sleep 1
  done

  fail "$label"
}

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

[[openshell.gateway.interceptors]]
name = "provider-governance"
grpc_endpoint = "http://$INTERCEPTOR_ADDR"
order = 10
failure_policy = "fail_closed"
timeout = "500ms"
max_response_bytes = 1048576
max_patches = 32
EOF
}

start_interceptor() {
  printf 'INFO starting governance interceptor\n'
  "$EXAMPLE_DIR/target/debug/governance-interceptor" \
    --listen "$INTERCEPTOR_ADDR" \
    --policy "$EXAMPLE_DIR/policy.yaml" \
    --profiles "$EXAMPLE_DIR/profiles" \
    --gateway-endpoint "$GATEWAY_ENDPOINT" >"$INTERCEPTOR_LOG" 2>&1 &
  INTERCEPTOR_PID=$!
}

start_gateway() {
  printf 'INFO starting gateway\n'
  env -u OPENSHELL_DRIVERS "$ROOT/target/debug/openshell-gateway" \
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
  local label="gateway starts with interceptor"

  for _ in {1..60}; do
    if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
      fail "$label"
    fi

    if curl -fsS "http://$HEALTH_ADDR/healthz" >/dev/null 2>&1; then
      pass "$label"
      return
    fi

    sleep 1
  done

  fail "$label"
}

run_suite() {
  CLI=(
    env
    -u OPENSHELL_SANDBOX_POLICY
    "$ROOT/target/debug/openshell"
    --gateway-endpoint "$GATEWAY_ENDPOINT"
  )

  run_step "enables provider profile policy composition" "${CLI[@]}" settings set --global --key providers_v2_enabled --value true --yes
  wait_for_profile "github"
  wait_for_profile "slack"
  expect_output_contains "lists github profile" "github" "${CLI[@]}" provider list-profiles
  expect_output_contains "lists slack profile" "slack" "${CLI[@]}" provider list-profiles

  cat >"$TMPDIR/disallowed-profile.yaml" <<'EOF'
id: custom-slack
display_name: Custom Slack
description: Profile outside the managed github/slack set used to verify interceptor import denial
category: messaging
credentials: []
endpoints: []
binaries: []
EOF

  expect_failure "denies provider profile delete" "${CLI[@]}" provider profile delete slack
  expect_failure "denies disallowed provider profile import" "${CLI[@]}" provider profile import -f "$TMPDIR/disallowed-profile.yaml"

  expect_failure "denies slack provider with github profile" "${CLI[@]}" provider create --name slack --type github --credential SLACK_BOT_TOKEN=dummy
  run_step "allows github provider create" "${CLI[@]}" provider create --name github --type github --credential GITHUB_TOKEN=dummy
  run_step "allows slack provider create" "${CLI[@]}" provider create --name slack --type slack --credential SLACK_BOT_TOKEN=dummy

  expect_failure "denies disallowed provider create" "${CLI[@]}" provider create --name bitbucket --type github --credential GITHUB_TOKEN=dummy

  run_step "creates governed sandbox" "${CLI[@]}" sandbox create --name "$SANDBOX_NAME" --no-auto-providers --keep --no-tty -- /bin/sh -lc true
  expect_log_contains "gateway logs interceptor log annotations" "log_annotations" "$GATEWAY_LOG"
  expect_log_contains "gateway logs governance correlation id" "governance:create-sandbox:$SANDBOX_NAME" "$GATEWAY_LOG"
  expect_output_contains "sandbox has github provider" "github" "${CLI[@]}" sandbox provider list "$SANDBOX_NAME"
  expect_output_contains "sandbox has slack provider" "slack" "${CLI[@]}" sandbox provider list "$SANDBOX_NAME"
  expect_output_contains "effective policy has github provider layer" "_provider_github" "${CLI[@]}" policy get "$SANDBOX_NAME" --full -o json
  expect_output_contains "effective policy has slack provider layer" "_provider_slack" "${CLI[@]}" policy get "$SANDBOX_NAME" --full -o json

  expect_failure "denies provider attach" "${CLI[@]}" sandbox provider attach "$SANDBOX_NAME" github
  expect_failure "denies provider detach" "${CLI[@]}" sandbox provider detach "$SANDBOX_NAME" github
  expect_failure "denies policy replacement" "${CLI[@]}" policy set "$SANDBOX_NAME" --policy "$EXAMPLE_DIR/policy.yaml"

  run_step "deletes governed sandbox" "${CLI[@]}" sandbox delete "$SANDBOX_NAME"

  expect_failure "denies governed provider update" "${CLI[@]}" provider update slack --credential SLACK_BOT_TOKEN=changed
  expect_failure "denies governed provider delete" "${CLI[@]}" provider delete github
}

cd "$ROOT"

run_setup_step "building gateway" cargo build --quiet -p openshell-server --bin openshell-gateway
run_setup_step "building governance interceptor" cargo build --quiet --manifest-path "$EXAMPLE_DIR/Cargo.toml"
run_setup_step "building test CLI" cargo build --quiet -p openshell-cli --bin openshell

generate_gateway_jwt_bundle
write_gateway_config
start_interceptor
start_gateway
wait_for_gateway
run_suite

echo "ALL PASS governance interceptor smoke"
