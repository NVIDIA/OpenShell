#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLE_DIR="$ROOT/examples/governance-interceptor"
TMPDIR="$(mktemp -d)"
SMOKE_RUN_ID="${OPENSHELL_GOVERNANCE_RUN_ID:-governance-smoke-$$-$RANDOM}"
port_is_free() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    ! lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1
  fi
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

DEFAULT_PORT_BASE="$(choose_port_block 3)"
JWT_DIR="$TMPDIR/jwt"
LOG_DIR="${OPENSHELL_GOVERNANCE_LOG_DIR:-$TMPDIR/logs}"
SMOKE_LOG="$LOG_DIR/smoke.log"
INTERCEPTOR_LOG="$LOG_DIR/interceptor.log"
GATEWAY_LOG="$LOG_DIR/gateway.log"
INTERCEPTOR_ADDR="${OPENSHELL_GOVERNANCE_INTERCEPTOR_ADDR:-127.0.0.1:$DEFAULT_PORT_BASE}"
GATEWAY_ADDR="${OPENSHELL_GOVERNANCE_GATEWAY_ADDR:-127.0.0.1:$((DEFAULT_PORT_BASE + 1))}"
HEALTH_ADDR="${OPENSHELL_GOVERNANCE_HEALTH_ADDR:-127.0.0.1:$((DEFAULT_PORT_BASE + 2))}"
GATEWAY_ID="${OPENSHELL_GOVERNANCE_GATEWAY_ID:-$SMOKE_RUN_ID}"
SANDBOX_NAME="${OPENSHELL_GOVERNANCE_SANDBOX_NAME:-$SMOKE_RUN_ID-sandbox}"
mkdir -p "$LOG_DIR"

cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "${INTERCEPTOR_PID:-}" ]]; then kill "$INTERCEPTOR_PID" 2>/dev/null || true; fi
  if [[ -n "${GATEWAY_PID:-}" ]]; then kill "$GATEWAY_PID" 2>/dev/null || true; fi
  if [[ "$status" -eq 0 && "${OPENSHELL_GOVERNANCE_KEEP_LOGS:-0}" != "1" ]]; then
    rm -rf "$TMPDIR"
  else
    echo "logs retained in $LOG_DIR" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

log() {
  printf '%s\n' "$*" >>"$SMOKE_LOG"
}

pass() {
  printf 'PASS %s\n' "$1"
}

fail() {
  printf 'FAIL %s\n' "$1" >&2
  dump_logs
  exit 1
}

setup_fail() {
  printf 'ERROR %s\n' "$1" >&2
  dump_logs
  exit 1
}

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

run_setup_step() {
  local label="$1"
  shift
  printf 'INFO %s\n' "$label"
  {
    printf '\n== %s ==\n' "$label"
    printf '+ %q ' "$@"
    printf '\n'
  } >>"$SMOKE_LOG"
  if ! "$@" >>"$SMOKE_LOG" 2>&1; then
    setup_fail "$label"
  fi
}

run_step() {
  local label="$1"
  shift
  {
    printf '\n== %s ==\n' "$label"
    printf '+ %q ' "$@"
    printf '\n'
  } >>"$SMOKE_LOG"
  if "$@" >>"$SMOKE_LOG" 2>&1; then
    pass "$label"
  else
    fail "$label"
  fi
}

expect_failure() {
  local label="$1"
  shift
  {
    printf '\n== %s ==\n' "$label"
    printf '+ %q ' "$@"
    printf '\n'
  } >>"$SMOKE_LOG"
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
  {
    printf '\n== %s ==\n' "$label"
    printf '+ %q ' "$@"
    printf '\n'
  } >>"$SMOKE_LOG"
  if "$@" >"$output_file" 2>>"$SMOKE_LOG" && grep -q "$needle" "$output_file"; then
    pass "$label"
  else
    cat "$output_file" >>"$SMOKE_LOG" 2>/dev/null || true
    fail "$label"
  fi
}

configure_native_build_env() {
  if [[ "$(uname -s)" == "Darwin" && "${OPENSHELL_GOVERNANCE_KEEP_CC:-0}" != "1" ]]; then
    export CC="${OPENSHELL_GOVERNANCE_CC:-clang}"
    export CXX="${OPENSHELL_GOVERNANCE_CXX:-clang++}"
    log "Using macOS native build compiler: CC=$CC CXX=$CXX"
  fi

  if [[ "${OPENSHELL_GOVERNANCE_KEEP_RUSTC_WRAPPER:-0}" != "1" ]]; then
    export RUSTC_WRAPPER="${OPENSHELL_GOVERNANCE_RUSTC_WRAPPER:-}"
  fi

  if [[ -z "${RUSTC_WRAPPER:-}" ]]; then
    log "Building without RUSTC_WRAPPER for reproducible smoke builds."
  else
    log "Using RUSTC_WRAPPER=$RUSTC_WRAPPER"
  fi
}

docker_socket_responds() {
  local socket="$1"
  curl --silent --fail --unix-socket "$socket" http://localhost/_ping >/dev/null 2>&1
}

docker_context_socket() {
  if ! command -v docker >/dev/null 2>&1; then
    return
  fi

  local endpoint
  endpoint="$(docker context inspect --format '{{ (index .Endpoints "docker").Host }}' 2>/dev/null || true)"
  if [[ "$endpoint" == unix://* ]]; then
    printf '%s\n' "${endpoint#unix://}"
  fi
}

configure_container_runtime_env() {
  if [[ -n "${DOCKER_HOST:-}" ]]; then
    log "Using caller-provided DOCKER_HOST=$DOCKER_HOST"
    return
  fi

  local candidate
  local -a candidates=()

  candidate="$(docker_context_socket)"
  if [[ -n "$candidate" ]]; then
    candidates+=("$candidate")
  fi

  if [[ -n "${HOME:-}" ]]; then
    candidates+=(
      "$HOME/.colima/default/docker.sock"
      "$HOME/.colima/docker.sock"
      "$HOME/.docker/run/docker.sock"
    )
  fi

  candidates+=("/var/run/docker.sock")

  for candidate in "${candidates[@]}"; do
    if [[ -S "$candidate" ]] && docker_socket_responds "$candidate"; then
      export DOCKER_HOST="unix://$candidate"
      log "Using Docker socket from $DOCKER_HOST for workspace builds and gateway runtime."
      return
    fi
  done

  log "No reachable Docker socket detected; relying on gateway driver autodetection."
}

generate_gateway_jwt_bundle() {
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate local smoke-test gateway JWT keys" >&2
    exit 1
  fi

  mkdir -p "$JWT_DIR"
  openssl genpkey -algorithm ed25519 -out "$JWT_DIR/signing.pem" >/dev/null 2>&1
  openssl pkey -in "$JWT_DIR/signing.pem" -pubout -out "$JWT_DIR/public.pem" >/dev/null 2>&1
  printf '%s\n' "$GATEWAY_ID" > "$JWT_DIR/kid"
}

start_dedicated_gateway() {
  printf 'INFO starting dedicated gateway\n'
  log "Starting dedicated gateway id=$GATEWAY_ID endpoint=http://$GATEWAY_ADDR health=http://$HEALTH_ADDR"
  env \
    -u OPENSHELL_GATEWAY_CONFIG \
    -u OPENSHELL_BIND_ADDRESS \
    -u OPENSHELL_SERVER_PORT \
    -u OPENSHELL_HEALTH_PORT \
    -u OPENSHELL_METRICS_PORT \
    -u OPENSHELL_LOG_LEVEL \
    -u OPENSHELL_TLS_CERT \
    -u OPENSHELL_TLS_KEY \
    -u OPENSHELL_TLS_CLIENT_CA \
    -u OPENSHELL_LOCAL_TLS_DIR \
    -u OPENSHELL_DRIVERS \
    -u OPENSHELL_DISABLE_TLS \
    -u OPENSHELL_OIDC_ISSUER \
    -u OPENSHELL_ENABLE_MTLS_AUTH \
    -u OPENSHELL_OIDC_AUDIENCE \
    -u OPENSHELL_OIDC_JWKS_TTL \
    -u OPENSHELL_OIDC_ROLES_CLAIM \
    -u OPENSHELL_OIDC_ADMIN_ROLE \
    -u OPENSHELL_OIDC_USER_ROLE \
    -u OPENSHELL_OIDC_SCOPES_CLAIM \
    -u OPENSHELL_GRPC_RATE_LIMIT_REQUESTS \
    -u OPENSHELL_GRPC_RATE_LIMIT_WINDOW_SECONDS \
    -u OPENSHELL_SERVER_SAN \
    -u OPENSHELL_ENABLE_LOOPBACK_SERVICE_HTTP \
    "OPENSHELL_DB_URL=sqlite://$TMPDIR/gateway.db" \
    "$ROOT/target/debug/openshell-gateway" --config "$TMPDIR/gateway.toml" >"$GATEWAY_LOG" 2>&1 &
  GATEWAY_PID=$!
}

cd "$ROOT"
configure_native_build_env
configure_container_runtime_env
generate_gateway_jwt_bundle
run_setup_step "building gateway" cargo build --quiet -p openshell-server --bin openshell-gateway
run_setup_step "building CLI" cargo build --quiet -p openshell-cli --bin openshell
run_setup_step "building governance interceptor" cargo build --quiet --manifest-path "$EXAMPLE_DIR/Cargo.toml"

"$EXAMPLE_DIR/target/debug/governance-interceptor" \
  --listen "$INTERCEPTOR_ADDR" \
  --policy "$EXAMPLE_DIR/policy.yaml" >"$INTERCEPTOR_LOG" 2>&1 &
INTERCEPTOR_PID=$!

cat > "$TMPDIR/gateway.toml" <<EOF
[openshell]
version = 1

[openshell.gateway]
bind_address = "$GATEWAY_ADDR"
health_bind_address = "$HEALTH_ADDR"
disable_tls = true
log_level = "warn"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$JWT_DIR/signing.pem"
public_key_path = "$JWT_DIR/public.pem"
kid_path = "$JWT_DIR/kid"
gateway_id = "$GATEWAY_ID"
ttl_secs = 0

[[openshell.gateway.interceptors]]
name = "source-control-governance"
grpc_endpoint = "http://$INTERCEPTOR_ADDR"
order = 10
failure_policy = "fail_closed"
timeout = "500ms"
max_response_bytes = 1048576
max_patches = 32
EOF

start_dedicated_gateway

gateway_ready=0
for _ in {1..60}; do
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    fail "gateway starts with interceptor"
  fi
  if curl -fsS "http://$HEALTH_ADDR/healthz" >/dev/null 2>&1; then
    gateway_ready=1
    break
  fi
  sleep 1
done
if [[ "$gateway_ready" == "1" ]]; then
  pass "gateway starts with interceptor"
else
  fail "gateway starts with interceptor"
fi

CLI=(
  env
  -u OPENSHELL_GATEWAY
  -u OPENSHELL_GATEWAY_ENDPOINT
  -u OPENSHELL_GATEWAY_INSECURE
  -u OPENSHELL_SANDBOX_POLICY
  "$ROOT/target/debug/openshell"
  --gateway-endpoint "http://$GATEWAY_ADDR"
)

run_step "allows github provider create" "${CLI[@]}" provider create --name github --type github --credential GITHUB_TOKEN=dummy
run_step "allows gitlab provider create" "${CLI[@]}" provider create --name gitlab --type gitlab --credential GITLAB_TOKEN=dummy

expect_failure "denies non-governed provider create" "${CLI[@]}" provider create --name bitbucket --type github --credential GITHUB_TOKEN=dummy

run_step "creates governed sandbox" "${CLI[@]}" sandbox create --name "$SANDBOX_NAME" --no-auto-providers --keep --no-tty -- /bin/sh -lc true
expect_output_contains "sandbox has github provider" "github" "${CLI[@]}" sandbox provider list "$SANDBOX_NAME"
expect_output_contains "sandbox has gitlab provider" "gitlab" "${CLI[@]}" sandbox provider list "$SANDBOX_NAME"

expect_failure "denies provider attach" "${CLI[@]}" sandbox provider attach "$SANDBOX_NAME" github

expect_failure "denies provider detach" "${CLI[@]}" sandbox provider detach "$SANDBOX_NAME" github

expect_failure "denies policy replacement" "${CLI[@]}" policy set "$SANDBOX_NAME" --policy "$EXAMPLE_DIR/policy.yaml"

run_step "deletes governed sandbox" "${CLI[@]}" sandbox delete "$SANDBOX_NAME"

expect_failure "denies governed provider update" "${CLI[@]}" provider update gitlab --credential GITLAB_TOKEN=changed

expect_failure "denies governed provider delete" "${CLI[@]}" provider delete github

echo "ALL PASS governance interceptor smoke"
