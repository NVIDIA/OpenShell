#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLE_DIR="$ROOT/examples/governance-interceptor"
TMPDIR="$(mktemp -d)"
JWT_DIR="$TMPDIR/jwt"
LOG_DIR="${OPENSHELL_GOVERNANCE_LOG_DIR:-$TMPDIR/logs}"
SMOKE_LOG="$LOG_DIR/smoke.log"
INTERCEPTOR_LOG="$LOG_DIR/interceptor.log"
GATEWAY_LOG="$LOG_DIR/gateway.log"
INTERCEPTOR_ADDR="${OPENSHELL_GOVERNANCE_INTERCEPTOR_ADDR:-127.0.0.1:18081}"
GATEWAY_ADDR="${OPENSHELL_GOVERNANCE_GATEWAY_ADDR:-127.0.0.1:18080}"
HEALTH_ADDR="${OPENSHELL_GOVERNANCE_HEALTH_ADDR:-127.0.0.1:18082}"
DRIVER="${OPENSHELL_GOVERNANCE_SMOKE_DRIVER:-}"
SANDBOX_NAME="${OPENSHELL_GOVERNANCE_SANDBOX_NAME:-governed-smoke-$$}"
ROOT_BUILD_ARGS=()
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
  printf '  smoke log: %s\n' "$SMOKE_LOG" >&2
  printf '  gateway log: %s\n' "$GATEWAY_LOG" >&2
  printf '  interceptor log: %s\n' "$INTERCEPTOR_LOG" >&2
  exit 1
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

missing_z3() {
  cat >&2 <<'EOF'
No usable local Z3 installation found.

Install Z3 or point the build at an existing install, then rerun:
  brew install z3
  Z3_SYS_Z3_HEADER=/path/to/include/z3.h Z3_LIBRARY_PATH_OVERRIDE=/path/to/lib examples/governance-interceptor/smoke.sh

The bundled Z3 build downloads source metadata from GitHub and can fail in offline or rate-limited environments.
To opt into that path anyway, set OPENSHELL_GOVERNANCE_ALLOW_BUNDLED_Z3=1.
EOF
  exit 1
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

configure_z3_build_env() {
  if [[ -n "${Z3_SYS_Z3_HEADER:-}" || -n "${Z3_LIBRARY_PATH_OVERRIDE:-}" ]]; then
    log "Using caller-provided Z3 build environment."
    return
  fi

  if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists z3 >/dev/null 2>&1; then
    log "Using pkg-config Z3 for workspace builds."
    return
  fi

  z3_prefix=""
  if command -v brew >/dev/null 2>&1; then
    z3_prefix="$(brew --prefix z3 2>/dev/null || true)"
  fi

  for candidate in "$z3_prefix" /opt/homebrew/opt/z3 /usr/local/opt/z3; do
    if [[ -n "$candidate" && -f "$candidate/include/z3.h" && -d "$candidate/lib" ]]; then
      log "Using local Z3 from ${candidate} for workspace builds."
      export Z3_SYS_Z3_HEADER="${candidate}/include/z3.h"
      export Z3_LIBRARY_PATH_OVERRIDE="${candidate}/lib"
      return
    fi
  done

  if [[ "${OPENSHELL_GOVERNANCE_ALLOW_BUNDLED_Z3:-0}" == "1" ]]; then
    log "Falling back to bundled Z3 for workspace builds."
    ROOT_BUILD_ARGS+=(--features bundled-z3)
    return
  fi

  missing_z3
}

generate_gateway_jwt_bundle() {
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate local smoke-test gateway JWT keys" >&2
    exit 1
  fi

  mkdir -p "$JWT_DIR"
  openssl genpkey -algorithm ed25519 -out "$JWT_DIR/signing.pem" >/dev/null 2>&1
  openssl pkey -in "$JWT_DIR/signing.pem" -pubout -out "$JWT_DIR/public.pem" >/dev/null 2>&1
  printf 'governance-smoke\n' > "$JWT_DIR/kid"
}

cd "$ROOT"
configure_native_build_env
configure_z3_build_env
generate_gateway_jwt_bundle
run_step "build gateway" cargo build --quiet -p openshell-server --bin openshell-gateway "${ROOT_BUILD_ARGS[@]}"
run_step "build CLI" cargo build --quiet -p openshell-cli --bin openshell "${ROOT_BUILD_ARGS[@]}"
run_step "build governance interceptor" cargo build --quiet --manifest-path "$EXAMPLE_DIR/Cargo.toml"

"$EXAMPLE_DIR/target/debug/governance-interceptor" \
  --listen "$INTERCEPTOR_ADDR" \
  --policy "$EXAMPLE_DIR/policy.yaml" >"$INTERCEPTOR_LOG" 2>&1 &
INTERCEPTOR_PID=$!

driver_line=""
if [[ -n "$DRIVER" ]]; then
  driver_line="compute_drivers = [\"$DRIVER\"]"
fi

cat > "$TMPDIR/gateway.toml" <<EOF
[openshell]
version = 1

[openshell.gateway]
bind_address = "$GATEWAY_ADDR"
health_bind_address = "$HEALTH_ADDR"
disable_tls = true
log_level = "warn"
$driver_line

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$JWT_DIR/signing.pem"
public_key_path = "$JWT_DIR/public.pem"
kid_path = "$JWT_DIR/kid"
gateway_id = "governance-smoke"
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

OPENSHELL_DB_URL="sqlite://$TMPDIR/gateway.db" \
  "$ROOT/target/debug/openshell-gateway" --config "$TMPDIR/gateway.toml" >"$GATEWAY_LOG" 2>&1 &
GATEWAY_PID=$!

gateway_ready=0
for _ in {1..60}; do
  if curl -fsS "http://$HEALTH_ADDR/healthz" >/dev/null 2>&1; then
    gateway_ready=1
    break
  fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    fail "gateway starts with interceptor"
  fi
  sleep 1
done
if [[ "$gateway_ready" == "1" ]]; then
  pass "gateway starts with interceptor"
else
  fail "gateway starts with interceptor"
fi

CLI=("$ROOT/target/debug/openshell" --gateway-endpoint "http://$GATEWAY_ADDR")

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
