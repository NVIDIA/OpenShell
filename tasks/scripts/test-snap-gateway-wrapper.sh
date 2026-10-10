#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

wrapper=${1:?Usage: test-snap-gateway-wrapper.sh <wrapper>}
work=$(mktemp -d "${TMPDIR:-/tmp}/openshell snap wrapper.XXXXXX")
trap 'rm -rf "$work"' EXIT

snap="$work/snap"
common="$work/common"
log="$work/calls"
expected="$work/expected"
mkdir -p "$snap/bin" "$common"

cat >"$snap/bin/openshell-gateway" <<'EOF'
#!/bin/sh
printf '%s|config=%s|db=%s|tls=%s\n' \
  "$*" \
  "${OPENSHELL_GATEWAY_CONFIG:-}" \
  "${OPENSHELL_DB_URL:-}" \
  "${OPENSHELL_LOCAL_TLS_DIR:-}" >>"$FAKE_GATEWAY_LOG"
if [ "${1:-}:${2:-}" = config:preflight ] && [ "${FAKE_PREFLIGHT_FAIL:-}" = 1 ]; then
  exit 42
fi
EOF
chmod +x "$snap/bin/openshell-gateway"

run_system_wrapper() {
  env -u OPENSHELL_GATEWAY_CONFIG \
    SNAP="$snap" \
    SNAP_COMMON="$common" \
    OPENSHELL_SNAP_CONFIG_FILE="$common/gateway.toml" \
    OPENSHELL_DB_URL="sqlite:$common/gateway.db?mode=rwc" \
    OPENSHELL_LOCAL_TLS_DIR="$common/tls" \
    FAKE_GATEWAY_LOG="$log" \
    "$wrapper" "$@"
}

assert_log() {
  printf '%s\n' "$1" >"$expected"
  if ! cmp -s "$expected" "$log"; then
    echo "FAIL: unexpected call sequence" >&2
    diff -u "$expected" "$log" >&2
    exit 1
  fi
}

# A missing compatibility config remains optional and OpenShell performs its
# normal config discovery.
: >"$log"
run_system_wrapper --trace
assert_log "config preflight -- --trace|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls
--trace|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls"

# An existing compatibility config is exposed through the standard gateway
# config environment variable for both preflight and startup.
printf 'valid schema-v2\n' >"$common/gateway.toml"
: >"$log"
run_system_wrapper --trace
assert_log "config preflight -- --trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls
--trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls"

# An operator-provided environment path takes precedence over the Snap
# compatibility path, while CLI arguments are replayed unchanged.
override="$work/override.toml"
printf 'operator override\n' >"$override"
: >"$log"
env \
  SNAP="$snap" \
  SNAP_COMMON="$common" \
  OPENSHELL_SNAP_CONFIG_FILE="$common/gateway.toml" \
  OPENSHELL_GATEWAY_CONFIG="$override" \
  OPENSHELL_DB_URL="sqlite:$common/gateway.db?mode=rwc" \
  OPENSHELL_LOCAL_TLS_DIR="$common/tls" \
  FAKE_GATEWAY_LOG="$log" \
  "$wrapper" --config "$work/cli.toml" --trace
assert_log "config preflight -- --config $work/cli.toml --trace|config=$override|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$override|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls
--config $work/cli.toml --trace|config=$override|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls"

# Broken compatibility symlinks are selected so preflight fails closed rather
# than silently falling back to defaults.
rm "$common/gateway.toml"
ln -s "$work/missing.toml" "$common/gateway.toml"
: >"$log"
if FAKE_PREFLIGHT_FAIL=1 run_system_wrapper --trace; then
  echo "FAIL: broken compatibility symlink reached certificate generation" >&2
  exit 1
fi
assert_log "config preflight -- --trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls"

# Preflight failure prevents certificate generation and gateway startup.
: >"$log"
if FAKE_PREFLIGHT_FAIL=1 run_system_wrapper --config --; then
  echo "FAIL: preflight failure reached certificate generation" >&2
  exit 1
fi
assert_log "config preflight -- --config --|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls"

# User mode supplies only XDG roots. The wrapper derives TLS state, leaves the
# database unset for OpenShell's native default, and lets OpenShell discover
# the XDG config itself.
user_common="$work/user-common"
user_tls="$user_common/.local/state/openshell/tls"
: >"$log"
env -u OPENSHELL_GATEWAY_CONFIG \
  -u OPENSHELL_SNAP_CONFIG_FILE \
  -u OPENSHELL_DB_URL \
  -u OPENSHELL_LOCAL_TLS_DIR \
  SNAP="$snap" \
  SNAP_COMMON="$common" \
  XDG_CONFIG_HOME="$user_common/.config" \
  XDG_STATE_HOME="$user_common/.local/state" \
  FAKE_GATEWAY_LOG="$log" \
  "$wrapper" --trace
assert_log "config preflight -- --trace|config=|db=|tls=$user_tls
generate-certs --output-dir $user_tls --server-san host.openshell.internal|config=|db=|tls=$user_tls
--trace|config=|db=|tls=$user_tls"

if env -u OPENSHELL_LOCAL_TLS_DIR -u XDG_STATE_HOME \
  SNAP="$snap" FAKE_GATEWAY_LOG="$log" "$wrapper" --trace \
  >"$work/out" 2>"$work/err"; then
  echo "FAIL: wrapper accepted missing TLS roots" >&2
  exit 1
fi
grep -Fq 'OPENSHELL_LOCAL_TLS_DIR or XDG_STATE_HOME is required' "$work/err"

echo "Snap gateway wrapper tests passed"
