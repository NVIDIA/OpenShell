#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

wrapper_input=${1:?Usage: test-snap-gateway-wrapper.sh <wrapper>}
wrapper_dir=$(cd "$(dirname "$wrapper_input")" && pwd)
wrapper="${wrapper_dir}/$(basename "$wrapper_input")"
work=$(mktemp -d "${TMPDIR:-/tmp}/openshell snap wrapper.XXXXXX")
trap 'rm -rf "$work"' EXIT

snap="$work/snap"
common="$work/common"
log="$work/calls"
expected="$work/expected"
mkdir -p "$snap/bin" "$common"

cat >"$snap/bin/openshell-gateway" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$FAKE_GATEWAY_LOG"
printf 'env:%s|%s|%s\n' \
  "${OPENSHELL_GATEWAY_CONFIG:-}" \
  "${OPENSHELL_DB_URL:-}" \
  "${OPENSHELL_DISABLE_TLS:-}" >>"$FAKE_GATEWAY_LOG"
if [ "${1:-}" = config ] && [ "${2:-}" = preflight ]; then
  if [ "${FAKE_PREFLIGHT_FAIL:-}" = 1 ]; then
    exit 42
  fi
  if [ "${FAKE_REJECT_UNPAIRED_RATE:-}" = 1 ]; then
    case " $* " in
      *" --grpc-rate-limit-requests "*)
        case " $* " in
          *" --grpc-rate-limit-window-seconds "*) ;;
          *) exit 43 ;;
        esac
        ;;
    esac
  fi
fi
EOF
chmod +x "$snap/bin/openshell-gateway"

run_wrapper() {
  local config=$1
  local fail=${2:-}
  if [ "$config" = unset ]; then
    env -u OPENSHELL_GATEWAY_CONFIG \
      SNAP="$snap" \
      SNAP_COMMON="$common" \
      FAKE_GATEWAY_LOG="$log" \
      FAKE_PREFLIGHT_FAIL="$fail" \
      "$wrapper" --trace
  else
    env \
      SNAP="$snap" \
      SNAP_COMMON="$common" \
      OPENSHELL_GATEWAY_CONFIG="$config" \
      FAKE_GATEWAY_LOG="$log" \
      FAKE_PREFLIGHT_FAIL="$fail" \
      "$wrapper" --trace
  fi
}

assert_log() {
  printf '%s\n' "$1" >"$expected"
  if ! cmp -s "$expected" "$log"; then
    echo "FAIL: unexpected call sequence" >&2
    diff -u "$expected" "$log" >&2
    exit 1
  fi
}

override="$work/override.toml"
printf 'operator override\n' >"$override"
cp "$override" "$work/override-before"
: >"$log"
run_wrapper "$override"
assert_log "config preflight -- --trace
env:$override|sqlite:$common/gateway.db?mode=rwc|true
--trace
env:$override|sqlite:$common/gateway.db?mode=rwc|true"
cmp -s "$work/override-before" "$override"

cli_config="$work/cli.toml"
printf 'CLI override\n' >"$cli_config"
cp "$cli_config" "$work/cli-before"
: >"$log"
env \
  SNAP="$snap" \
  SNAP_COMMON="$common" \
  OPENSHELL_GATEWAY_CONFIG="$override" \
  FAKE_GATEWAY_LOG="$log" \
  "$wrapper" --trace --config "$cli_config"
assert_log "config preflight -- --trace --config $cli_config
env:$override|sqlite:$common/gateway.db?mode=rwc|true
--trace --config $cli_config
env:$override|sqlite:$common/gateway.db?mode=rwc|true"
cmp -s "$work/cli-before" "$cli_config"

: >"$log"
if env \
  SNAP="$snap" \
  SNAP_COMMON="$common" \
  OPENSHELL_GATEWAY_CONFIG="$override" \
  FAKE_GATEWAY_LOG="$log" \
  FAKE_PREFLIGHT_FAIL=1 \
  "$wrapper" --config="$cli_config"; then
  echo "FAIL: CLI-selected config preflight failure reached gateway start" >&2
  exit 1
fi
assert_log "config preflight -- --config=$cli_config
env:$override|sqlite:$common/gateway.db?mode=rwc|true"
cmp -s "$work/cli-before" "$cli_config"

: >"$log"
if env \
  SNAP="$snap" \
  SNAP_COMMON="$common" \
  OPENSHELL_GATEWAY_CONFIG="$override" \
  FAKE_GATEWAY_LOG="$log" \
  FAKE_REJECT_UNPAIRED_RATE=1 \
  "$wrapper" --grpc-rate-limit-requests 10; then
  echo "FAIL: invalid daemon overrides reached gateway start" >&2
  exit 1
fi
assert_log "config preflight -- --grpc-rate-limit-requests 10
env:$override|sqlite:$common/gateway.db?mode=rwc|true"

for invalid_selector in terminator nested-config; do
  : >"$log"
  if [ "$invalid_selector" = terminator ]; then
    invalid_args=(--config --)
  else
    invalid_args=(--config "--config=$cli_config")
  fi
  if env \
    SNAP="$snap" \
    SNAP_COMMON="$common" \
    OPENSHELL_GATEWAY_CONFIG="$override" \
    FAKE_GATEWAY_LOG="$log" \
    "$wrapper" "${invalid_args[@]}"; then
    echo "FAIL: invalid $invalid_selector selector reached gateway execution" >&2
    exit 1
  fi
  if [ -s "$log" ]; then
    echo "FAIL: invalid $invalid_selector selector reached preflight" >&2
    exit 1
  fi
done

: >"$log"
env \
  SNAP="$snap" \
  SNAP_COMMON="$common" \
  OPENSHELL_GATEWAY_CONFIG="$override" \
  FAKE_GATEWAY_LOG="$log" \
  "$wrapper" --config=--dash-leading
assert_log "config preflight -- --config=--dash-leading
env:$override|sqlite:$common/gateway.db?mode=rwc|true
--config=--dash-leading
env:$override|sqlite:$common/gateway.db?mode=rwc|true"

canonical="$common/gateway.toml"
printf 'valid schema-v2\n' >"$canonical"
cp "$canonical" "$work/canonical-before"
: >"$log"
run_wrapper unset
assert_log "config preflight -- --config $canonical --trace
env:|sqlite:$common/gateway.db?mode=rwc|true
--config $canonical --trace
env:|sqlite:$common/gateway.db?mode=rwc|true"
cmp -s "$work/canonical-before" "$canonical"

rm "$canonical"
: >"$log"
run_wrapper unset
assert_log "config preflight -- --trace
env:|sqlite:$common/gateway.db?mode=rwc|true
--trace
env:|sqlite:$common/gateway.db?mode=rwc|true"

assert_preflight_failure() {
  local name=$1
  : >"$log"
  if run_wrapper unset 1; then
    echo "FAIL: $name reached gateway start" >&2
    exit 1
  fi
  assert_log "config preflight -- --config $canonical --trace
env:|sqlite:$common/gateway.db?mode=rwc|true"
}

printf 'legacy version = 1\n' >"$canonical"
cp "$canonical" "$work/legacy-before"
assert_preflight_failure legacy
cmp -s "$work/legacy-before" "$canonical"

printf 'not valid TOML = [\n' >"$canonical"
cp "$canonical" "$work/malformed-before"
assert_preflight_failure malformed
cmp -s "$work/malformed-before" "$canonical"

rm "$canonical"
ln -s "$work/missing-target" "$canonical"
readlink "$canonical" >"$work/link-before"
assert_preflight_failure broken-symlink
readlink "$canonical" >"$work/link-after"
cmp -s "$work/link-before" "$work/link-after"

rm "$canonical"
mkdir "$canonical"
printf 'nonregular marker\n' >"$canonical/marker"
cp "$canonical/marker" "$work/marker-before"
assert_preflight_failure nonregular
cmp -s "$work/marker-before" "$canonical/marker"

echo "Snap gateway wrapper tests passed"
