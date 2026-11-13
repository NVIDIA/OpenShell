#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
unset OPENSHELL_COMPUTE_DRIVER OPENSHELL_DRIVERS

wrapper_source=${1:?Usage: test-snap-gateway-wrapper.sh <wrapper>}
work=$(mktemp -d "${TMPDIR:-/tmp}/openshell snap wrapper.XXXXXX")
trap 'rm -rf "$work"' EXIT

snap="$work/snap"
common="$work/common"
log="$work/calls"
expected="$work/expected"
mkdir -p "$snap/bin" "$common"

kvm_device="$work/kvm"
: >"$kvm_device"
wrapper="$work/openshell-gateway-wrapper"
unavailable_wrapper="$work/openshell-gateway-wrapper-no-kvm"
sed "s|kvm_device=/dev/kvm|kvm_device='$kvm_device'|" "$wrapper_source" >"$wrapper"
sed "s|kvm_device=/dev/kvm|kvm_device='$work/missing-kvm'|" "$wrapper_source" >"$unavailable_wrapper"
chmod +x "$wrapper" "$unavailable_wrapper"

cat >"$snap/bin/openshell-gateway" <<'EOF'
#!/bin/sh
printf '%s|config=%s|db=%s|tls=%s|driver=%s\n' \
  "$*" \
  "${OPENSHELL_GATEWAY_CONFIG:-}" \
  "${OPENSHELL_DB_URL:-}" \
  "${OPENSHELL_LOCAL_TLS_DIR:-}" \
  "${OPENSHELL_COMPUTE_DRIVER:-}" >>"$FAKE_GATEWAY_LOG"
if [ "${1:-}:${2:-}" = config:preflight ] && [ "${FAKE_PREFLIGHT_FAIL:-}" = 1 ]; then
  exit 42
fi
EOF
chmod +x "$snap/bin/openshell-gateway"

run_system_wrapper() {
  env -u OPENSHELL_GATEWAY_CONFIG \
    SNAP="$snap" \
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

assert_vm_config() {
  local config=$1
  local expected_config="$work/expected-config"
  printf '%s\n' \
    '[openshell]' \
    'version = 2' \
    '' \
    '[openshell.gateway]' \
    'compute_driver = "vm"' >"$expected_config"
  cmp "$expected_config" "$config"
  [[ $(stat -c '%a' "$config") == 600 ]]
}

# Fresh system gateway state with KVM access gets a persistent VM config.
: >"$log"
run_system_wrapper
assert_vm_config "$common/gateway.toml"
assert_log "config preflight --|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver="

# Existing configuration is never replaced.
printf 'operator configuration\n' >"$common/gateway.toml"
: >"$log"
run_system_wrapper --trace
[[ $(<"$common/gateway.toml") == 'operator configuration' ]]

# Existing file-backed database state leaves driver selection to the gateway.
rm "$common/gateway.toml"
: >"$common/gateway.db"
: >"$log"
run_system_wrapper
[[ ! -e "$common/gateway.toml" ]]

# Without KVM access, the wrapper leaves driver selection to the gateway.
rm "$common/gateway.db"
: >"$log"
wrapper=$unavailable_wrapper run_system_wrapper
[[ ! -e "$common/gateway.toml" ]]

# SQLite memory databases have no persisted state and get the VM default.
for database_url in \
  'sqlite::memory:' \
  'sqlite::memory:?cache=shared' \
  'sqlite://?mode=memory' \
  'sqlite:/tmp/named-memory?mode=memory'
do
  memory_config="$work/memory/$(printf '%s' "$database_url" | tr '/:?' '___').toml"
  rm -f "$memory_config"
  env \
    SNAP="$snap" \
    OPENSHELL_GATEWAY_CONFIG="$memory_config" \
    OPENSHELL_DB_URL="$database_url" \
    OPENSHELL_LOCAL_TLS_DIR="$common/tls" \
    FAKE_GATEWAY_LOG="$log" \
    "$wrapper"
  assert_vm_config "$memory_config"
done

# Non-SQLite databases do not get a generated config.
remote_config="$work/remote/gateway.toml"
env \
  SNAP="$snap" \
  OPENSHELL_GATEWAY_CONFIG="$remote_config" \
  OPENSHELL_DB_URL='postgresql://db.example.test/openshell' \
  OPENSHELL_LOCAL_TLS_DIR="$common/tls" \
  FAKE_GATEWAY_LOG="$log" \
  "$wrapper"
[[ ! -e "$remote_config" ]]

# User mode derives its config and database paths from the persistent XDG roots.
user_common="$work/user-common"
user_config="$user_common/.config/openshell/gateway.toml"
user_db="sqlite:$user_common/.local/state/openshell/gateway/openshell.db?mode=rwc"
user_tls="$user_common/.local/state/openshell/tls"
: >"$log"
env -u OPENSHELL_GATEWAY_CONFIG \
  -u OPENSHELL_SNAP_CONFIG_FILE \
  -u OPENSHELL_DB_URL \
  -u OPENSHELL_LOCAL_TLS_DIR \
  SNAP="$snap" \
  XDG_CONFIG_HOME="$user_common/.config" \
  XDG_STATE_HOME="$user_common/.local/state" \
  FAKE_GATEWAY_LOG="$log" \
  "$wrapper"
assert_vm_config "$user_config"
assert_log "config preflight --|config=$user_config|db=$user_db|tls=$user_tls|driver=
generate-certs --output-dir $user_tls --server-san host.openshell.internal|config=$user_config|db=$user_db|tls=$user_tls|driver=
|config=$user_config|db=$user_db|tls=$user_tls|driver="

# Existing config path objects are preserved for gateway preflight to reject.
rm -f "$common/gateway.toml"
ln -s "$work/missing.toml" "$common/gateway.toml"
: >"$log"
if FAKE_PREFLIGHT_FAIL=1 run_system_wrapper; then
  echo "FAIL: broken config symlink reached certificate generation" >&2
  exit 1
fi
[[ -L "$common/gateway.toml" ]]
assert_log "config preflight --|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver="

if env -u OPENSHELL_LOCAL_TLS_DIR -u XDG_STATE_HOME \
  SNAP="$snap" FAKE_GATEWAY_LOG="$log" "$wrapper" \
  >"$work/out" 2>"$work/err"; then
  echo "FAIL: wrapper accepted missing TLS roots" >&2
  exit 1
fi
grep -Fq 'OPENSHELL_LOCAL_TLS_DIR or XDG_STATE_HOME is required' "$work/err"

echo "Snap gateway wrapper tests passed"
