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

# Use regular files as deterministic stand-ins for /dev/kvm, including
# inaccessible and single-permission cases.
kvm_device="$work/kvm"
: >"$kvm_device"
read_only_kvm="$work/read-only-kvm"
write_only_kvm="$work/write-only-kvm"
: >"$read_only_kvm"
: >"$write_only_kvm"
chmod 0400 "$read_only_kvm"
chmod 0200 "$write_only_kvm"
wrapper="$work/openshell-gateway-wrapper"
unavailable_wrapper="$work/openshell-gateway-wrapper-no-kvm"
read_only_wrapper="$work/openshell-gateway-wrapper-read-only-kvm"
write_only_wrapper="$work/openshell-gateway-wrapper-write-only-kvm"
sed "s|kvm_device=/dev/kvm|kvm_device='$kvm_device'|" "$wrapper_source" >"$wrapper"
sed "s|kvm_device=/dev/kvm|kvm_device='$work/missing-kvm'|" "$wrapper_source" >"$unavailable_wrapper"
sed "s|kvm_device=/dev/kvm|kvm_device='$read_only_kvm'|" "$wrapper_source" >"$read_only_wrapper"
sed "s|kvm_device=/dev/kvm|kvm_device='$write_only_kvm'|" "$wrapper_source" >"$write_only_wrapper"
chmod +x "$wrapper" "$unavailable_wrapper" "$read_only_wrapper" "$write_only_wrapper"

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
assert_log "config preflight -- --trace|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=vm
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=vm
--trace|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=vm"

# Without read/write KVM access, leave selection unset so the gateway can run
# its normal driver detection.
: >"$log"
wrapper=$unavailable_wrapper run_system_wrapper --trace
assert_log "config preflight -- --trace|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
--trace|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver="

if [ "$(id -u)" -ne 0 ]; then
  for restricted_wrapper in "$read_only_wrapper" "$write_only_wrapper"; do
    : >"$log"
    wrapper=$restricted_wrapper run_system_wrapper --trace
    assert_log "config preflight -- --trace|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
--trace|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver="
  done
fi

# An existing compatibility config is exposed through the standard gateway
# config environment variable for both preflight and startup.
printf 'valid schema-v2\n' >"$common/gateway.toml"
: >"$log"
run_system_wrapper --trace
assert_log "config preflight -- --trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=vm
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=vm
--trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=vm"

# An explicit TOML selector remains authoritative, including indentation.
printf '[openshell.gateway]\n  compute_driver = "docker"\n' >"$common/gateway.toml"
: >"$log"
run_system_wrapper --trace
assert_log "config preflight -- --trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
--trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver="

# An explicit TOML selector remains authoritative without KVM access.
: >"$log"
wrapper=$unavailable_wrapper run_system_wrapper --trace
assert_log "config preflight -- --trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
--trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver="

# Best-effort TOML inspection recognizes quoted keys and dotted key syntax.
for selector in \
  '  "compute_driver" = "docker"' \
  "  'compute_driver' = \"docker\"" \
  'openshell.gateway.compute_driver = "docker"' \
  '"openshell"."gateway"."compute_driver" = "docker"' \
  "openshell . \"gateway\" . 'compute_driver' = \"docker\""
do
  printf '%s\n' "$selector" >"$common/gateway.toml"
  : >"$log"
  run_system_wrapper --trace
  assert_log "config preflight -- --trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
--trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver="
done

# The deprecated environment selector remains authoritative during migration.
rm "$common/gateway.toml"
: >"$log"
OPENSHELL_DRIVERS=docker run_system_wrapper --trace
assert_log "config preflight -- --trace|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
--trace|config=|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver="

printf '[openshell.gateway]\ncompute_driver = "docker"\n' >"$common/gateway.toml"

# A service-level environment selector takes precedence without reading TOML.
: >"$log"
OPENSHELL_COMPUTE_DRIVER=docker run_system_wrapper --trace
assert_log "config preflight -- --trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=docker
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=docker
--trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=docker"

# An explicit environment selector remains authoritative without KVM access.
: >"$log"
OPENSHELL_COMPUTE_DRIVER=docker wrapper=$unavailable_wrapper run_system_wrapper --trace
assert_log "config preflight -- --trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=docker
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=docker
--trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=docker"

# An operator-provided environment path takes precedence over the snap
# compatibility path, while CLI arguments are replayed unchanged.
override="$work/override.toml"
printf 'operator override\n' >"$override"
cli_config="$work/cli.toml"
printf '[openshell.gateway]\ncompute_driver = "docker"\n' >"$cli_config"
: >"$log"
env \
  SNAP="$snap" \
  SNAP_COMMON="$common" \
  OPENSHELL_SNAP_CONFIG_FILE="$common/gateway.toml" \
  OPENSHELL_GATEWAY_CONFIG="$override" \
  OPENSHELL_DB_URL="sqlite:$common/gateway.db?mode=rwc" \
  OPENSHELL_LOCAL_TLS_DIR="$common/tls" \
  FAKE_GATEWAY_LOG="$log" \
  "$wrapper" --config "$cli_config" --trace
assert_log "config preflight -- --config $cli_config --trace|config=$override|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$override|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
--config $cli_config --trace|config=$override|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver="

# An explicitly empty environment selector is still preserved for gateway
# validation instead of being replaced with the snap default.
: >"$log"
OPENSHELL_COMPUTE_DRIVER= run_system_wrapper --trace
assert_log "config preflight -- --trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
generate-certs --output-dir $common/tls --server-san host.openshell.internal|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=
--trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver="

# Broken compatibility symlinks are selected so preflight fails closed rather
# than silently falling back to defaults.
rm "$common/gateway.toml"
ln -s "$work/missing.toml" "$common/gateway.toml"
: >"$log"
if FAKE_PREFLIGHT_FAIL=1 run_system_wrapper --trace; then
  echo "FAIL: broken compatibility symlink reached certificate generation" >&2
  exit 1
fi
assert_log "config preflight -- --trace|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=vm"

# Preflight failure prevents certificate generation and gateway startup.
: >"$log"
if FAKE_PREFLIGHT_FAIL=1 run_system_wrapper --config --; then
  echo "FAIL: preflight failure reached certificate generation" >&2
  exit 1
fi
assert_log "config preflight -- --config --|config=$common/gateway.toml|db=sqlite:$common/gateway.db?mode=rwc|tls=$common/tls|driver=vm"

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
assert_log "config preflight -- --trace|config=|db=|tls=$user_tls|driver=vm
generate-certs --output-dir $user_tls --server-san host.openshell.internal|config=|db=|tls=$user_tls|driver=vm
--trace|config=|db=|tls=$user_tls|driver=vm"

if env -u OPENSHELL_LOCAL_TLS_DIR -u XDG_STATE_HOME \
  SNAP="$snap" FAKE_GATEWAY_LOG="$log" "$wrapper" --trace \
  >"$work/out" 2>"$work/err"; then
  echo "FAIL: wrapper accepted missing TLS roots" >&2
  exit 1
fi
grep -Fq 'OPENSHELL_LOCAL_TLS_DIR or XDG_STATE_HOME is required' "$work/err"

echo "Snap gateway wrapper tests passed"
