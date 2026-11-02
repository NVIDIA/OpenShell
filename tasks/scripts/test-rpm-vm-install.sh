#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Verify that the installed gateway starts the VM driver from its package path.
set -euo pipefail

gateway_bin=${OPENSHELL_RPM_SMOKE_GATEWAY_BIN:-/usr/bin/openshell-gateway}
driver_bin=${OPENSHELL_RPM_SMOKE_DRIVER_BIN:-/usr/libexec/openshell/openshell-driver-vm}
test -x "$gateway_bin"
test -x "$driver_bin"

smoke_dir=$(mktemp -d)
gateway_pid=
driver_pid=
cleanup() {
  if [[ -n "$gateway_pid" ]]; then
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
  fi
  if [[ -n "$driver_pid" && -e "/proc/$driver_pid/exe" ]]; then
    if [[ "$(readlink -f "/proc/$driver_pid/exe" 2>/dev/null || true)" == "$driver_bin" ]]; then
      kill "$driver_pid" 2>/dev/null || true
    fi
  fi
  rm -rf -- "$smoke_dir"
}
trap cleanup EXIT

cat >"$smoke_dir/gateway.toml" <<EOF
[openshell]
version = 2

[openshell.gateway]
compute_driver = "vm"
disable_tls = true

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.drivers.vm]
bootstrap_image = "unreachable.invalid/vm:preflight"
state_dir = "$smoke_dir/vm-state"
EOF

"$gateway_bin" config preflight --path "$smoke_dir/gateway.toml"
"$gateway_bin" generate-certs --output-dir "$smoke_dir/tls" --server-san host.openshell.internal

smoke_port=$((20000 + RANDOM % 20000))
OPENSHELL_GATEWAY_CONFIG="$smoke_dir/gateway.toml" \
OPENSHELL_LOCAL_TLS_DIR="$smoke_dir/tls" \
OPENSHELL_DB_URL="sqlite:$smoke_dir/openshell.db" \
OPENSHELL_SERVER_PORT="$smoke_port" \
"$gateway_bin" >"$smoke_dir/gateway.log" 2>&1 &
gateway_pid=$!

for _ in {1..50}; do
  if ! kill -0 "$gateway_pid" 2>/dev/null; then
    cat "$smoke_dir/gateway.log" >&2
    echo "gateway exited before starting the packaged VM driver" >&2
    exit 1
  fi
  if [[ ! -r "/proc/$gateway_pid/task/$gateway_pid/children" ]]; then
    sleep 0.2
    continue
  fi
  for child_pid in $(<"/proc/$gateway_pid/task/$gateway_pid/children"); do
    if [[ "$(readlink -f "/proc/$child_pid/exe" 2>/dev/null || true)" == "$driver_bin" ]]; then
      driver_pid=$child_pid
      break
    fi
  done
  if [[ -n "$driver_pid" ]]; then
    sleep 0.5
    if kill -0 "$gateway_pid" 2>/dev/null && kill -0 "$driver_pid" 2>/dev/null; then
      echo "gateway started $driver_bin"
      exit 0
    fi
  fi
  sleep 0.2
done

cat "$smoke_dir/gateway.log" >&2
echo "gateway did not start $driver_bin" >&2
exit 1
