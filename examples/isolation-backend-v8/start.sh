#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 077

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ "$(id -u)" == 0 ]]; then
  echo "Run this example as a non-root user." >&2
  exit 1
fi
cargo build
cargo build --manifest-path ../../Cargo.toml \
  -p openshell-gateway -p openshell-supervisor -p openshell-cli
export PATH="$PWD/target/debug:$PWD/../../target/debug:$PATH"
v8_state_dir="$(mktemp -d /tmp/openshell-v8.XXXXXX)"
v8_gateway_port="${V8_DEMO_PORT:-18770}"
export OPENSHELL_GATEWAY_ENDPOINT="http://127.0.0.1:$v8_gateway_port"
openshell-gateway generate-certs --output-dir "$v8_state_dir/tls"
cat > "$v8_state_dir/gateway.toml" <<TOML
[openshell]
version = 2

[openshell.gateway]
bind_address = "127.0.0.1:$v8_gateway_port"
disable_tls = true
compute_driver = "v8-example"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$v8_state_dir/tls/jwt/signing.pem"
public_key_path = "$v8_state_dir/tls/jwt/public.pem"
kid_path = "$v8_state_dir/tls/jwt/kid"
gateway_id = "v8-local-demo"

[openshell.drivers.v8-example]
socket_path = "$v8_state_dir/compute.sock"
isolation_backend = "example-v8"

[[openshell.supervisor.isolation_backends]]
name = "example-v8"
endpoint = { kind = "unix", socket_path = "$v8_state_dir/backend.sock" }
TOML

v8_children=()
cleanup() {
  trap - EXIT INT TERM
  for ((i=${#v8_children[@]}-1; i>=0; i--)); do
    kill "${v8_children[i]}" 2>/dev/null || true
  done
  for v8_pid in "${v8_children[@]}"; do
    wait "$v8_pid" 2>/dev/null || true
  done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

v8-backend backend --state-dir "$v8_state_dir" > "$v8_state_dir/backend.log" 2>&1 &
v8_children+=("$!")
v8-backend driver --state-dir "$v8_state_dir" --script "${1:-guest.js}" > "$v8_state_dir/driver.log" 2>&1 &
v8_children+=("$!")
for ((i=0; i<100; i++)); do
  if [[ -S "$v8_state_dir/compute.sock" ]]; then break; fi
  if ! kill -0 "${v8_children[1]}" 2>/dev/null; then
    cat "$v8_state_dir/driver.log" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ ! -S "$v8_state_dir/compute.sock" ]]; then
  echo "Timed out waiting for the compute driver; see $v8_state_dir/driver.log" >&2
  exit 1
fi
printf '\nDemo state and logs: %s\n' "$v8_state_dir"
printf 'Gateway: %s\n' "$OPENSHELL_GATEWAY_ENDPOINT"
printf 'Guest request results: tail -f %q/backend.log\n' "$v8_state_dir"
printf 'In another terminal, follow the README to create a sandbox. Ctrl-C stops the demo.\n\n'
openshell-gateway --config "$v8_state_dir/gateway.toml" \
  --db-url "sqlite://$v8_state_dir/gateway.db?mode=rwc" &
v8_children+=("$!")
wait "${v8_children[2]}"
