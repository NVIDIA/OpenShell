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
js_sbx_state_dir="$(mktemp -d /tmp/js-sbx.XXXXXX)"
js_sbx_gateway_port="${JS_SBX_PORT:-18770}"
export OPENSHELL_GATEWAY_ENDPOINT="http://127.0.0.1:$js_sbx_gateway_port"
openshell-gateway generate-certs --output-dir "$js_sbx_state_dir/tls"
cat > "$js_sbx_state_dir/gateway.toml" <<TOML
[openshell]
version = 2

[openshell.gateway]
bind_address = "127.0.0.1:$js_sbx_gateway_port"
disable_tls = true
compute_driver = "js-sbx-example"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$js_sbx_state_dir/tls/jwt/signing.pem"
public_key_path = "$js_sbx_state_dir/tls/jwt/public.pem"
kid_path = "$js_sbx_state_dir/tls/jwt/kid"
gateway_id = "js-sbx-demo"

[openshell.drivers.js-sbx-example]
socket_path = "$js_sbx_state_dir/compute.sock"
isolation_backend = "js-sbx"

[[openshell.supervisor.isolation_backends]]
name = "js-sbx"
endpoint = { kind = "unix", socket_path = "$js_sbx_state_dir/backend.sock" }
TOML

js_sbx_children=()
cleanup() {
  trap - EXIT INT TERM
  for ((i=${#js_sbx_children[@]}-1; i>=0; i--)); do
    kill "${js_sbx_children[i]}" 2>/dev/null || true
  done
  for js_sbx_pid in "${js_sbx_children[@]}"; do
    wait "$js_sbx_pid" 2>/dev/null || true
  done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

js-sbx serve --state-dir "$js_sbx_state_dir" > "$js_sbx_state_dir/backend.log" 2>&1 &
js_sbx_children+=("$!")
js-sbx driver --state-dir "$js_sbx_state_dir" --script "${1:-guest.js}" > "$js_sbx_state_dir/driver.log" 2>&1 &
js_sbx_children+=("$!")
for ((i=0; i<100; i++)); do
  if [[ -S "$js_sbx_state_dir/compute.sock" ]]; then break; fi
  if ! kill -0 "${js_sbx_children[1]}" 2>/dev/null; then
    cat "$js_sbx_state_dir/driver.log" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ ! -S "$js_sbx_state_dir/compute.sock" ]]; then
  echo "Timed out waiting for the compute driver; see $js_sbx_state_dir/driver.log" >&2
  exit 1
fi
printf '\nDemo state and logs: %s\n' "$js_sbx_state_dir"
printf 'Gateway: %s\n' "$OPENSHELL_GATEWAY_ENDPOINT"
printf 'Guest output: tail -f %q/backend.log\n' "$js_sbx_state_dir"
printf 'In another terminal, follow the README to create a sandbox. Ctrl-C stops the demo.\n\n'
openshell-gateway --config "$js_sbx_state_dir/gateway.toml" \
  --db-url "sqlite://$js_sbx_state_dir/gateway.db?mode=rwc" &
js_sbx_children+=("$!")
wait "${js_sbx_children[2]}"
