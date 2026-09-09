#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
SUITE="$ROOT/e2e/response-middleware-live"
OUT="${MIDDLEWARE_LIVE_OUTPUT:-$SUITE/output}"
mkdir -p "$OUT"
SERVICE_HOST="${MIDDLEWARE_LIVE_HOST:-$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')}"
: "${SERVICE_HOST:?Set MIDDLEWARE_LIVE_HOST to the reachable host IPv4 address}"
RUNTIME="$(mktemp -d /tmp/pr3074-runtime.XXXXXX)"
printf '%s\n' "$RUNTIME" > "$OUT/runtime-path"
openssl genpkey -algorithm ed25519 -out "$RUNTIME/signing.pem"
openssl pkey -in "$RUNTIME/signing.pem" -pubout -out "$RUNTIME/public.pem"
echo pr3074-live > "$RUNTIME/kid"
cat > "$OUT/gateway.toml" <<EOF
[openshell]
version = 1
[openshell.gateway.auth]
allow_unauthenticated_users = true
[openshell.gateway.gateway_jwt]
signing_key_path = "$RUNTIME/signing.pem"
public_key_path = "$RUNTIME/public.pem"
kid_path = "$RUNTIME/kid"
gateway_id = "pr3074-live"
ttl_secs = 0
[openshell.drivers.docker]
supervisor_image = "localhost/openshell-pr3074/supervisor:555ff3289"
sandbox_namespace = "pr3074-live"
image_pull_policy = "IfNotPresent"
EOF
for i in 1 2 3 4; do
  limit=262144
  if [[ "$i" == 4 ]]; then limit=32; fi
  cat >> "$OUT/gateway.toml" <<EOF
[[openshell.supervisor.middleware]]
name = "fixture-$i"
grpc_endpoint = "http://$SERVICE_HOST:$((18190+i))"
allow_insecure_transport = true
max_payload_bytes = $limit
timeout = "150ms"
EOF
done
exec env -u OPENSHELL_DRIVERS "$ROOT/target/debug/openshell-gateway" \
  --drivers docker --config "$OUT/gateway.toml" --bind-address 127.0.0.1 \
  --port 18201 --health-port 18202 --metrics-port 0 --log-level info \
  --disable-tls --db-url "sqlite://$RUNTIME/gateway.db"
