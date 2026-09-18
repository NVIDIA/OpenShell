#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone openshell-gateway backed by the Kubernetes compute driver.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tasks/scripts/gateway-common.sh
source "${ROOT}/tasks/scripts/gateway-common.sh"
# shellcheck source=tasks/scripts/gateway-pull-policy.sh
source "${ROOT}/tasks/scripts/gateway-pull-policy.sh"

PORT="${OPENSHELL_SERVER_PORT:-8080}"
GATEWAY_NAME="${OPENSHELL_GATEWAY_NAME:-kubernetes-dev}"
STATE_DIR="${OPENSHELL_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-kubernetes}"
SANDBOX_NAMESPACE="${OPENSHELL_SANDBOX_NAMESPACE:-kubernetes-dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
SANDBOX_IMAGE_PULL_POLICY="$(normalize_image_pull_policy "${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-if_not_present}")"
GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-}"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
PRIMARY_BIND_IP="${OPENSHELL_BIND_ADDRESS:-127.0.0.1}"
GATEWAY_BIN="${OPENSHELL_GATEWAY_BIN:-${ROOT}/target/debug/openshell-gateway}"

validate_gateway_name "${GATEWAY_NAME}" OPENSHELL_GATEWAY_NAME

if port_is_in_use "${PORT}"; then
  echo "ERROR: port ${PORT} is already in use; free it or set OPENSHELL_SERVER_PORT" >&2
  exit 2
fi

echo "Building openshell-gateway..."
run_mise_task build:gateway

if [[ ! -x "${GATEWAY_BIN}" ]]; then
  echo "ERROR: expected gateway binary at ${GATEWAY_BIN}" >&2
  exit 1
fi

TLS_DIR="${STATE_DIR}/tls"
echo "Generating local gateway credentials..."
"${GATEWAY_BIN}" generate-certs \
  --output-dir "${TLS_DIR}" \
  --server-san "127.0.0.1" \
  --server-san "localhost" \
  --server-san "host.openshell.internal"

mkdir -p "${STATE_DIR}"
CONFIG_PATH="${STATE_DIR}/gateway.toml"
install -m 600 /dev/null "${CONFIG_PATH}"
cat >"${CONFIG_PATH}" <<EOF
[openshell]
version = 2

[openshell.gateway]
name = "${GATEWAY_NAME}"
compute_driver = "kubernetes"
disable_tls = true

[openshell.gateway.otlp]
endpoint = "http://127.0.0.1:4317"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${TLS_DIR}/jwt/signing.pem"
public_key_path = "${TLS_DIR}/jwt/public.pem"
kid_path = "${TLS_DIR}/jwt/kid"
gateway_id = "${GATEWAY_NAME}"
ttl_secs = 3600

[openshell.drivers.kubernetes]
namespace = "${SANDBOX_NAMESPACE}"
default_image = "${SANDBOX_IMAGE}"
image_pull_policy = "${SANDBOX_IMAGE_PULL_POLICY}"
EOF
if [[ -n "${GRPC_ENDPOINT}" ]]; then
  printf 'grpc_endpoint = "%s"\n' "${GRPC_ENDPOINT}" >>"${CONFIG_PATH}"
fi

GATEWAY_ENDPOINT="http://127.0.0.1:${PORT}"
register_local_gateway "${GATEWAY_NAME}" "${GATEWAY_ENDPOINT}" "${PORT}" true

echo "Starting standalone Kubernetes gateway..."
echo "  gateway:   ${GATEWAY_NAME}"
echo "  endpoint:  ${GATEWAY_ENDPOINT}"
echo "  bind:      ${PRIMARY_BIND_IP}:${PORT}"
echo "  namespace: ${SANDBOX_NAMESPACE}"
echo "  state dir: ${STATE_DIR}"
echo
echo "Active gateway set to '${GATEWAY_NAME}'. The CLI now targets this gateway by default."
echo

exec "${GATEWAY_BIN}" \
  --config "${CONFIG_PATH}" \
  --bind-address "${PRIMARY_BIND_IP}" \
  --port "${PORT}" \
  --log-level "${LOG_LEVEL}" \
  --compute-driver kubernetes \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
