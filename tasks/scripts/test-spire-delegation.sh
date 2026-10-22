#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the gateway's SPIRE delegated-identity test against a real
# SPIRE server and agent.
#
# Downloads a pinned, checksum-verified SPIRE release, starts a server and an
# agent with a private admin socket, authorizes this user's processes as the
# delegate, registers the sandbox entries the test expects, and runs the
# ignored `spire_tests` test in openshell-server.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPIRE_VERSION="1.15.4"
case "$(uname -m)" in
  x86_64 | amd64)
    SPIRE_ARCH=amd64
    SPIRE_SHA256=d8e3ee9a9d48636249484d91af37566dfc0a9d7e71edcbe7acd49cf18bc3c87c
    ;;
  aarch64 | arm64)
    SPIRE_ARCH=arm64
    SPIRE_SHA256=81d9b69d662c7813f905805cafd9f2e6d2255639b65c9e1b7297deb2b1df3eb0
    ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 2
    ;;
esac
if [ "$(uname -s)" != "Linux" ]; then
  echo "test:spire-delegation requires Linux" >&2
  exit 2
fi

CACHE="${OPENSHELL_SPIRE_CACHE:-${ROOT}/target/spire}"
ARCHIVE="${CACHE}/spire-${SPIRE_VERSION}-linux-${SPIRE_ARCH}-musl.tar.gz"
BIN="${CACHE}/spire-${SPIRE_VERSION}/bin"
mkdir -p "${CACHE}"
if [ ! -x "${BIN}/spire-server" ] || [ ! -x "${BIN}/spire-agent" ]; then
  curl -fsSL -o "${ARCHIVE}" \
    "https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-${SPIRE_ARCH}-musl.tar.gz"
  echo "${SPIRE_SHA256}  ${ARCHIVE}" | sha256sum -c -
  tar -xzf "${ARCHIVE}" -C "${CACHE}" \
    "spire-${SPIRE_VERSION}/bin/spire-server" "spire-${SPIRE_VERSION}/bin/spire-agent"
fi

# Unix socket paths must stay short.
WORK="$(mktemp -d /tmp/osspire.XXXXXX)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  done
  rm -rf "${WORK}"
}
trap cleanup EXIT

TRUST_DOMAIN="openshell.test"
GATEWAY_ID="gw-test"
ID_PREFIX="spiffe://${TRUST_DOMAIN}/openshell"
DELEGATE_ID="spiffe://${TRUST_DOMAIN}/openshell/shared-gateway"
NODE_ID="spiffe://${TRUST_DOMAIN}/node/test"
SERVER_SOCKET="${WORK}/server/api.sock"
ADMIN_SOCKET="${WORK}/agent/private/admin.sock"
SERVER_PORT="$(uv run --no-project python -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
mkdir -p "${WORK}/server" "${WORK}/agent/public" "${WORK}/agent/private"

cat >"${WORK}/server.conf" <<EOF
server {
  bind_address = "127.0.0.1"
  bind_port = "${SERVER_PORT}"
  socket_path = "${SERVER_SOCKET}"
  trust_domain = "${TRUST_DOMAIN}"
  data_dir = "${WORK}/server"
  log_level = "WARN"
  default_jwt_svid_ttl = "5m"
}
plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "${WORK}/server/datastore.sqlite3"
    }
  }
  NodeAttestor "join_token" {
    plugin_data {}
  }
  KeyManager "memory" {
    plugin_data {}
  }
}
EOF

cat >"${WORK}/agent.conf" <<EOF
agent {
  data_dir = "${WORK}/agent"
  log_level = "WARN"
  server_address = "127.0.0.1"
  server_port = "${SERVER_PORT}"
  socket_path = "${WORK}/agent/public/api.sock"
  admin_socket_path = "${ADMIN_SOCKET}"
  authorized_delegates = ["${DELEGATE_ID}"]
  trust_bundle_path = "${WORK}/bundle.pem"
  trust_domain = "${TRUST_DOMAIN}"
}
plugins {
  NodeAttestor "join_token" {
    plugin_data {}
  }
  KeyManager "memory" {
    plugin_data {}
  }
  WorkloadAttestor "unix" {
    plugin_data {}
  }
}
EOF

wait_healthy() {
  local binary=$1 socket=$2
  for _ in $(seq 1 60); do
    if "${BIN}/${binary}" healthcheck -socketPath "${socket}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "${binary} did not become healthy" >&2
  return 1
}

server() {
  "${BIN}/spire-server" "$@" -socketPath "${SERVER_SOCKET}"
}

"${BIN}/spire-server" run -config "${WORK}/server.conf" >"${WORK}/server.log" 2>&1 &
PIDS+=($!)
wait_healthy spire-server "${SERVER_SOCKET}"
server bundle show >"${WORK}/bundle.pem"
JOIN_TOKEN="$(server token generate -spiffeID "${NODE_ID}" | awk '/^Token:/ {print $2}')"
"${BIN}/spire-agent" run -config "${WORK}/agent.conf" -joinToken "${JOIN_TOKEN}" >"${WORK}/agent.log" 2>&1 &
PIDS+=($!)
wait_healthy spire-agent "${WORK}/agent/public/api.sock"

entry() {
  server entry create -parentID "${NODE_ID}" -spiffeID "$1" -selector "$2" >/dev/null
}
sandbox_id() {
  cat /proc/sys/kernel/random/uuid
}
sandbox_entry() {
  entry "${ID_PREFIX}/gateway/${GATEWAY_ID}/sandbox/$2" "openshell:sandbox:${GATEWAY_ID}:$1"
}

# The delegate: this user's processes, attested over the admin socket.
entry "${DELEGATE_ID}" "unix:uid:$(id -u)"
ALPHA="$(sandbox_id)"
BETA="$(sandbox_id)"
UNREGISTERED="$(sandbox_id)"
MISREGISTERED="$(sandbox_id)"
AMBIGUOUS="$(sandbox_id)"
sandbox_entry "${ALPHA}" "${ALPHA}"
sandbox_entry "${BETA}" "${BETA}"
# Operator mistakes the gateway must refuse rather than resolve.
sandbox_entry "${MISREGISTERED}" "${ALPHA}"
sandbox_entry "${AMBIGUOUS}" "${AMBIGUOUS}"
sandbox_entry "${AMBIGUOUS}" "${AMBIGUOUS}-other"

status=0
OPENSHELL_TEST_SPIRE_ADMIN_SOCKET="${ADMIN_SOCKET}" \
  OPENSHELL_TEST_SPIRE_ID_PREFIX="${ID_PREFIX}" \
  OPENSHELL_TEST_SPIRE_GATEWAY_ID="${GATEWAY_ID}" \
  OPENSHELL_TEST_SPIRE_SANDBOX_ALPHA="${ALPHA}" \
  OPENSHELL_TEST_SPIRE_SANDBOX_BETA="${BETA}" \
  OPENSHELL_TEST_SPIRE_SANDBOX_UNREGISTERED="${UNREGISTERED}" \
  OPENSHELL_TEST_SPIRE_SANDBOX_MISREGISTERED="${MISREGISTERED}" \
  OPENSHELL_TEST_SPIRE_SANDBOX_AMBIGUOUS="${AMBIGUOUS}" \
  cargo test -p openshell-server --lib spiffe_delegation::tests \
  -- --ignored --nocapture || status=$?
if [ "${status}" -ne 0 ]; then
  echo "--- spire-server log" >&2
  tail -n 50 "${WORK}/server.log" >&2 || true
  echo "--- spire-agent log" >&2
  tail -n 50 "${WORK}/agent.log" >&2 || true
fi
exit "${status}"
