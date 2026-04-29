#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e smoke test against a standalone gateway running the
# bundled Docker compute driver.
#
# Unlike the Kubernetes driver (which deploys a k3s cluster) or the VM
# driver (which boots libkrun), the Docker driver runs in-process inside
# the gateway binary and uses the local Docker daemon to run sandbox
# containers. This script:
#
#   1. Builds openshell-gateway, openshell-cli, and a Linux ELF
#      openshell-sandbox binary (via the Docker image build pipeline on
#      non-Linux hosts so macOS linker fd limits are avoided).
#   2. Ensures the sandbox base image exists locally; containers launch
#      from it with the freshly built openshell-sandbox binary bind-mounted
#      over the image-provided copy.
#   3. Generates an ephemeral mTLS PKI (CA, server cert, client cert).
#   4. Starts openshell-gateway with --drivers=docker, binding to a
#      random free host port.
#   5. Installs the client cert into the CLI gateway config dir and
#      runs the Rust smoke test.
#   6. Tears the gateway process down on exit.
#
# Usage: mise run e2e:docker

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d "/tmp/openshell-e2e-docker.XXXXXX")"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"
CLI_BIN="${ROOT}/target/debug/openshell"
STATE_DIR=""
GATEWAY_CONFIG_DIR=""
GATEWAY_PID=""
GATEWAY_LOG="${WORKDIR}/gateway.log"
# Unique sandbox namespace for this test run. Set just before the gateway
# is started so cleanup can filter Docker containers strictly to ones
# this run created, even when other OpenShell sandboxes are present on
# the host. Empty until assigned -- cleanup treats an empty namespace as
# "do nothing" so an early-exit trap never touches unrelated containers.
E2E_NAMESPACE=""

cleanup() {
  local exit_code=$?
  if [ -n "${GATEWAY_PID}" ] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo "Stopping openshell-gateway (pid ${GATEWAY_PID})..."
    kill "${GATEWAY_PID}" 2>/dev/null || true
    wait "${GATEWAY_PID}" 2>/dev/null || true
  fi

  # On failure, preserve sandbox container logs for post-mortem
  # debugging before removing the containers. Filter strictly to
  # containers this test run created (managed-by + this run's unique
  # sandbox namespace) so we never touch unrelated OpenShell sandboxes
  # the developer may be running in parallel.
  if [ "${exit_code}" -ne 0 ] \
     && [ -n "${E2E_NAMESPACE}" ] \
     && command -v docker >/dev/null 2>&1; then
    local ids
    ids=$(docker ps -aq \
      --filter "label=openshell.ai/managed-by=openshell" \
      --filter "label=openshell.ai/sandbox-namespace=${E2E_NAMESPACE}" \
      2>/dev/null || true)
    if [ -n "${ids}" ]; then
      echo "=== sandbox container logs (preserved for debugging) ==="
      for id in ${ids}; do
        echo "--- container ${id} (inspect) ---"
        docker inspect --format '{{.Name}} state={{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}} error={{.State.Error}}' "${id}" 2>/dev/null || true
        echo "--- container ${id} (last 80 log lines) ---"
        docker logs --tail 80 "${id}" 2>&1 || true
      done
      echo "=== end sandbox container logs ==="
    fi
  fi

  # Remove any lingering sandbox containers the gateway failed to clean
  # up. Scope the filter to this run's namespace so we don't force-remove
  # sandboxes belonging to other gateways or test runs on the same host.
  if [ -n "${E2E_NAMESPACE}" ] && command -v docker >/dev/null 2>&1; then
    local stale
    stale=$(docker ps -aq \
      --filter "label=openshell.ai/managed-by=openshell" \
      --filter "label=openshell.ai/sandbox-namespace=${E2E_NAMESPACE}" \
      2>/dev/null || true)
    if [ -n "${stale}" ]; then
      # shellcheck disable=SC2086
      docker rm -f ${stale} >/dev/null 2>&1 || true
    fi
  fi

  if [ "${exit_code}" -ne 0 ] && [ -f "${GATEWAY_LOG}" ]; then
    echo "=== gateway log (preserved for debugging) ==="
    cat "${GATEWAY_LOG}"
    echo "=== end gateway log ==="
  fi

  # Remove gateway CLI config we created so repeated runs don't
  # accumulate stale gateway entries.
  if [ -n "${GATEWAY_CONFIG_DIR}" ] && [ -d "${GATEWAY_CONFIG_DIR}" ]; then
    rm -rf "${GATEWAY_CONFIG_DIR}"
  fi

  rm -rf "${WORKDIR}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Preflight ────────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker CLI is required to run e2e:docker" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon is not reachable (docker info failed)" >&2
  exit 2
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is required to generate ephemeral PKI" >&2
  exit 2
fi

normalize_arch() {
  case "$1" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "$1" ;;
  esac
}

linux_target_triple() {
  case "$1" in
    amd64) echo "x86_64-unknown-linux-gnu" ;;
    arm64) echo "aarch64-unknown-linux-gnu" ;;
    *)
      echo "ERROR: unsupported Docker daemon architecture '$1'" >&2
      exit 2
      ;;
  esac
}

# Detect Linux arch of the Docker daemon so we build the matching
# openshell-sandbox binary.
DAEMON_ARCH="$(normalize_arch "$(docker info --format '{{.Architecture}}' 2>/dev/null || true)")"
SUPERVISOR_TARGET="$(linux_target_triple "${DAEMON_ARCH}")"
HOST_OS="$(uname -s)"
HOST_ARCH="$(normalize_arch "$(uname -m)")"
SUPERVISOR_OUT_DIR="${WORKDIR}/supervisor/${DAEMON_ARCH}"
SUPERVISOR_BIN="${SUPERVISOR_OUT_DIR}/openshell-sandbox"

# ── Build binaries ───────────────────────────────────────────────────
# Cap build parallelism to avoid OOM when run alongside a docker build or
# on memory-constrained developer machines. Override with CARGO_BUILD_JOBS.
CARGO_BUILD_JOBS_ARG=()
if [ -n "${CARGO_BUILD_JOBS:-}" ]; then
  CARGO_BUILD_JOBS_ARG=(-j "${CARGO_BUILD_JOBS}")
fi

echo "Building openshell-gateway and openshell-cli..."
cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
  -p openshell-server --bin openshell-gateway \
  -p openshell-cli --features openshell-core/dev-settings

echo "Building openshell-sandbox for ${SUPERVISOR_TARGET}..."
mkdir -p "${SUPERVISOR_OUT_DIR}"
if [ "${HOST_OS}" = "Linux" ] && [ "${HOST_ARCH}" = "${DAEMON_ARCH}" ]; then
  rustup target add "${SUPERVISOR_TARGET}" >/dev/null 2>&1 || true
  cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
    --release -p openshell-sandbox --target "${SUPERVISOR_TARGET}"
  cp "${ROOT}/target/${SUPERVISOR_TARGET}/release/openshell-sandbox" "${SUPERVISOR_BIN}"
else
  CONTAINER_ENGINE=docker \
  DOCKER_PLATFORM="linux/${DAEMON_ARCH}" \
  DOCKER_OUTPUT="type=local,dest=${SUPERVISOR_OUT_DIR}" \
    bash "${ROOT}/tasks/scripts/docker-build-image.sh" supervisor-output
fi

if [ ! -f "${SUPERVISOR_BIN}" ]; then
  echo "ERROR: expected supervisor binary at ${SUPERVISOR_BIN}" >&2
  exit 1
fi
chmod +x "${SUPERVISOR_BIN}"

# ── Ensure a sandbox base image is available locally ────────────────
# The bundled openshell-sandbox binary enforces a 'sandbox' user/group
# in the image. Use the community sandbox base image (also what real
# deployments default to). Callers can override with
# OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE if they have a smaller local image
# with the required 'sandbox' user.
SANDBOX_IMAGE="${OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
if ! docker image inspect "${SANDBOX_IMAGE}" >/dev/null 2>&1; then
  echo "Pulling ${SANDBOX_IMAGE}..."
  docker pull "${SANDBOX_IMAGE}"
fi

# ── Generate ephemeral mTLS PKI ──────────────────────────────────────
PKI_DIR="${WORKDIR}/pki"
mkdir -p "${PKI_DIR}"
cd "${PKI_DIR}"

cat > openssl.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = openshell-server
[san_server]
subjectAltName = @alt_server
[alt_server]
DNS.1 = localhost
DNS.2 = host.openshell.internal
DNS.3 = host.docker.internal
IP.1 = 127.0.0.1
IP.2 = ::1
[san_client]
subjectAltName = DNS:openshell-client
EOF

openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout ca.key -out ca.crt -subj "/CN=openshell-e2e-ca" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -config openssl.cnf >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 30 -extfile openssl.cnf -extensions san_server >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=openshell-client" >/dev/null 2>&1
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 30 -extfile openssl.cnf -extensions san_client >/dev/null 2>&1

cd "${ROOT}"

# ── Pick a free port ─────────────────────────────────────────────────
pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}
HOST_PORT=$(pick_port)

STATE_DIR="${WORKDIR}/state"
mkdir -p "${STATE_DIR}"

# Containers started by the docker driver reach the host gateway via
# host.openshell.internal (mapped to host-gateway by the driver). The
# gateway itself binds to 0.0.0.0:${HOST_PORT}.
GATEWAY_ENDPOINT="https://host.openshell.internal:${HOST_PORT}"

# Unique per-run sandbox namespace. The Docker driver stamps every
# container with `openshell.ai/sandbox-namespace=<ns>`, so cleanup can
# filter on this value and never touch sandboxes belonging to other
# gateways or test runs on the same host.
E2E_NAMESPACE="e2e-docker-$$-${HOST_PORT}"

echo "Starting openshell-gateway on port ${HOST_PORT} (namespace: ${E2E_NAMESPACE})..."
"${GATEWAY_BIN}" \
  --port "${HOST_PORT}" \
  --drivers docker \
  --sandbox-namespace "${E2E_NAMESPACE}" \
  --tls-cert "${PKI_DIR}/server.crt" \
  --tls-key "${PKI_DIR}/server.key" \
  --tls-client-ca "${PKI_DIR}/ca.crt" \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc" \
  --grpc-endpoint "${GATEWAY_ENDPOINT}" \
  --docker-supervisor-bin "${SUPERVISOR_BIN}" \
  --docker-tls-ca "${PKI_DIR}/ca.crt" \
  --docker-tls-cert "${PKI_DIR}/client.crt" \
  --docker-tls-key "${PKI_DIR}/client.key" \
  --sandbox-image "${SANDBOX_IMAGE}" \
  --sandbox-image-pull-policy IfNotPresent \
  >"${GATEWAY_LOG}" 2>&1 &
GATEWAY_PID=$!

# ── Register the gateway with the CLI ────────────────────────────────
# Writes both metadata.json (for `--gateway <name>` lookup) and the mTLS
# bundle the CLI uses to authenticate to the gateway.
GATEWAY_NAME="openshell-e2e-docker-${HOST_PORT}"
CLI_GATEWAY_ENDPOINT="https://127.0.0.1:${HOST_PORT}"
GATEWAY_CONFIG_DIR="${HOME}/.config/openshell/gateways/${GATEWAY_NAME}"
mkdir -p "${GATEWAY_CONFIG_DIR}/mtls"
cp "${PKI_DIR}/ca.crt"     "${GATEWAY_CONFIG_DIR}/mtls/ca.crt"
cp "${PKI_DIR}/client.crt" "${GATEWAY_CONFIG_DIR}/mtls/tls.crt"
cp "${PKI_DIR}/client.key" "${GATEWAY_CONFIG_DIR}/mtls/tls.key"
cat >"${GATEWAY_CONFIG_DIR}/metadata.json" <<EOF
{
  "name": "${GATEWAY_NAME}",
  "gateway_endpoint": "${CLI_GATEWAY_ENDPOINT}",
  "is_remote": false,
  "gateway_port": ${HOST_PORT}
}
EOF

export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
export OPENSHELL_PROVISION_TIMEOUT=180

# ── Wait for gateway readiness ───────────────────────────────────────
echo "Waiting for gateway to become healthy..."
elapsed=0
timeout=120
while [ "${elapsed}" -lt "${timeout}" ]; do
  if ! kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo "ERROR: openshell-gateway exited before becoming healthy"
    exit 1
  fi
  if "${CLI_BIN}" status >/dev/null 2>&1; then
    echo "Gateway healthy after ${elapsed}s."
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
if [ "${elapsed}" -ge "${timeout}" ]; then
  echo "ERROR: gateway did not become healthy within ${timeout}s"
  exit 1
fi

# ── Run the smoke test ───────────────────────────────────────────────
echo "Running e2e smoke test (gateway: ${OPENSHELL_GATEWAY}, endpoint: ${CLI_GATEWAY_ENDPOINT})..."
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e --test smoke -- --nocapture

echo "Smoke test passed."
