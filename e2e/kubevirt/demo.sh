#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone OpenShell gateway on the host whose Kubernetes compute
# driver runs in `runtime = "kubevirt"` mode against the local `kvpoc` k3d
# cluster (see e2e/kubevirt/README.md for the full PoC walkthrough).
#
# Mirrors tasks/scripts/gateway-vm.sh (the libkrun VM driver dev gateway) but
# provisions KubeVirt VirtualMachines instead. The gateway runs on the host
# with the k3d kubeconfig; sandbox guests reach it over the k3d docker bridge
# (http://<bridge-gateway>:<port>).
#
# Prerequisites (see README.md):
#   - kvpoc k3d cluster with KubeVirt deployed and the guest image imported
#   - e2e/kubevirt/build-guest-image.sh has been run
#
# Usage: e2e/kubevirt/demo.sh [--demo | --probes]
#   --demo    after the gateway starts, run the create/exec/teardown demo
#             (requires the gateway to stay in the foreground; the demo runs
#             against it from a background shell)
#   --probes  after the gateway starts, run the root-workload attack-surface
#             probes (e2e/kubevirt/run-probes.sh): in-guest reset (reboot
#             syscall + iTCO watchdog), fake qemu-guest-agent, virtiofsd
#             privileged operations, and the launcher-netns listener audit

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${OPENSHELL_SERVER_PORT:-18085}"
GATEWAY_NAME="kvpoc"
STATE_DIR="${ROOT}/.cache/gateway-kubevirt"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
CARGO_TARGET="${CARGO_TARGET_DIR:-${ROOT}/target}"
GATEWAY_BIN="${CARGO_TARGET}/release/openshell-gateway"
OPENSHELL_CLI="${CARGO_TARGET}/release/openshell"
SANDBOX_NAMESPACE="kvpoc-sandboxes"
GUEST_IMAGE="${OPENSHELL_KVPOC_GUEST_IMAGE:-kvpoc/openshell-sandbox-vm:dev}"

RUN_DEMO=0
RUN_PROBES=0
case "${1:-}" in
    --demo) RUN_DEMO=1 ;;
    --probes) RUN_PROBES=1 ;;
esac
# The probes exercise the root workload mode by definition; the gateway's
# kubevirt config must select it at render time, so set the variable here
# (before the gateway TOML heredoc below reads it).
if [ "${RUN_PROBES}" = "1" ]; then
    export OPENSHELL_KVPOC_WORKLOAD=root
fi

# Supervisor topology for this run: "dedicated" (the default — one
# supervisor Pod per sandbox, matching the pod path's default) or "gateway"
# (the Helm-shared supervisor). Exported for run-demo.sh, whose checks are
# topology-aware.
TOPOLOGY="${OPENSHELL_KVPOC_TOPOLOGY:-dedicated}"
case "${TOPOLOGY}" in
    dedicated|gateway) ;;
    *) echo "OPENSHELL_KVPOC_TOPOLOGY must be 'dedicated' or 'gateway', got '${TOPOLOGY}'" >&2; exit 1 ;;
esac
export OPENSHELL_KVPOC_TOPOLOGY="${TOPOLOGY}"

# The k3d docker bridge gateway is the host address guests use to reach the
# gateway (k3d prints it at cluster creation; derive it from the network).
CLUSTER="${OPENSHELL_KVPOC_CLUSTER:-kvpoc}"
# The bridge gateway is the host address guests use to reach the gateway.
# Docker and podman report it with different JSON shapes; try both.
BRIDGE_IP="$(docker network inspect "k3d-${CLUSTER}" \
    -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)"
if [ -z "${BRIDGE_IP}" ]; then
    BRIDGE_IP="$(podman network inspect "k3d-${CLUSTER}" \
        -f '{{(index .Subnets 0).Gateway}}' 2>/dev/null || true)"
fi
[ -n "${BRIDGE_IP}" ] || { echo "could not resolve the k3d-${CLUSTER} bridge gateway IP" >&2; exit 1; }
GRPC_ENDPOINT="https://${BRIDGE_IP}:${PORT}"

echo "==> Building openshell-gateway and openshell CLI"
cargo build --release -p openshell-gateway -p openshell-cli

TLS_DIR="${STATE_DIR}/tls"
# Shared supervisor: rendered from the OpenShell Helm chart (see
# e2e/kubevirt/README.md) into the release namespace. The gateway mints
# the supervisor assignment token into the token Secret and resolves the
# Service (ClusterIP, selector, port) at create time.
SUPERVISOR_SERVICE="${OPENSHELL_KVPOC_SUPERVISOR_SERVICE:-kvpoc-openshell-supervisor}"
SUPERVISOR_NAMESPACE="${OPENSHELL_KVPOC_SUPERVISOR_NAMESPACE:-openshell}"
SUPERVISOR_PORT="${OPENSHELL_KVPOC_SUPERVISOR_PORT:-5500}"
SUPERVISOR_TOKEN_SECRET="${OPENSHELL_KVPOC_SUPERVISOR_TOKEN_SECRET:-kvpoc-openshell-supervisor-token}"
SUPERVISOR_CA_SECRET="${OPENSHELL_KVPOC_SUPERVISOR_CA_SECRET:-kvpoc-server-tls}"
PKI_DIR="${STATE_DIR}/tls/pki"
if [ ! -f "${PKI_DIR}/server/tls.crt" ]; then
    mkdir -p "${PKI_DIR}"
    "${GATEWAY_BIN}" generate-certs --output-dir "${PKI_DIR}" \
        --server-san 127.0.0.1 --server-san "${BRIDGE_IP}" \
        --server-san localhost --server-san "${GATEWAY_NAME}" \
        >/dev/null
fi
# Keep the supervisor's gateway-CA Secret in sync with the PKI the gateway
# serves (the supervisor mounts it to verify the assignment-stream
# connection). See e2e/kubevirt/README.md for the supervisor deployment.
if kubectl get namespace "${SUPERVISOR_NAMESPACE}" >/dev/null 2>&1; then
    kubectl -n "${SUPERVISOR_NAMESPACE}" create secret generic "${SUPERVISOR_CA_SECRET}" \
        --from-file=ca.crt="${PKI_DIR}/ca.crt" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
fi
# The dedicated topology's supervisor Pods live in the sandbox namespace and
# verify the gateway through this CA (client_tls_secret_name).
kubectl create namespace "${SANDBOX_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "${SANDBOX_NAMESPACE}" create secret generic "${SUPERVISOR_CA_SECRET}" \
    --from-file=ca.crt="${PKI_DIR}/ca.crt" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if [ ! -f "${TLS_DIR}/jwt/signing.pem" ]; then
    echo "==> Generating local gateway credentials"
    "${GATEWAY_BIN}" generate-certs --output-dir "${TLS_DIR}"
fi

mkdir -p "${STATE_DIR}"
# The demo is single-shot: drop any sandbox records left by a previous run
# so `sandbox create --name kvpoc-demo` is reproducible. Nothing durable is
# kept in this gateway.
rm -f "${STATE_DIR}"/gateway.db*
# Topology-dependent config fragments: the gateway topology selects the
# Helm-shared supervisor; the dedicated default (matching the pod path's
# default) runs one supervisor Pod per sandbox with the locally imported
# supervisor image and the gateway-CA client-TLS Secret synced into the
# sandbox namespace above.
if [ "${TOPOLOGY}" = "gateway" ]; then
    TOPOLOGY_CONFIG='supervisor_topology = "gateway"'
    DEDICATED_KEYS=''
    SHARED_SUPERVISOR_CONFIG=$(cat <<FRAG

[openshell.drivers.kubernetes.shared_supervisor]
service_name = "${SUPERVISOR_SERVICE}"
service_namespace = "${SUPERVISOR_NAMESPACE}"
runtime_port = ${SUPERVISOR_PORT}
token_secret_name = "${SUPERVISOR_TOKEN_SECRET}"
FRAG
)
else
    TOPOLOGY_CONFIG=''
    DEDICATED_KEYS=$(cat <<FRAG
supervisor_image = "${OPENSHELL_KVPOC_SUPERVISOR_IMAGE:-kvpoc/openshell-supervisor:dev}"
client_tls_secret_name = "${SUPERVISOR_CA_SECRET}"
FRAG
)
    SHARED_SUPERVISOR_CONFIG=''
fi

CONFIG_PATH="${STATE_DIR}/gateway.toml"
cat >"${CONFIG_PATH}" <<EOF
# OpenShell gateway for the KubeVirt compute-driver PoC (e2e/kubevirt/).
[openshell]
version = 2

[openshell.gateway]
# Driver selection moved to the OPENSHELL_DRIVERS environment variable on
# current main (a single `compute_driver` file key also exists).
# TLS is required: the shared supervisor's assignment token travels only
# over TLS, and supervisor_topology = "gateway" refuses to start without it.
# 0.0.0.0: the shared supervisor Pod and the CLI reach the gateway through
# the k3d docker bridge (https://172.18.0.1:PORT) and 127.0.0.1.
bind_address = "0.0.0.0:${PORT}"
health_bind_address = "127.0.0.1:$((PORT + 1))"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.tls]
cert_path = "${PKI_DIR}/server/tls.crt"
key_path = "${PKI_DIR}/server/tls.key"
client_ca_path = "${PKI_DIR}/ca.crt"

[openshell.gateway.gateway_jwt]
signing_key_path = "${TLS_DIR}/jwt/signing.pem"
public_key_path = "${TLS_DIR}/jwt/public.pem"
kid_path = "${TLS_DIR}/jwt/kid"
gateway_id = "kvpoc"
ttl_secs = 3600

[openshell.drivers.kubernetes]
runtime = "kubevirt"
gateway_id = "kvpoc"
namespace = "${SANDBOX_NAMESPACE}"
grpc_endpoint = "${GRPC_ENDPOINT}"
${TOPOLOGY_CONFIG}
${DEDICATED_KEYS}

[openshell.drivers.kubernetes.kubevirt]
guest_image = "${GUEST_IMAGE}"
guest_image_pull_policy = "IfNotPresent"
cpu_cores = 1
memory = "1Gi"
workload = "${OPENSHELL_KVPOC_WORKLOAD:-sandboxed}"
${SHARED_SUPERVISOR_CONFIG}
EOF

# Register the gateway for the CLI (mTLS: the shared supervisor requires
# gateway TLS, so the demo generates a PKI bundle into the state directory
# and lays the client side into the CLI's gateway directory). The demo runs
# the CLI against an isolated XDG_CONFIG_HOME under the demo state
# directory, so the user's own ~/.config/openshell is never touched.
CONFIG_HOME="${STATE_DIR}/cli-config"
export XDG_CONFIG_HOME="${CONFIG_HOME}"
GATEWAY_DIR="${CONFIG_HOME}/openshell/gateways/${GATEWAY_NAME}"
rm -rf "${GATEWAY_DIR}"
mkdir -p "${GATEWAY_DIR}"
mkdir -p "${GATEWAY_DIR}/mtls"
cp "${PKI_DIR}/ca.crt" "${GATEWAY_DIR}/mtls/ca.crt"
cp "${PKI_DIR}/client/tls.crt" "${GATEWAY_DIR}/mtls/tls.crt"
cp "${PKI_DIR}/client/tls.key" "${GATEWAY_DIR}/mtls/tls.key"
chmod 0600 "${GATEWAY_DIR}/mtls/tls.key"
cat >"${GATEWAY_DIR}/metadata.json" <<EOF
{
  "name": "${GATEWAY_NAME}",
  "gateway_endpoint": "https://127.0.0.1:${PORT}",
  "is_remote": false,
  "gateway_port": ${PORT},
  "auth_mode": "mtls"
}
EOF
printf '%s' "${GATEWAY_NAME}" >"${CONFIG_HOME}/openshell/active_gateway"

# Sandboxes render into a dedicated namespace.
kubectl create namespace "${SANDBOX_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

cleanup() {
    if [ "${RUN_DEMO}" = "1" ] && [ -n "${GATEWAY_PID:-}" ]; then
        kill "${GATEWAY_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo
echo "Starting KubeVirt-mode Kubernetes gateway..."
echo "  gateway:    ${GATEWAY_NAME} (http://127.0.0.1:${PORT})"
echo "  guest view: ${GRPC_ENDPOINT}"
echo "  namespace:  ${SANDBOX_NAMESPACE}"
echo "  guest disk: ${GUEST_IMAGE}"
echo

# Stamp the attach-wait window BEFORE the gateway launches: a supervisor
# whose token is still valid can attach within a second of the gateway
# coming up, and a later stamp would miss its log line.
GATEWAY_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# The gateway may run on a restricted kubeconfig (e.g. one minted from the
# chart's gateway ServiceAccount, to prove the Helm RBAC is sufficient):
# set OPENSHELL_KVPOC_GATEWAY_KUBECONFIG. The demo's own kubectl calls keep
# the ambient KUBECONFIG (they are demo scaffolding: namespace and CA
# Secret setup).
KUBECONFIG="${OPENSHELL_KVPOC_GATEWAY_KUBECONFIG:-${KUBECONFIG}}" \
    OPENSHELL_DRIVERS=kubernetes "${GATEWAY_BIN}" \
    --config "${CONFIG_PATH}" \
    --port "${PORT}" \
    --log-level "${LOG_LEVEL}" \
    --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc" &
GATEWAY_PID=$!

# Wait for the gateway to accept requests.
for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:$((PORT + 1))/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if [ "${RUN_DEMO}" = "1" ] || [ "${RUN_PROBES}" = "1" ]; then
    # The gateway topology's supervisor Deployment must attach to the
    # gateway's assignment stream before the first create: the token the
    # gateway mints is only served once the replica is attached, and a
    # create racing that attach leaves the boundary's dial refused.
    if [ "${TOPOLOGY}" = "gateway" ]; then
        echo "==> waiting for the shared supervisor replica to attach"
        # Only lines logged after this gateway's launch count (the stamp
        # was taken before the binary started), so a quick rerun cannot
        # satisfy the check with the previous gateway's attach line.
        ATTACHED=1
        for _ in $(seq 1 60); do
            if kubectl logs -n "${SUPERVISOR_NAMESPACE}" deployment/"${SUPERVISOR_SERVICE}" \
                --since-time="${GATEWAY_STARTED_AT}" 2>/dev/null \
                | grep -q "gateway accepted the supervisor host"; then
                ATTACHED=0
                break
            fi
            sleep 2
        done
        if [ "${ATTACHED}" != "0" ]; then
            echo "the shared supervisor replica did not attach to the gateway" >&2
            kill "${GATEWAY_PID}" 2>/dev/null || true
            exit 1
        fi
    fi
    if [ "${RUN_PROBES}" = "1" ]; then
        "${ROOT}/e2e/kubevirt/run-probes.sh" || {
            kill "${GATEWAY_PID}" 2>/dev/null || true
            exit 1
        }
    else
        "${ROOT}/e2e/kubevirt/run-demo.sh" || {
            kill "${GATEWAY_PID}" 2>/dev/null || true
            exit 1
        }
    fi
    kill "${GATEWAY_PID}" 2>/dev/null || true
    trap - EXIT
    wait "${GATEWAY_PID}" 2>/dev/null || true
else
    wait "${GATEWAY_PID}"
fi
