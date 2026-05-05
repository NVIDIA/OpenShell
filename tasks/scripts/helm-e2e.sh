#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run Rust and/or Python e2e tests against a gateway deployed via the Helm chart
# on a local k3d cluster (k3s backed by Docker).
#
# The script follows the same preflight → bootstrap → register → test → cleanup
# pattern as e2e/rust/e2e-docker.sh, but uses k3d + Skaffold + Helm instead of
# a standalone gateway process.
#
# Usage:
#   mise run e2e:helm                  # full suite, pkiInitJob PKI
#   mise run e2e:helm:rust             # Rust only
#   mise run e2e:helm:python           # Python only
#   mise run e2e:helm:cert-manager     # full suite, cert-manager PKI
#
# Environment variables:
#   HELM_E2E_SUITE          rust | python | all (default: all)
#   HELM_E2E_PKI            pki-init | cert-manager (default: pki-init)
#   HELM_E2E_KEEP_CLUSTER   1 to skip cluster deletion on exit (default: 0)
#   HELM_E2E_CLUSTER_NAME   override k3d cluster name (default: derived from branch)
#   KUBECONFIG              path to kubeconfig (default: <repo-root>/kubeconfig)
#   OPENSHELL_PROVISION_TIMEOUT  sandbox ready timeout in seconds (default: 300)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="${HELM_E2E_SUITE:-all}"
PKI_MODE="${HELM_E2E_PKI:-pki-init}"
KEEP_CLUSTER="${HELM_E2E_KEEP_CLUSTER:-0}"

# Derive cluster name the same way helm-k3s-local.sh does (last path component of branch).
_branch_cluster_name() {
  local branch
  branch="$(git -C "${ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
  local suffix="${branch##*/}"
  suffix="${suffix:0:24}"
  echo "openshell-dev-${suffix}"
}

CLUSTER_NAME="${HELM_E2E_CLUSTER_NAME:-$(_branch_cluster_name)}"
export KUBECONFIG="${KUBECONFIG:-${ROOT}/kubeconfig}"

WORKDIR="$(mktemp -d "/tmp/openshell-helm-e2e.XXXXXX")"
GATEWAY_NAME="openshell-helm-e2e-${CLUSTER_NAME}"
GATEWAY_CONFIG_DIR="${HOME}/.config/openshell/gateways/${GATEWAY_NAME}"
PF_PID=""
PORT=""
CLUSTER_CREATED=0

cleanup() {
  local exit_code=$?

  if [ -n "${PF_PID}" ] && kill -0 "${PF_PID}" 2>/dev/null; then
    echo "Stopping kubectl port-forward (pid ${PF_PID})..."
    kill "${PF_PID}" 2>/dev/null || true
    wait "${PF_PID}" 2>/dev/null || true
  fi

  if [ -d "${GATEWAY_CONFIG_DIR}" ]; then
    rm -rf "${GATEWAY_CONFIG_DIR}"
  fi

  if [ "${KEEP_CLUSTER}" = "1" ]; then
    echo "Keeping cluster '${CLUSTER_NAME}' (HELM_E2E_KEEP_CLUSTER=1)."
  elif [ "${CLUSTER_CREATED}" = "1" ]; then
    echo "Deleting cluster '${CLUSTER_NAME}'..."
    HELM_K3S_CLUSTER_NAME="${CLUSTER_NAME}" \
      bash "${ROOT}/tasks/scripts/helm-k3s-local.sh" delete 2>/dev/null || true
  fi

  rm -rf "${WORKDIR}" 2>/dev/null || true

  if [ "${exit_code}" -ne 0 ]; then
    echo "helm-e2e failed (exit ${exit_code})."
  fi
}
trap cleanup EXIT

# ── Preflight ────────────────────────────────────────────────────────────────
require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: '$1' is required but not found in PATH" >&2
    exit 2
  fi
}

require_cmd k3d
require_cmd helm
require_cmd kubectl
require_cmd docker
require_cmd openssl

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon is not reachable" >&2
  exit 2
fi

echo "=== helm-e2e: suite=${SUITE} pki=${PKI_MODE} cluster=${CLUSTER_NAME} ==="

# ── Cluster ──────────────────────────────────────────────────────────────────
if k3d cluster get "${CLUSTER_NAME}" >/dev/null 2>&1; then
  echo "Reusing existing k3d cluster '${CLUSTER_NAME}'."
  # Refresh kubeconfig in case it's stale.
  k3d kubeconfig write "${CLUSTER_NAME}" --output "${KUBECONFIG}" >/dev/null
else
  echo "Creating k3d cluster '${CLUSTER_NAME}'..."
  HELM_K3S_CLUSTER_NAME="${CLUSTER_NAME}" \
    bash "${ROOT}/tasks/scripts/helm-k3s-local.sh" create
  CLUSTER_CREATED=1
fi

# ── cert-manager (optional) ──────────────────────────────────────────────────
if [ "${PKI_MODE}" = "cert-manager" ]; then
  echo "Installing cert-manager..."
  helm repo add jetstack https://charts.jetstack.io --force-update >/dev/null 2>&1 || true
  helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace cert-manager --create-namespace \
    --set crds.enabled=true \
    --wait 2>&1
fi

# ── Build images ─────────────────────────────────────────────────────────────
# Use a fixed local tag so the image names are stable across runs and Helm
# can reference them without Skaffold's digest-based tags.
GATEWAY_IMAGE="openshell/gateway:helm-e2e"
SUPERVISOR_IMAGE="openshell/supervisor:helm-e2e"

echo "Building gateway image..."
docker buildx build \
  --build-arg BUILD_FROM_SOURCE=1 \
  --target gateway \
  --tag "${GATEWAY_IMAGE}" \
  --load \
  --file "${ROOT}/deploy/docker/Dockerfile.images" \
  "${ROOT}" 2>&1

echo "Building supervisor image..."
docker buildx build \
  --build-arg BUILD_FROM_SOURCE=1 \
  --target supervisor \
  --tag "${SUPERVISOR_IMAGE}" \
  --load \
  --file "${ROOT}/deploy/docker/Dockerfile.images" \
  "${ROOT}" 2>&1

# Load images into the k3d cluster nodes.
echo "Loading images into k3d cluster..."
k3d image import "${GATEWAY_IMAGE}" "${SUPERVISOR_IMAGE}" -c "${CLUSTER_NAME}" 2>&1

# ── Deploy via Helm ───────────────────────────────────────────────────────────
HELM_VALUES_FLAGS=(
  -f "${ROOT}/deploy/helm/openshell/values.yaml"
)
if [ "${PKI_MODE}" = "cert-manager" ]; then
  HELM_VALUES_FLAGS+=(-f "${ROOT}/deploy/helm/openshell/ci/values-cert-manager.yaml")
fi

echo "Deploying OpenShell via Helm (PKI: ${PKI_MODE})..."
helm upgrade --install openshell "${ROOT}/deploy/helm/openshell" \
  --namespace openshell --create-namespace \
  "${HELM_VALUES_FLAGS[@]}" \
  --set "image.repository=openshell/gateway" \
  --set "image.tag=helm-e2e" \
  --set "image.pullPolicy=Never" \
  --set "supervisor.image.repository=openshell/supervisor" \
  --set "supervisor.image.tag=helm-e2e" \
  --set "supervisor.image.pullPolicy=Never" \
  --wait --timeout 180s 2>&1

# ── Wait for PKI ─────────────────────────────────────────────────────────────
if [ "${PKI_MODE}" = "cert-manager" ]; then
  echo "Waiting for cert-manager certificates to be ready..."
  kubectl wait --for=condition=Ready certificate/openshell-server certificate/openshell-client \
    -n openshell --timeout=120s
else
  echo "Waiting for pkiInitJob secrets..."
  elapsed=0
  while [ "${elapsed}" -lt 60 ]; do
    if kubectl get secret openshell-client-tls -n openshell >/dev/null 2>&1; then
      echo "PKI secrets ready after ${elapsed}s."
      break
    fi
    sleep 3
    elapsed=$((elapsed + 3))
  done
  if [ "${elapsed}" -ge 60 ]; then
    echo "ERROR: pkiInitJob secrets not created within 60s" >&2
    exit 1
  fi
fi

# ── Port-forward ─────────────────────────────────────────────────────────────
pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}
PORT=$(pick_port)

echo "Port-forwarding openshell service → localhost:${PORT}..."
kubectl port-forward -n openshell svc/openshell "${PORT}:8080" \
  >"${WORKDIR}/pf.log" 2>&1 &
PF_PID=$!

# ── Register gateway with CLI ─────────────────────────────────────────────────
mkdir -p "${GATEWAY_CONFIG_DIR}/mtls"

kubectl get secret openshell-client-tls -n openshell \
  -o jsonpath='{.data.ca\.crt}'  | base64 -d > "${GATEWAY_CONFIG_DIR}/mtls/ca.crt"
kubectl get secret openshell-client-tls -n openshell \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > "${GATEWAY_CONFIG_DIR}/mtls/tls.crt"
kubectl get secret openshell-client-tls -n openshell \
  -o jsonpath='{.data.tls\.key}' | base64 -d > "${GATEWAY_CONFIG_DIR}/mtls/tls.key"

cat >"${GATEWAY_CONFIG_DIR}/metadata.json" <<EOF
{
  "name": "${GATEWAY_NAME}",
  "gateway_endpoint": "https://127.0.0.1:${PORT}",
  "is_remote": false,
  "gateway_port": ${PORT}
}
EOF

export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-300}"

# ── Wait for gateway health ───────────────────────────────────────────────────
CLI_BIN="${ROOT}/target/debug/openshell"
if [ ! -f "${CLI_BIN}" ]; then
  echo "Building openshell CLI..."
  cargo build -p openshell-cli --features openshell-core/dev-settings 2>&1
fi

echo "Waiting for gateway to become healthy (port ${PORT})..."
elapsed=0
timeout=120
while [ "${elapsed}" -lt "${timeout}" ]; do
  if ! kill -0 "${PF_PID}" 2>/dev/null; then
    echo "ERROR: port-forward exited unexpectedly" >&2
    cat "${WORKDIR}/pf.log" || true
    exit 1
  fi
  if "${CLI_BIN}" status --gateway "${GATEWAY_NAME}" >/dev/null 2>&1; then
    echo "Gateway healthy after ${elapsed}s."
    break
  fi
  sleep 3
  elapsed=$((elapsed + 3))
done
if [ "${elapsed}" -ge "${timeout}" ]; then
  echo "ERROR: gateway did not become healthy within ${timeout}s" >&2
  cat "${WORKDIR}/pf.log" || true
  exit 1
fi

# ── Run test suites ───────────────────────────────────────────────────────────
run_rust() {
  echo "--- Running Rust e2e ---"
  cargo build -p openshell-cli --features openshell-core/dev-settings
  cargo test --manifest-path e2e/rust/Cargo.toml --features e2e -- \
    --skip gateway_resume_scenarios \
    --skip docker_gpu_sandbox_runs_nvidia_smi \
    --skip sandbox_from_custom_dockerfile \
    --skip graphql_l7_enforces_allow_and_deny_rules_on_forward_and_connect_paths \
    --skip forward_proxy_allows_l7_permitted_request \
    --skip sandbox_reaches_host_openshell_internal_via_host_gateway_alias \
    --skip sandbox_inference_local_routes_to_host_openshell_internal \
    --nocapture
}

run_python() {
  echo "--- Running Python e2e ---"
  mise run --no-deps python:proto
  UV_NO_SYNC=1 PYTHONPATH=python uv run pytest \
    -o python_files='test_*.py' \
    -m 'not gpu' \
    -n "${E2E_PARALLEL:-5}" \
    e2e/python
}

case "${SUITE}" in
  rust)   run_rust ;;
  python) run_python ;;
  all)    run_rust; run_python ;;
  *)
    echo "ERROR: unknown HELM_E2E_SUITE '${SUITE}' (must be rust, python, or all)" >&2
    exit 2
    ;;
esac

echo "=== helm-e2e: all suites passed ==="
