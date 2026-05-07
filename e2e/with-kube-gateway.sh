#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run an e2e command against a Helm-deployed OpenShell gateway in Kubernetes.
#
# Modes:
#   - OPENSHELL_E2E_KUBE_CONTEXT set:
#       Target the named kubectl context, install the chart into an ephemeral
#       namespace, and port-forward the gateway. Cluster lifecycle is the
#       caller's responsibility (e.g. CI provisions kind via helm/kind-action).
#   - OPENSHELL_E2E_KUBE_CONTEXT unset:
#       Create a local k3d cluster via tasks/scripts/helm-k3s-local.sh, install
#       the chart, port-forward, and tear the cluster down on exit.
#
# Helm e2e currently uses plaintext gateway traffic (ci/values-tls-disabled.yaml).
#
# Image source: helm install pulls from ${OPENSHELL_REGISTRY}/{gateway,supervisor}:${IMAGE_TAG}
# (defaults: ghcr.io/nvidia/openshell, latest). CI sets IMAGE_TAG to the commit SHA;
# local devs should set it to a tag pulled from a registry the cluster can reach,
# or build and import images via a separate bootstrap step before running this script.

set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: e2e/with-kube-gateway.sh <command> [args...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

WORKDIR_PARENT="${TMPDIR:-/tmp}"
WORKDIR_PARENT="${WORKDIR_PARENT%/}"
WORKDIR="$(mktemp -d "${WORKDIR_PARENT}/openshell-e2e-kube.XXXXXX")"

CLUSTER_CREATED_BY_US=0
CLUSTER_NAME=""
KUBE_CONTEXT=""
NAMESPACE="openshell"
RELEASE_NAME="openshell"
PORTFORWARD_PID=""
PORTFORWARD_LOG="${WORKDIR}/portforward.log"
HELM_INSTALLED=0

# Isolate CLI/SDK gateway metadata from the developer's real config.
export XDG_CONFIG_HOME="${WORKDIR}/config"
export XDG_DATA_HOME="${WORKDIR}/data"

kctl() {
  kubectl --context "${KUBE_CONTEXT}" "$@"
}

helmctl() {
  helm --kube-context "${KUBE_CONTEXT}" "$@"
}

cleanup() {
  local exit_code=$?

  if [ -n "${PORTFORWARD_PID}" ]; then
    kill "${PORTFORWARD_PID}" >/dev/null 2>&1 || true
    wait "${PORTFORWARD_PID}" >/dev/null 2>&1 || true
  fi

  if [ "${exit_code}" -ne 0 ] && [ -n "${KUBE_CONTEXT}" ] && [ -n "${NAMESPACE}" ]; then
    if command -v kubectl >/dev/null 2>&1 \
       && kctl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
      echo "=== gateway pod state (preserved for debugging) ==="
      kctl -n "${NAMESPACE}" get pods -o wide 2>&1 || true
      echo "=== gateway events ==="
      kctl -n "${NAMESPACE}" get events --sort-by=.lastTimestamp 2>&1 \
        | tail -n 80 || true
      echo "=== gateway logs (last 200 lines) ==="
      kctl -n "${NAMESPACE}" logs \
        -l "app.kubernetes.io/instance=${RELEASE_NAME}" --tail=200 \
        --all-containers --prefix 2>&1 || true
      echo "=== end gateway debug output ==="
    fi
    if [ -f "${PORTFORWARD_LOG}" ]; then
      echo "=== port-forward log ==="
      cat "${PORTFORWARD_LOG}" || true
      echo "=== end port-forward log ==="
    fi
  fi

  if [ "${HELM_INSTALLED}" = "1" ] && [ -n "${KUBE_CONTEXT}" ] && [ -n "${NAMESPACE}" ]; then
    if command -v helm >/dev/null 2>&1; then
      helmctl uninstall "${RELEASE_NAME}" --namespace "${NAMESPACE}" --wait \
        --timeout 60s >/dev/null 2>&1 || true
    fi
    if command -v kubectl >/dev/null 2>&1; then
      kctl delete namespace "${NAMESPACE}" --wait=false \
        --ignore-not-found >/dev/null 2>&1 || true
    fi
  fi

  if [ "${CLUSTER_CREATED_BY_US}" = "1" ] && [ -n "${CLUSTER_NAME}" ]; then
    if command -v k3d >/dev/null 2>&1 && k3d cluster list "${CLUSTER_NAME}" \
        >/dev/null 2>&1; then
      echo "Deleting ephemeral k3d cluster ${CLUSTER_NAME}..."
      k3d cluster delete "${CLUSTER_NAME}" >/dev/null 2>&1 || true
    fi
  fi

  rm -rf "${WORKDIR}" 2>/dev/null || true
}
trap cleanup EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: $1 is required to run Helm-backed e2e tests" >&2
    exit 2
  fi
}

require_cmd helm
require_cmd kubectl
require_cmd curl

if [ -n "${OPENSHELL_E2E_KUBE_CONTEXT:-}" ]; then
  KUBE_CONTEXT="${OPENSHELL_E2E_KUBE_CONTEXT}"
  echo "Using existing kubectl context: ${KUBE_CONTEXT}"
  if ! kctl cluster-info >/dev/null 2>&1; then
    echo "ERROR: kubectl context '${KUBE_CONTEXT}' is not reachable." >&2
    exit 2
  fi
else
  require_cmd k3d
  CLUSTER_NAME="oshe2e-$$-$(date +%s | tail -c 8)"
  echo "Creating ephemeral k3d cluster ${CLUSTER_NAME}..."
  HELM_K3S_CLUSTER_NAME="${CLUSTER_NAME}" \
  HELM_K3S_KUBECONFIG="${WORKDIR}/kubeconfig" \
    bash "${ROOT}/tasks/scripts/helm-k3s-local.sh" create
  CLUSTER_CREATED_BY_US=1
  export KUBECONFIG="${WORKDIR}/kubeconfig"
  KUBE_CONTEXT="k3d-${CLUSTER_NAME}"
fi

IMAGE_TAG_VALUE="${IMAGE_TAG:-latest}"
REGISTRY_VALUE="${OPENSHELL_REGISTRY:-ghcr.io/nvidia/openshell}"
REGISTRY_VALUE="${REGISTRY_VALUE%/}"

# When this script created the cluster, import locally-available gateway and
# supervisor images so devs without a registry login can iterate. Best-effort:
# missing images fall through to the cluster's pull behavior at install time.
if [ "${CLUSTER_CREATED_BY_US}" = "1" ]; then
  for image in \
    "${REGISTRY_VALUE}/gateway:${IMAGE_TAG_VALUE}" \
    "${REGISTRY_VALUE}/supervisor:${IMAGE_TAG_VALUE}"; do
    if docker image inspect "${image}" >/dev/null 2>&1; then
      echo "Importing ${image} into k3d cluster ${CLUSTER_NAME}..."
      k3d image import "${image}" --cluster "${CLUSTER_NAME}" \
        --mode direct >/dev/null
    fi
  done
fi

# The Kubernetes compute driver creates and watches Sandbox CRs reconciled
# by the upstream agent-sandbox-controller. Without the CRD + controller,
# every gateway K8s call 404s and CreateSandbox never produces a Pod.
echo "Installing agent-sandbox CRDs and controller..."
kctl apply -f "${ROOT}/deploy/kube/manifests/agent-sandbox.yaml"
kctl wait --for=condition=Established crd/sandboxes.agents.x-k8s.io --timeout=120s
kctl -n agent-sandbox-system rollout status statefulset/agent-sandbox-controller --timeout=300s

echo "Installing Helm chart (release=${RELEASE_NAME}, namespace=${NAMESPACE}, tag=${IMAGE_TAG_VALUE})..."
helmctl install "${RELEASE_NAME}" "${ROOT}/deploy/helm/openshell" \
  --namespace "${NAMESPACE}" --create-namespace \
  --values "${ROOT}/deploy/helm/openshell/ci/values-tls-disabled.yaml" \
  --set "fullnameOverride=openshell" \
  --set "image.repository=${REGISTRY_VALUE}/gateway" \
  --set "image.tag=${IMAGE_TAG_VALUE}" \
  --set "supervisor.image.repository=${REGISTRY_VALUE}/supervisor" \
  --set "supervisor.image.tag=${IMAGE_TAG_VALUE}" \
  --wait --timeout 5m
HELM_INSTALLED=1

LOCAL_PORT="$(e2e_pick_port)"
echo "Starting kubectl port-forward svc/openshell ${LOCAL_PORT}:8080..."
kctl -n "${NAMESPACE}" port-forward "svc/openshell" \
  "${LOCAL_PORT}:8080" >"${PORTFORWARD_LOG}" 2>&1 &
PORTFORWARD_PID=$!

elapsed=0
timeout=30
while [ "${elapsed}" -lt "${timeout}" ]; do
  if ! kill -0 "${PORTFORWARD_PID}" 2>/dev/null; then
    echo "ERROR: kubectl port-forward exited before becoming reachable" >&2
    cat "${PORTFORWARD_LOG}" >&2 || true
    exit 1
  fi
  if curl -s -o /dev/null --connect-timeout 1 "http://127.0.0.1:${LOCAL_PORT}"; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [ "${elapsed}" -ge "${timeout}" ]; then
  echo "ERROR: port-forward did not accept TCP within ${timeout}s" >&2
  cat "${PORTFORWARD_LOG}" >&2 || true
  exit 1
fi

GATEWAY_NAME="openshell-e2e-kube-${LOCAL_PORT}"
GATEWAY_ENDPOINT="http://127.0.0.1:${LOCAL_PORT}"
e2e_register_plaintext_gateway \
  "${XDG_CONFIG_HOME}" \
  "${GATEWAY_NAME}" \
  "${GATEWAY_ENDPOINT}" \
  "${LOCAL_PORT}"

export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
export OPENSHELL_E2E_DRIVER="kubernetes"
export OPENSHELL_E2E_SANDBOX_NAMESPACE="${NAMESPACE}"
export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-300}"

echo "Running e2e command against ${GATEWAY_ENDPOINT}: $*"
"$@"
