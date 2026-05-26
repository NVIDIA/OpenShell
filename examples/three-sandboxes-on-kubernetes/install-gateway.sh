#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Install the OpenShell gateway into the cluster reachable via the
# kubeconfig context named by $KUBE_CONTEXT. Idempotent: re-running
# upgrades the release in place.
#
# Required env:
#   KUBE_CONTEXT          kubeconfig context to target (e.g. testmember-5)
#
# Optional env:
#   OPENSHELL_NAMESPACE   namespace for the gateway (default: openshell)
#   OPENSHELL_RELEASE     Helm release name (default: openshell)
#   CHART_PATH            path to the OpenShell helm chart
#                         (default: ./deploy/helm/openshell in this checkout).
#                         Set to a chart checked out at the same tag as the
#                         gateway image in values.yaml — e.g.
#                           git worktree add /tmp/openshell-v0.0.47 v0.0.47
#                           export CHART_PATH=/tmp/openshell-v0.0.47/deploy/helm/openshell
#                         Mismatched chart/image versions cause sandbox pods
#                         to fail with "invalid gRPC endpoint".
#
# Usage:
#   export KUBE_CONTEXT=<your-context>
#   bash examples/three-sandboxes-on-kubernetes/install-gateway.sh

set -euo pipefail

: "${KUBE_CONTEXT:?KUBE_CONTEXT must be set (e.g. export KUBE_CONTEXT=testmember-5)}"
NAMESPACE="${OPENSHELL_NAMESPACE:-openshell}"
RELEASE="${OPENSHELL_RELEASE:-openshell}"
CONTEXT="${KUBE_CONTEXT}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHART_DIR="${CHART_PATH:-${REPO_ROOT}/deploy/helm/openshell}"
VALUES_FILE="${SCRIPT_DIR}/values.yaml"

echo "▸ Verifying kube context: ${CONTEXT}"
kubectl --context "${CONTEXT}" cluster-info >/dev/null

echo "▸ Ensuring namespace ${NAMESPACE} exists"
kubectl --context "${CONTEXT}" get namespace "${NAMESPACE}" >/dev/null 2>&1 \
    || kubectl --context "${CONTEXT}" create namespace "${NAMESPACE}"

echo "▸ Installing gateway (release=${RELEASE}, namespace=${NAMESPACE})"
helm --kube-context "${CONTEXT}" upgrade --install "${RELEASE}" "${CHART_DIR}" \
    --namespace "${NAMESPACE}" \
    --values "${VALUES_FILE}"

echo "▸ Waiting for gateway rollout"
kubectl --context "${CONTEXT}" -n "${NAMESPACE}" rollout status "statefulset/${RELEASE}" --timeout=180s

echo
echo "Gateway installed on context '${CONTEXT}' in namespace '${NAMESPACE}'."
echo "Next: forward the gateway service in another terminal:"
echo "  kubectl --context ${CONTEXT} -n ${NAMESPACE} port-forward svc/${RELEASE} 8080:8080"
echo "Then register it with the CLI:"
echo "  openshell gateway add http://127.0.0.1:8080 --local --name ${CONTEXT}"
