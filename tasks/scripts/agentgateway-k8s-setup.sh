#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ACTION="${1:-install}"
KUBE_CONTEXT="${OPENSHELL_AGENTGATEWAY_KUBE_CONTEXT:-}"
NAMESPACE="agentgateway-system"
RELEASE_NAME="agentgateway"
AGENTGATEWAY_VERSION="${OPENSHELL_AGENTGATEWAY_VERSION:-v1.5.0}"
GATEWAY_API_VERSION="${OPENSHELL_GATEWAY_API_VERSION:-v1.6.2}"
MANIFEST="${ROOT}/deploy/kube/manifests/agentgateway-openshell.yaml"

kubectl_args=()
helm_args=()
if [ -n "${KUBE_CONTEXT}" ]; then
  kubectl_args+=(--context "${KUBE_CONTEXT}")
  helm_args+=(--kube-context "${KUBE_CONTEXT}")
fi

case "${ACTION}" in
  install)
    kubectl "${kubectl_args[@]}" apply --server-side -f \
      "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"

    helm "${helm_args[@]}" upgrade --install "${RELEASE_NAME}-crds" \
      oci://cr.agentgateway.dev/charts/agentgateway-crds \
      --version "${AGENTGATEWAY_VERSION}" \
      --namespace "${NAMESPACE}" --create-namespace \
      --wait --timeout 5m
    helm "${helm_args[@]}" upgrade --install "${RELEASE_NAME}" \
      oci://cr.agentgateway.dev/charts/agentgateway \
      --version "${AGENTGATEWAY_VERSION}" \
      --namespace "${NAMESPACE}" \
      --wait --timeout 5m

    kubectl "${kubectl_args[@]}" apply -f "${MANIFEST}"
    ;;
  delete)
    kubectl "${kubectl_args[@]}" delete -f "${MANIFEST}" \
      --ignore-not-found --wait=false
    helm "${helm_args[@]}" uninstall "${RELEASE_NAME}" \
      --namespace "${NAMESPACE}" --wait --timeout 60s 2>/dev/null || true
    helm "${helm_args[@]}" uninstall "${RELEASE_NAME}-crds" \
      --namespace "${NAMESPACE}" --wait --timeout 60s 2>/dev/null || true
    kubectl "${kubectl_args[@]}" delete namespace "${NAMESPACE}" \
      --ignore-not-found --wait=true --timeout=60s
    ;;
  *)
    echo "Usage: $0 [install|delete]" >&2
    exit 2
    ;;
esac
