#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Remove the local cluster monitoring add-ons installed by
# observability-k8s-setup.sh.
#
# Usage:
#   mise run observability:k8s:teardown

set -euo pipefail

MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
OBSERVABILITY_NAMESPACE="${OBSERVABILITY_NAMESPACE:-observability}"
PROMSTACK_RELEASE="${PROMSTACK_RELEASE:-kube-prometheus-stack}"
JAEGER_RELEASE="${JAEGER_RELEASE:-jaeger}"

echo "Uninstalling ${PROMSTACK_RELEASE} from ${MONITORING_NAMESPACE}..."
helm uninstall "${PROMSTACK_RELEASE}" --namespace "${MONITORING_NAMESPACE}" --ignore-not-found

echo "Uninstalling ${JAEGER_RELEASE} from ${OBSERVABILITY_NAMESPACE}..."
helm uninstall "${JAEGER_RELEASE}" --namespace "${OBSERVABILITY_NAMESPACE}" --ignore-not-found

echo "Deleting namespaces..."
kubectl delete namespace "${MONITORING_NAMESPACE}" "${OBSERVABILITY_NAMESPACE}" --ignore-not-found

echo "Done."
