#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# One-time install of kube-prometheus-stack + Jaeger all-in-one into the local
# k3s cluster created by `mise run helm:k3s:create`.
#
# - kube-prometheus-stack provides Prometheus, Grafana, and the
#   ServiceMonitor/PodMonitor CRDs the openshell chart uses.
# - Jaeger all-in-one provides an OTLP/gRPC receiver (:4317) and UI (:16686).
#
# Re-running is safe; both releases use `helm upgrade --install`.
#
# Usage:
#   mise run observability:k8s:setup
#
# After setup, enable monitoring on the openshell release by uncommenting
# `ci/values-monitoring.yaml` in `deploy/helm/openshell/skaffold.yaml`, then
# rerun skaffold.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VALUES_DIR="${REPO_ROOT}/deploy/kube/observability"

MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
OBSERVABILITY_NAMESPACE="${OBSERVABILITY_NAMESPACE:-observability}"
PROMSTACK_RELEASE="${PROMSTACK_RELEASE:-kube-prometheus-stack}"
PROMSTACK_VERSION="${PROMSTACK_VERSION:-75.0.0}"
PROMSTACK_VALUES="${PROMSTACK_VALUES:-${VALUES_DIR}/prometheus-values.yaml}"
JAEGER_RELEASE="${JAEGER_RELEASE:-jaeger}"
JAEGER_VERSION="${JAEGER_VERSION:-3.4.0}"
JAEGER_VALUES="${JAEGER_VALUES:-${VALUES_DIR}/jaeger-values.yaml}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-180}"

# ---------------------------------------------------------------------------
# Helm repos
# ---------------------------------------------------------------------------

echo "Adding Helm repos..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
helm repo add jaegertracing https://jaegertracing.github.io/helm-charts >/dev/null 2>&1 || true
helm repo update prometheus-community jaegertracing >/dev/null

# ---------------------------------------------------------------------------
# kube-prometheus-stack
# ---------------------------------------------------------------------------
#
# Slimmed-down install: keep Prometheus + Grafana + Operator (the parts the
# openshell chart's ServiceMonitor needs), drop Alertmanager and the
# node/kube-state metrics exporters to keep k3d resource usage down. Real
# clusters get the full bundle via the published docs.

echo "Installing ${PROMSTACK_RELEASE} into namespace ${MONITORING_NAMESPACE}..."
helm upgrade --install "${PROMSTACK_RELEASE}" prometheus-community/kube-prometheus-stack \
    --version "${PROMSTACK_VERSION}" \
    --namespace "${MONITORING_NAMESPACE}" \
    --create-namespace \
    --values "${PROMSTACK_VALUES}" \
    --wait --timeout "${HEALTH_TIMEOUT}s"

# ---------------------------------------------------------------------------
# Jaeger all-in-one
# ---------------------------------------------------------------------------

echo "Installing ${JAEGER_RELEASE} into namespace ${OBSERVABILITY_NAMESPACE}..."
helm upgrade --install "${JAEGER_RELEASE}" jaegertracing/jaeger \
    --version "${JAEGER_VERSION}" \
    --namespace "${OBSERVABILITY_NAMESPACE}" \
    --create-namespace \
    --values "${JAEGER_VALUES}" \
    --wait --timeout "${HEALTH_TIMEOUT}s"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "Cluster monitoring stack is ready."
echo ""
echo "  Grafana:      http://localhost:3000  (admin / admin)"
echo "  Prometheus:   http://localhost:9090"
echo "  Jaeger UI:    http://localhost:16686"
echo ""
echo "  Start port-forwards:    mise run observability:port-forward"
echo ""
echo "  Enable on the openshell release:"
echo "    1. Uncomment 'ci/values-monitoring.yaml' in deploy/helm/openshell/skaffold.yaml"
echo "    2. mise run helm:skaffold:dev"
echo ""
echo "  Teardown:               mise run observability:k8s:teardown"
echo ""
