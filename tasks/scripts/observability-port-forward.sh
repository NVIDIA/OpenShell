#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Background port-forwards for Grafana, Prometheus, and the Jaeger UI.
# Runs until interrupted; trap ensures the kubectl background processes are
# cleaned up on Ctrl+C / SIGTERM.
#
# Usage:
#   mise run observability:port-forward

set -euo pipefail

MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
OBSERVABILITY_NAMESPACE="${OBSERVABILITY_NAMESPACE:-observability}"
PROMSTACK_RELEASE="${PROMSTACK_RELEASE:-kube-prometheus-stack}"
JAEGER_RELEASE="${JAEGER_RELEASE:-jaeger}"

GRAFANA_LOCAL_PORT="${GRAFANA_LOCAL_PORT:-3000}"
PROMETHEUS_LOCAL_PORT="${PROMETHEUS_LOCAL_PORT:-9090}"
JAEGER_UI_LOCAL_PORT="${JAEGER_UI_LOCAL_PORT:-16686}"

PIDS=()

cleanup() {
    if [[ ${#PIDS[@]} -gt 0 ]]; then
        echo ""
        echo "Stopping port-forwards..."
        kill "${PIDS[@]}" 2>/dev/null || true
        wait "${PIDS[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

forward() {
    local namespace="$1"
    local target="$2"
    local local_port="$3"
    local remote_port="$4"
    kubectl --namespace "${namespace}" port-forward "${target}" \
        "${local_port}:${remote_port}" >/dev/null 2>&1 &
    PIDS+=("$!")
}

echo "Starting port-forwards..."
forward "${MONITORING_NAMESPACE}" "svc/${PROMSTACK_RELEASE}-grafana" "${GRAFANA_LOCAL_PORT}" 80
forward "${MONITORING_NAMESPACE}" "svc/${PROMSTACK_RELEASE}-prometheus" "${PROMETHEUS_LOCAL_PORT}" 9090
forward "${OBSERVABILITY_NAMESPACE}" "svc/${JAEGER_RELEASE}-query" "${JAEGER_UI_LOCAL_PORT}" 16686

echo ""
echo "  Grafana:     http://localhost:${GRAFANA_LOCAL_PORT}    (admin / admin)"
echo "  Prometheus:  http://localhost:${PROMETHEUS_LOCAL_PORT}"
echo "  Jaeger UI:   http://localhost:${JAEGER_UI_LOCAL_PORT}"
echo ""
echo "Press Ctrl+C to stop."

# Block until any forwarder exits or signal is received.
wait -n
