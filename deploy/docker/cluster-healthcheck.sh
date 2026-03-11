#!/bin/sh

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# ---------------------------------------------------------------------------
# Pre-flight: verify container DNS resolution is functional.
# If the DNS proxy is broken, nothing will work (image pulls fail, pods
# can't start, etc.). Fail fast with a clear signal instead of letting the
# health check return unhealthy for 5+ minutes with no useful output.
# ---------------------------------------------------------------------------

# Check whether a string looks like an IP address (v4 or v6) with optional port.
is_ip_literal() {
    local host="${1%:*}"
    echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && return 0
    echo "$host" | grep -qE '^\[?[0-9a-fA-F:]+\]?$' && return 0
    return 1
}

DNS_TARGET="${REGISTRY_HOST:-ghcr.io}"
# IP-literal registry hosts (e.g. 127.0.0.1:5000) don't need DNS resolution.
if ! is_ip_literal "$DNS_TARGET"; then
    DNS_LOOKUP="${DNS_TARGET%%:*}"
    if ! nslookup "$DNS_LOOKUP" >/dev/null 2>&1; then
        echo "HEALTHCHECK_DNS_FAILURE: cannot resolve $DNS_TARGET" >&2
        exit 1
    fi
fi

kubectl get --raw='/readyz' >/dev/null 2>&1 || exit 1

# ---------------------------------------------------------------------------
# Check for node pressure conditions (DiskPressure, MemoryPressure, PIDPressure).
# When a node is under pressure the kubelet evicts pods and rejects new ones,
# so the cluster will never become healthy. Emit a marker to stderr so the
# bootstrap polling loop can detect it early and surface a clear diagnosis.
# ---------------------------------------------------------------------------
NODE_CONDITIONS=$(kubectl get nodes -o jsonpath='{range .items[*]}{range .status.conditions[*]}{.type}={.status}{"\n"}{end}{end}' 2>/dev/null || true)
for PRESSURE in DiskPressure MemoryPressure PIDPressure; do
    if echo "$NODE_CONDITIONS" | grep -q "^${PRESSURE}=True$"; then
        echo "HEALTHCHECK_NODE_PRESSURE: ${PRESSURE}" >&2
    fi
done

kubectl -n openshell get statefulset/openshell >/dev/null 2>&1 || exit 1
kubectl -n openshell wait --for=jsonpath='{.status.readyReplicas}'=1 statefulset/openshell --timeout=1s >/dev/null 2>&1 || exit 1

# Verify TLS secrets exist (created by openshell-bootstrap before the StatefulSet starts)
# Skip when TLS is disabled — secrets are not required.
if [ "${DISABLE_TLS:-}" != "true" ]; then
    kubectl -n openshell get secret openshell-server-tls >/dev/null 2>&1 || exit 1
    kubectl -n openshell get secret openshell-client-tls >/dev/null 2>&1 || exit 1
fi
