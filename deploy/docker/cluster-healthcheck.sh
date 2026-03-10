#!/bin/sh

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

kubectl get --raw='/readyz' >/dev/null 2>&1 || exit 1

kubectl -n openshell get statefulset/openshell >/dev/null 2>&1 || exit 1
kubectl -n openshell wait --for=jsonpath='{.status.readyReplicas}'=1 statefulset/openshell --timeout=1s >/dev/null 2>&1 || exit 1

# Verify TLS secrets exist (created by openshell-bootstrap before the StatefulSet starts)
# Skip when TLS is disabled — secrets are not required.
if [ "${DISABLE_TLS:-}" != "true" ]; then
    kubectl -n openshell get secret openshell-server-tls >/dev/null 2>&1 || exit 1
    kubectl -n openshell get secret openshell-client-tls >/dev/null 2>&1 || exit 1
fi
