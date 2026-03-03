#!/bin/sh

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

kubectl get --raw='/readyz' >/dev/null 2>&1 || exit 1

kubectl -n navigator get statefulset/navigator >/dev/null 2>&1 || exit 1
kubectl -n navigator wait --for=jsonpath='{.status.readyReplicas}'=1 statefulset/navigator --timeout=1s >/dev/null 2>&1 || exit 1

# Verify TLS secrets exist (created by navigator-bootstrap before the StatefulSet starts)
kubectl -n navigator get secret navigator-server-tls >/dev/null 2>&1 || exit 1
kubectl -n navigator get secret navigator-client-tls >/dev/null 2>&1 || exit 1
