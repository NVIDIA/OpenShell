#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Create three OpenShell sandboxes on the gateway installed on the
# cluster named by $KUBE_CONTEXT.
#
# Assumes:
#   - install-gateway.sh has already been run.
#   - The gateway is reachable to the CLI (e.g. via `kubectl port-forward`
#     or an ingress), and registered with `openshell gateway add`.
#
# Required env:
#   KUBE_CONTEXT          kubeconfig context where the gateway is installed
#
# Optional env:
#   OPENSHELL_NAMESPACE   namespace where sandbox pods live (default: openshell)
#
# Usage:
#   export KUBE_CONTEXT=<your-context>
#   bash examples/three-sandboxes-on-kubernetes/create-sandboxes.sh

set -euo pipefail

: "${KUBE_CONTEXT:?KUBE_CONTEXT must be set (e.g. export KUBE_CONTEXT=testmember-5)}"

SANDBOXES=("alpha" "beta" "gamma")

if ! command -v openshell >/dev/null 2>&1; then
    echo "openshell CLI not found in PATH" >&2
    exit 1
fi

echo "▸ Verifying active gateway"
openshell status

for name in "${SANDBOXES[@]}"; do
    echo
    echo "▸ Creating sandbox: ${name}"
    openshell sandbox create \
        --name "${name}" \
        --keep \
        --no-auto-providers \
        --no-tty \
        -- echo "${name} ready"
done

echo
echo "▸ Sandboxes registered with the gateway:"
openshell sandbox list

NAMESPACE="${OPENSHELL_NAMESPACE:-openshell}"

echo
echo "▸ Sandbox pods on context '${KUBE_CONTEXT}' in namespace '${NAMESPACE}':"
kubectl --context "${KUBE_CONTEXT}" -n "${NAMESPACE}" get pods \
    -l 'agents.x-k8s.io/sandbox-name-hash' || true

echo
echo "Connect into any of them with:"
for name in "${SANDBOXES[@]}"; do
    echo "  openshell sandbox connect ${name}"
done
