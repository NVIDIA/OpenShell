#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Idempotent bootstrap for the out-of-cluster controller iteration loop.
#
# Stages (each is a no-op if already done):
#   1. kind cluster
#   2. OpenShellSandbox CRD applied
#
# After this, run the reconciler against the cluster from outside:
#   make standalone
#
# Or apply a test CR:
#   make sample

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"
CLUSTER_NAME="openshell-controller-test"

# Honour podman if docker is aliased — kind respects this env.
export KIND_EXPERIMENTAL_PROVIDER="${KIND_EXPERIMENTAL_PROVIDER:-podman}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# 1. Cluster
if kind get clusters | grep -qx "$CLUSTER_NAME"; then
  log "kind cluster '$CLUSTER_NAME' already exists"
else
  log "creating kind cluster '$CLUSTER_NAME'"
  kind create cluster --config "$HERE/kind-cluster.yaml"
fi

# 2. Export the cluster kubeconfig into the repo-local file that mise's
# `[env].KUBECONFIG` points at. This is the path the standalone reconciler
# reads when it runs under `mise exec`. Without this, mise clobbers any
# shell-level KUBECONFIG override at exec time and the client can't find
# the kind context.
log "writing kubeconfig to $REPO_ROOT/kubeconfig"
kind get kubeconfig --name "$CLUSTER_NAME" > "$REPO_ROOT/kubeconfig"

KUBECONFIG="$REPO_ROOT/kubeconfig" kubectl config use-context "kind-$CLUSTER_NAME"

# 3. CRD
log "applying OpenShellSandbox CRD"
KUBECONFIG="$REPO_ROOT/kubeconfig" kubectl apply -f "$REPO_ROOT/deploy/helm/openshell/crds/openshellsandbox.yaml"

log "harness up. context: kind-$CLUSTER_NAME"
log "next: 'make standalone' (runs the reconciler) and 'make sample' (applies a CR)"
