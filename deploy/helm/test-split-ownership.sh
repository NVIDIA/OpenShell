#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

helm template ryno "${repo_root}/deploy/helm/ryno" \
  --namespace ryno \
  --set agentSandbox.preflight.enabled=false \
  --set workspaceResources.enabled=false \
  >"${work_dir}/gateway.yaml"

if yq ea -e \
  'select(.kind == "Role" and .metadata.name == "ryno-sandbox")' \
  "${work_dir}/gateway.yaml" >/dev/null 2>&1; then
  echo "gateway chart rendered workspace resources despite workspaceResources.enabled=false" >&2
  exit 1
fi

helm template ryno "${repo_root}/deploy/helm/ryno" \
  --namespace ryno \
  --set agentSandbox.preflight.enabled=false \
  --set supervisor.sandboxRuntime.networkPolicyEnforced=true \
  --set rbac.clusterScoped.create=false \
  >"${work_dir}/namespace-admin.yaml"

cluster_scoped_kinds="$(
  yq ea -N -r \
    'select(.kind == "ClusterRole" or .kind == "ClusterRoleBinding") |
     [.kind, .metadata.name] | join(" ")' \
    "${work_dir}/namespace-admin.yaml"
)"
if [[ -n "${cluster_scoped_kinds}" ]]; then
  echo "gateway chart rendered cluster-scoped objects despite rbac.clusterScoped.create=false:" >&2
  echo "${cluster_scoped_kinds}" >&2
  exit 1
fi

if ! yq ea -e \
  'select(.kind == "ServiceAccount" and .metadata.name == "ryno")' \
  "${work_dir}/namespace-admin.yaml" >/dev/null 2>&1; then
  echo "gateway chart dropped the gateway ServiceAccount with rbac.clusterScoped.create=false" >&2
  exit 1
fi

helm template ryno-workspace "${repo_root}/deploy/helm/ryno-workspace" \
  --namespace app-a \
  --set gateway.serviceAccount.name=ryno \
  --set gateway.serviceAccount.namespace=ryno \
  >"${work_dir}/workspace.yaml"

invalid_workspace_docs="$(
  yq ea -N -r \
    'select(. != null and (.apiVersion == null or .kind == null)) | document_index' \
    "${work_dir}/workspace.yaml"
)"
if [[ -n "${invalid_workspace_docs}" ]]; then
  echo "workspace chart rendered documents without apiVersion or kind: ${invalid_workspace_docs}" >&2
  exit 1
fi

helm template ryno "${repo_root}/deploy/helm/ryno" \
  --namespace ryno \
  --set agentSandbox.preflight.enabled=false \
  --set-json workspaceResources=null \
  >"${work_dir}/legacy-reuse-values.yaml"

yq ea -e \
  'select(.kind == "Role" and .metadata.name == "ryno-sandbox") |
   .apiVersion == "rbac.authorization.k8s.io/v1"' \
  "${work_dir}/legacy-reuse-values.yaml" >/dev/null

yq ea -N -r \
  'select(.kind != null) | [.apiVersion, .kind, (.metadata.namespace // "ryno"), .metadata.name] | @tsv' \
  "${work_dir}/gateway.yaml" | sort -u >"${work_dir}/gateway.objects"
yq ea -N -r \
  'select(.kind != null) | [.apiVersion, .kind, (.metadata.namespace // "app-a"), .metadata.name] | @tsv' \
  "${work_dir}/workspace.yaml" | sort -u >"${work_dir}/workspace.objects"

comm -12 "${work_dir}/gateway.objects" "${work_dir}/workspace.objects" \
  >"${work_dir}/overlap.objects"
if [[ -s "${work_dir}/overlap.objects" ]]; then
  echo "gateway and workspace charts claim the same Kubernetes objects:" >&2
  cat "${work_dir}/overlap.objects" >&2
  exit 1
fi

echo "gateway and workspace chart object ownership is disjoint"
