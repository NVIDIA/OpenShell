#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

helm template openshell "${repo_root}/deploy/helm/openshell" \
  --namespace openshell \
  --set agentSandbox.preflight.enabled=false \
  --set workspaceResources.enabled=false \
  >"${work_dir}/gateway.yaml"

helm template openshell-workspace "${repo_root}/deploy/helm/openshell-workspace" \
  --namespace app-a \
  --set gateway.serviceAccount.name=openshell \
  --set gateway.serviceAccount.namespace=openshell \
  >"${work_dir}/workspace.yaml"

yq ea -N -r \
  'select(.kind != null) | [.apiVersion, .kind, (.metadata.namespace // "openshell"), .metadata.name] | @tsv' \
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
