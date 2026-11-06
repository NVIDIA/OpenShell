#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Helm post-renderer for the external Kubernetes compute-driver smoke test.
# It keeps the test-only external-driver container and Unix socket plumbing out
# of the chart.

set -euo pipefail

plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/openshell-external-compute-driver.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

cp "${plugin_dir}/kustomization.yaml" "${work_dir}/kustomization.yaml"
cp "${plugin_dir}/workload-patch.yaml" "${work_dir}/workload-patch.yaml"
tee "${work_dir}/rendered.yaml" >/dev/null

# server.hostGatewayIP renders the gateway pod's hostAliases entry.
if grep -q 'host\.openshell\.internal' "${work_dir}/rendered.yaml" \
  && grep -q '^ *hostAliases:' "${work_dir}/rendered.yaml"; then
  cp -R "${plugin_dir}/host-gateway" "${work_dir}/host-gateway"
  printf 'components:\n  - host-gateway\n' >>"${work_dir}/kustomization.yaml"
fi

kubectl kustomize "${work_dir}"
