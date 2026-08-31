#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Install the upstream Agent Sandbox CRDs and controller. Pass any kubectl
# context arguments (for example, --context kind-e2e) as script arguments.
set -euo pipefail

agent_sandbox_version="${AGENT_SANDBOX_VERSION:-v0.5.4}"

agent_sandbox_manifest_asset() {
  local version="${1#v}"
  local major minor patch
  IFS=. read -r major minor patch <<<"${version}"
  patch="${patch%%[-+]*}"

  if [[ ! "${major}" =~ ^[0-9]+$ || ! "${minor}" =~ ^[0-9]+$ || ! "${patch}" =~ ^[0-9]+$ ]]; then
    echo "error: invalid Agent Sandbox release version: $1" >&2
    return 1
  fi

  if (( 10#${major} > 0 || 10#${minor} > 5 || (10#${minor} == 5 && 10#${patch} >= 2) )); then
    echo "sandbox.yaml"
  else
    echo "manifest.yaml"
  fi
}

wait_for_agent_sandbox_crd() {
  local deadline
  local established

  deadline=$(( $(date +%s) + 120 ))
  while [ "$(date +%s)" -lt "${deadline}" ]; do
    if kubectl "$@" get crd/sandboxes.agents.x-k8s.io >/dev/null 2>&1; then
      established="$(kubectl "$@" get crd/sandboxes.agents.x-k8s.io \
        -o 'jsonpath={.status.conditions[?(@.type=="Established")].status}' \
        2>/dev/null || true)"
      if [ "${established}" = "True" ]; then
        return 0
      fi
    fi
    sleep 2
  done

  echo "Timed out waiting for agent-sandbox Sandbox CRD to become Established" >&2
  kubectl "$@" get crd/sandboxes.agents.x-k8s.io -o yaml >&2 || true
  return 1
}

echo "Installing agent-sandbox CRDs and controller (${agent_sandbox_version})..."
agent_sandbox_base="https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${agent_sandbox_version}"
agent_sandbox_manifest="$(agent_sandbox_manifest_asset "${agent_sandbox_version}")"
kubectl "$@" apply -f "${agent_sandbox_base}/${agent_sandbox_manifest}"
wait_for_agent_sandbox_crd "$@"
kubectl "$@" -n agent-sandbox-system rollout status \
  deployment/agent-sandbox-controller --timeout=300s
