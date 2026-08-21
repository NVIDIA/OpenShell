#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Install the upstream Agent Sandbox CRDs and controller. Pass any kubectl
# context arguments (for example, --context kind-e2e) as script arguments.
set -euo pipefail

agent_sandbox_version="${AGENT_SANDBOX_VERSION:-v0.5.0}"
echo "Installing agent-sandbox CRDs and controller (${agent_sandbox_version})..."
agent_sandbox_base="https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${agent_sandbox_version}"
kubectl "$@" apply -f "${agent_sandbox_base}/manifest.yaml"
kubectl "$@" wait --for=condition=Established \
  crd/sandboxes.agents.x-k8s.io --timeout=120s
kubectl "$@" -n agent-sandbox-system rollout status \
  deployment/agent-sandbox-controller --timeout=300s
