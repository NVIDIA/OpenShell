#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# List the runtime jobs required by one family/profile. The workflow uses this
# same list for execution and completion, so skipped selected jobs fail the gate.
set -euo pipefail

family="${1:-}"
profile="${2:-}"
case "${family}" in
  conformance|drivers) ;;
  *) echo "error: expected conformance or drivers, got '${family}'" >&2; exit 2 ;;
esac

case "${profile}" in
  core)
    jobs=(docker-e2e podman-e2e vm-e2e kubernetes-e2e kubernetes-workspace-managed-e2e vm-external-driver-e2e)
    if [ "${family}" = conformance ]; then
      jobs+=(docker-external-driver-e2e podman-external-driver-e2e kubernetes-external-driver-e2e)
    else
      # Operator mode currently excludes conformance; see #2971.
      jobs+=(kubernetes-workspace-operator-e2e)
    fi
    ;;
  release) jobs=(docker-e2e vm-e2e) ;;
  gpu) jobs=(gpu-e2e) ;;
  kubernetes-ha) jobs=(kubernetes-ha-e2e) ;;
  kubernetes-credentials) jobs=(kubernetes-credential-drivers-e2e) ;;
  *) echo "error: unknown runtime profile '${profile}'" >&2; exit 2 ;;
esac

jq -cn --args '$ARGS.positional' "${jobs[@]}"
