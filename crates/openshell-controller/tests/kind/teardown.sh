#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Delete the kind cluster created by bootstrap.sh.

set -euo pipefail

CLUSTER_NAME="openshell-controller-test"
export KIND_EXPERIMENTAL_PROVIDER="${KIND_EXPERIMENTAL_PROVIDER:-podman}"

if kind get clusters | grep -qx "$CLUSTER_NAME"; then
  echo "==> deleting kind cluster '$CLUSTER_NAME'"
  kind delete cluster --name "$CLUSTER_NAME"
else
  echo "==> kind cluster '$CLUSTER_NAME' not present, nothing to do"
fi
