#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Unified cluster entrypoint: bootstrap if no cluster is running, then
# incremental deploy.

set -euo pipefail

CLUSTER_NAME=${CLUSTER_NAME:-$(basename "$PWD")}
CONTAINER_NAME="navigator-cluster-${CLUSTER_NAME}"

if ! docker ps -q --filter "name=${CONTAINER_NAME}" | grep -q .; then
  echo "No running cluster found. Bootstrapping..."
  exec tasks/scripts/cluster-bootstrap.sh fast
fi

exec tasks/scripts/cluster-deploy-fast.sh "$@"
