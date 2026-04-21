#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

normalize_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//'
}

CLUSTER_NAME=${CLUSTER_NAME:-$(basename "$PWD")}
CLUSTER_NAME=$(normalize_name "${CLUSTER_NAME}")
CONTAINER_NAME="openshell-cluster-${CLUSTER_NAME}"

if ! docker ps -aq --filter "name=^${CONTAINER_NAME}$" | grep -q .; then
  echo "No cluster container '${CONTAINER_NAME}' found."
  exit 0
fi

echo "Stopping cluster '${CLUSTER_NAME}'..."
docker rm -f "${CONTAINER_NAME}" >/dev/null
echo "Cluster '${CLUSTER_NAME}' stopped and removed."
