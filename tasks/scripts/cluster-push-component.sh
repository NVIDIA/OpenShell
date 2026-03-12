#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

component=${1:-}
if [ -z "${component}" ]; then
  echo "usage: $0 <gateway>" >&2
  exit 1
fi

case "${component}" in
  gateway)
    ;;
  *)
    echo "invalid component '${component}'; expected gateway" >&2
    exit 1
    ;;
esac

# Normalize cluster name: lowercase, replace invalid chars with hyphens
normalize_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//'
}

IMAGE_TAG=${IMAGE_TAG:-dev}
IMAGE_REPO_BASE=${IMAGE_REPO_BASE:-${OPENSHELL_REGISTRY:-127.0.0.1:5000/openshell}}
CLUSTER_NAME=${CLUSTER_NAME:-$(basename "$PWD")}
CLUSTER_NAME=$(normalize_name "${CLUSTER_NAME}")
CONTAINER_NAME="openshell-cluster-${CLUSTER_NAME}"
SOURCE_IMAGE="openshell/${component}:${IMAGE_TAG}"
TARGET_IMAGE="${IMAGE_REPO_BASE}/${component}:${IMAGE_TAG}"

source_candidates=(
  "openshell/${component}:${IMAGE_TAG}"
  "localhost:5000/openshell/${component}:${IMAGE_TAG}"
  "127.0.0.1:5000/openshell/${component}:${IMAGE_TAG}"
)

resolved_source_image=""
for candidate in "${source_candidates[@]}"; do
  if docker image inspect "${candidate}" >/dev/null 2>&1; then
    resolved_source_image="${candidate}"
    break
  fi
done

if [ -z "${resolved_source_image}" ]; then
  echo "Local image not found for ${component}:${IMAGE_TAG}, building..."
  tasks/scripts/docker-build-component.sh "${component}"
  resolved_source_image="openshell/${component}:${IMAGE_TAG}"
fi

docker tag "${resolved_source_image}" "${TARGET_IMAGE}"
docker push "${TARGET_IMAGE}"

# Evict the stale image from k3s's containerd cache so new pods pull the
# updated image. Without this, k3s uses its cached copy (imagePullPolicy
# defaults to IfNotPresent for non-:latest tags) and pods run stale code.
if docker ps -q --filter "name=${CONTAINER_NAME}" | grep -q .; then
  docker exec "${CONTAINER_NAME}" crictl rmi "${TARGET_IMAGE}" >/dev/null 2>&1 || true
fi
