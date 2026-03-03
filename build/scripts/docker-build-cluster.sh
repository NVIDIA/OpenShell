#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the k3s cluster image with bundled helm charts.
#
# Environment:
#   IMAGE_TAG                - Image tag (default: dev)
#   K3S_VERSION              - k3s version (set by mise.toml [env])

#   DOCKER_PLATFORM          - Target platform (optional)
#   DOCKER_BUILDER           - Buildx builder name (default: auto-select)
#   DOCKER_PUSH              - When set to "1", push instead of loading into local daemon
#   IMAGE_REGISTRY           - Registry prefix for image name (e.g. ghcr.io/org/repo)
set -euo pipefail

IMAGE_TAG=${IMAGE_TAG:-dev}
IMAGE_NAME="navigator/cluster"
if [[ -n "${IMAGE_REGISTRY:-}" ]]; then
  IMAGE_NAME="${IMAGE_REGISTRY}/cluster"
fi
DOCKER_BUILD_CACHE_DIR=${DOCKER_BUILD_CACHE_DIR:-.cache/buildkit}
CACHE_PATH="${DOCKER_BUILD_CACHE_DIR}/cluster"

mkdir -p "${CACHE_PATH}"

# Select builder — prefer native "docker" driver for local single-arch builds
# to avoid slow tarball export from the docker-container driver.
BUILDER_ARGS=()
if [[ -n "${DOCKER_BUILDER:-}" ]]; then
  BUILDER_ARGS=(--builder "${DOCKER_BUILDER}")
elif [[ -z "${DOCKER_PLATFORM:-}" && -z "${CI:-}" ]]; then
  _ctx=$(docker context inspect --format '{{.Name}}' 2>/dev/null || echo default)
  BUILDER_ARGS=(--builder "${_ctx}")
fi

CACHE_ARGS=()
if [[ -z "${CI:-}" ]]; then
  # Local development: use filesystem cache with docker-container driver.
  if docker buildx inspect ${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} 2>/dev/null | grep -q "Driver: docker-container"; then
    CACHE_ARGS=(
      --cache-from "type=local,src=${CACHE_PATH}"
      --cache-to "type=local,dest=${CACHE_PATH},mode=max"
    )
  fi
fi

# Create build directory for charts
mkdir -p deploy/docker/.build/charts

# Package navigator helm chart
echo "Packaging navigator helm chart..."
helm package deploy/helm/navigator -d deploy/docker/.build/charts/

# Build cluster image (no bundled component images — they are pulled at runtime
# from the distribution registry; credentials are injected at deploy time)
echo "Building cluster image..."

OUTPUT_FLAG="--load"
if [[ "${DOCKER_PUSH:-}" == "1" ]]; then
  OUTPUT_FLAG="--push"
fi

docker buildx build \
  ${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} \
  ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
  ${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"} \
  -f deploy/docker/Dockerfile.cluster \
  -t ${IMAGE_NAME}:${IMAGE_TAG} \
  --build-arg K3S_VERSION=${K3S_VERSION} \
  ${OUTPUT_FLAG} \
  .

echo "Done! Cluster image: ${IMAGE_NAME}:${IMAGE_TAG}"
