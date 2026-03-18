#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build multi-arch gateway + cluster images and push to a container registry.
# Requires DOCKER_REGISTRY to be set (e.g. ghcr.io/myorg).

set -euo pipefail

REGISTRY=${DOCKER_REGISTRY:?Set DOCKER_REGISTRY to push multi-arch images (e.g. ghcr.io/myorg)}
IMAGE_TAG=${IMAGE_TAG:-dev}
PLATFORMS=${DOCKER_PLATFORMS:-linux/amd64,linux/arm64}
TAG_LATEST=${TAG_LATEST:-false}
EXTRA_DOCKER_TAGS_RAW=${EXTRA_DOCKER_TAGS:-}
EXTRA_TAGS=()

if [[ -n "${EXTRA_DOCKER_TAGS_RAW}" ]]; then
  EXTRA_DOCKER_TAGS_RAW=${EXTRA_DOCKER_TAGS_RAW//,/ }
  for tag in ${EXTRA_DOCKER_TAGS_RAW}; do
    [[ -n "${tag}" ]] && EXTRA_TAGS+=("${tag}")
  done
fi

BUILDER_NAME=${DOCKER_BUILDER:-multiarch}
if docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
  echo "Using existing buildx builder: ${BUILDER_NAME}"
  docker buildx use "${BUILDER_NAME}"
else
  echo "Creating multi-platform buildx builder: ${BUILDER_NAME}..."
  docker buildx create --name "${BUILDER_NAME}" --use --bootstrap
fi

export DOCKER_BUILDER="${BUILDER_NAME}"
export DOCKER_PLATFORM="${PLATFORMS}"
export DOCKER_PUSH=1
export IMAGE_REGISTRY="${REGISTRY}"

echo "Building multi-arch gateway image..."
tasks/scripts/docker-build-image.sh gateway

echo
echo "Building multi-arch cluster image..."
tasks/scripts/docker-build-image.sh cluster

TAGS_TO_APPLY=("${EXTRA_TAGS[@]}")
if [[ "${TAG_LATEST}" == "true" ]]; then
  TAGS_TO_APPLY+=("latest")
fi

if [[ ${#TAGS_TO_APPLY[@]} -gt 0 ]]; then
  for component in gateway cluster; do
    full_image="${REGISTRY}/${component}"
    for tag in "${TAGS_TO_APPLY[@]}"; do
      [[ "${tag}" == "${IMAGE_TAG}" ]] && continue
      echo "Tagging ${full_image}:${tag}..."
      docker buildx imagetools create \
        --prefer-index=false \
        -t "${full_image}:${tag}" \
        "${full_image}:${IMAGE_TAG}"
    done
  done
fi

echo
echo "Done! Multi-arch images pushed to ${REGISTRY}:"
echo "  ${REGISTRY}/gateway:${IMAGE_TAG}"
echo "  ${REGISTRY}/cluster:${IMAGE_TAG}"
if [[ "${TAG_LATEST}" == "true" ]]; then
  echo "  (all also tagged :latest)"
fi
if [[ ${#EXTRA_TAGS[@]} -gt 0 ]]; then
  echo "  (all also tagged: ${EXTRA_TAGS[*]})"
fi
