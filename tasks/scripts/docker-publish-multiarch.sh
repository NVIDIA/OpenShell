#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "Usage: docker-publish-multiarch.sh --mode <registry|ecr>" >&2
  exit 1
}

MODE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      ;;
  esac
done

[[ -n "${MODE}" ]] || usage

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

case "${MODE}" in
  registry)
    REGISTRY=${DOCKER_REGISTRY:?Set DOCKER_REGISTRY to push multi-arch images (e.g. ghcr.io/myorg)}
    ;;
  ecr)
    AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID:-012345678901}
    AWS_REGION=${AWS_REGION:-us-west-2}
    REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/openshell"
    ;;
  *)
    echo "Unknown mode: ${MODE}" >&2
    usage
    ;;
esac

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

mkdir -p deploy/docker/.build/charts
echo "Packaging helm chart..."
helm package deploy/helm/openshell -d deploy/docker/.build/charts/

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
