#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build multi-arch gateway + cluster images and push to a container registry.
# Requires DOCKER_REGISTRY to be set (e.g. ghcr.io/myorg).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/container-engine.sh"

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

# ---------------------------------------------------------------------------
# Docker path: use buildx builders + imagetools for multi-arch
# ---------------------------------------------------------------------------
_publish_multiarch_docker() {
  BUILDER_NAME=${DOCKER_BUILDER:-multiarch}
  if ce buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    echo "Using existing buildx builder: ${BUILDER_NAME}"
    ce buildx use "${BUILDER_NAME}"
  else
    echo "Creating multi-platform buildx builder: ${BUILDER_NAME}..."
    ce buildx create --name "${BUILDER_NAME}" --use --bootstrap
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
        ce_imagetools_create \
          --prefer-index=false \
          -t "${full_image}:${tag}" \
          "${full_image}:${IMAGE_TAG}"
      done
    done
  fi
}

# ---------------------------------------------------------------------------
# Podman path: build per-platform, assemble manifest lists, push
# ---------------------------------------------------------------------------
_publish_multiarch_podman() {
  export IMAGE_REGISTRY="${REGISTRY}"

  # Split comma-separated platforms into an array.
  IFS=',' read -ra PLATFORM_LIST <<< "${PLATFORMS}"

  for component in gateway cluster; do
    local full_image="${REGISTRY}/${component}"
    local manifest_name="${full_image}:${IMAGE_TAG}"

    # Remove any pre-existing manifest list.
    ce manifest rm "${manifest_name}" 2>/dev/null || true
    ce manifest create "${manifest_name}"

    echo "Building multi-arch ${component} image..."
    for platform in "${PLATFORM_LIST[@]}"; do
      echo "  Building ${component} for ${platform}..."
      # Build for each platform and add to the manifest list.
      # docker-build-image.sh sources container-engine.sh itself,
      # so ce_build is used internally.
      DOCKER_PLATFORM="${platform}" \
      DOCKER_PUSH="" \
      IMAGE_TAG="${IMAGE_TAG}" \
        tasks/scripts/docker-build-image.sh "${component}"

      # Tag with a platform-specific suffix for manifest assembly.
      local platform_tag="${IMAGE_TAG}-${platform//\//-}"
      ce tag "openshell/${component}:${IMAGE_TAG}" "${full_image}:${platform_tag}"
      ce push "${full_image}:${platform_tag}"
      ce manifest add "${manifest_name}" "${full_image}:${platform_tag}"
    done

    echo "Pushing manifest ${manifest_name}..."
    ce manifest push --all "${manifest_name}" "docker://${manifest_name}"

    # Apply extra tags.
    TAGS_TO_APPLY=("${EXTRA_TAGS[@]}")
    if [[ "${TAG_LATEST}" == "true" ]]; then
      TAGS_TO_APPLY+=("latest")
    fi

    for tag in "${TAGS_TO_APPLY[@]}"; do
      [[ "${tag}" == "${IMAGE_TAG}" ]] && continue
      echo "Tagging ${full_image}:${tag}..."
      ce manifest create "${full_image}:${tag}" 2>/dev/null || ce manifest rm "${full_image}:${tag}" 2>/dev/null
      # Re-create from the primary manifest.
      if command -v skopeo >/dev/null 2>&1; then
        skopeo copy --all "docker://${manifest_name}" "docker://${full_image}:${tag}"
      else
        ce manifest create "${full_image}:${tag}"
        for platform in "${PLATFORM_LIST[@]}"; do
          local platform_tag="${IMAGE_TAG}-${platform//\//-}"
          ce manifest add "${full_image}:${tag}" "${full_image}:${platform_tag}"
        done
        ce manifest push --all "${full_image}:${tag}" "docker://${full_image}:${tag}"
      fi
    done
  done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if ce_is_docker; then
  _publish_multiarch_docker
else
  _publish_multiarch_podman
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
