#!/usr/bin/env bash
# Generic Docker image builder for Navigator components.
# Usage: docker-build-component.sh <component> [extra docker build args...]
#
# Environment:
#   IMAGE_TAG          - Image tag (default: dev)
#   DOCKER_PLATFORM    - Target platform (optional, e.g. linux/amd64)
#   DOCKER_BUILDER     - Buildx builder name (default: auto-select)
set -euo pipefail

COMPONENT=${1:?"Usage: docker-build-component.sh <component> [extra-args...]"}
shift

IMAGE_TAG=${IMAGE_TAG:-dev}
DOCKER_BUILD_CACHE_DIR=${DOCKER_BUILD_CACHE_DIR:-.cache/buildkit}
CACHE_PATH="${DOCKER_BUILD_CACHE_DIR}/${COMPONENT}"

mkdir -p "${CACHE_PATH}"

# Select the builder. For local (single-arch) builds use a builder with the
# native "docker" driver so images land directly in the Docker image store —
# no slow tarball export via the docker-container driver.
# Multi-platform builds (DOCKER_PLATFORM set) keep the current builder which
# is typically docker-container.
BUILDER_ARGS=()
if [[ -n "${DOCKER_BUILDER:-}" ]]; then
  BUILDER_ARGS=(--builder "${DOCKER_BUILDER}")
elif [[ -z "${DOCKER_PLATFORM:-}" && -z "${CI:-}" ]]; then
  # Pick the builder matching the active docker context (uses docker driver).
  _ctx=$(docker context inspect --format '{{.Name}}' 2>/dev/null || echo default)
  BUILDER_ARGS=(--builder "${_ctx}")
fi

CACHE_ARGS=()
if [[ -n "${CI:-}" ]]; then
  echo "CI environment detected; skipping local build cache export options."
elif docker buildx inspect "${BUILDER_ARGS[@]}" 2>/dev/null | grep -q "Driver: docker-container"; then
  CACHE_ARGS=(
    --cache-from "type=local,src=${CACHE_PATH}"
    --cache-to "type=local,dest=${CACHE_PATH},mode=max"
  )
fi

docker buildx build \
  "${BUILDER_ARGS[@]}" \
  ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
  "${CACHE_ARGS[@]}" \
  -f "deploy/docker/Dockerfile.${COMPONENT}" \
  -t "navigator-${COMPONENT}:${IMAGE_TAG}" \
  "$@" \
  --load \
  .
