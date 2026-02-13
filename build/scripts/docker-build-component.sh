#!/usr/bin/env bash
# Generic Docker image builder for Navigator components.
# Usage: docker-build-component.sh <component> [extra docker build args...]
#
# Environment:
#   IMAGE_TAG          - Image tag (default: dev)
#   DOCKER_PLATFORM    - Target platform (optional, e.g. linux/amd64)
set -euo pipefail

COMPONENT=${1:?"Usage: docker-build-component.sh <component> [extra-args...]"}
shift

IMAGE_TAG=${IMAGE_TAG:-dev}
DOCKER_BUILD_CACHE_DIR=${DOCKER_BUILD_CACHE_DIR:-.cache/buildkit}
CACHE_PATH="${DOCKER_BUILD_CACHE_DIR}/${COMPONENT}"

mkdir -p "${CACHE_PATH}"

CACHE_ARGS=()
if [[ -n "${CI:-}" ]]; then
  echo "CI environment detected; skipping local build cache export options."
elif docker buildx inspect 2>/dev/null | grep -q "Driver: docker-container"; then
  CACHE_ARGS=(
    --cache-from "type=local,src=${CACHE_PATH}"
    --cache-to "type=local,dest=${CACHE_PATH},mode=max"
  )
else
  echo "Buildx driver does not support local cache export; skipping local build cache options."
fi

docker buildx build \
  ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
  "${CACHE_ARGS[@]}" \
  -f "deploy/docker/Dockerfile.${COMPONENT}" \
  -t "navigator-${COMPONENT}:${IMAGE_TAG}" \
  "$@" \
  --load \
  .
