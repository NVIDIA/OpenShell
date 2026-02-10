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

docker buildx build \
  ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
  -f "deploy/docker/Dockerfile.${COMPONENT}" \
  -t "navigator-${COMPONENT}:${IMAGE_TAG}" \
  "$@" \
  --load \
  .
