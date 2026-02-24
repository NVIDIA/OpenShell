#!/usr/bin/env bash
set -euo pipefail

component=${1:-}
if [ -z "${component}" ]; then
  echo "usage: $0 <server|sandbox>" >&2
  exit 1
fi

case "${component}" in
  server|sandbox)
    ;;
  *)
    echo "invalid component '${component}'; expected server or sandbox" >&2
    exit 1
    ;;
esac

IMAGE_TAG=${IMAGE_TAG:-dev}
IMAGE_REPO_BASE=${IMAGE_REPO_BASE:-${NAVIGATOR_REGISTRY:-localhost:5000/navigator}}
CLUSTER_NAME=${CLUSTER_NAME:-$(basename "$PWD")}
CONTAINER_NAME="navigator-cluster-${CLUSTER_NAME}"

docker tag "navigator-${component}:${IMAGE_TAG}" "${IMAGE_REPO_BASE}/${component}:${IMAGE_TAG}"
docker push "${IMAGE_REPO_BASE}/${component}:${IMAGE_TAG}"

# Evict the stale image from k3s's containerd cache so new pods pull the
# updated image. Without this, k3s uses its cached copy (imagePullPolicy
# defaults to IfNotPresent for non-:latest tags) and pods run stale code.
if docker ps -q --filter "name=${CONTAINER_NAME}" | grep -q .; then
  docker exec "${CONTAINER_NAME}" crictl rmi "${IMAGE_REPO_BASE}/${component}:${IMAGE_TAG}" >/dev/null 2>&1 || true
fi
