#!/usr/bin/env bash
set -euo pipefail

component=${1:-}
if [ -z "${component}" ]; then
  echo "usage: $0 <server|sandbox|pki-job>" >&2
  exit 1
fi

case "${component}" in
  server|sandbox|pki-job)
    ;;
  *)
    echo "invalid component '${component}'; expected server, sandbox, or pki-job" >&2
    exit 1
    ;;
esac

IMAGE_TAG=${IMAGE_TAG:-dev}
IMAGE_REPO_BASE=${IMAGE_REPO_BASE:-${NAVIGATOR_REGISTRY:-localhost:5000/navigator}}

docker tag "navigator-${component}:${IMAGE_TAG}" "${IMAGE_REPO_BASE}/${component}:${IMAGE_TAG}"
docker push "${IMAGE_REPO_BASE}/${component}:${IMAGE_TAG}"
