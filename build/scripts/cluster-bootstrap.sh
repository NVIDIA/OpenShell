#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME=${CLUSTER_NAME:-$(basename "$PWD")}
IMAGE_TAG=${IMAGE_TAG:-dev}

if [ -n "${CI:-}" ] && [ -n "${CI_REGISTRY_IMAGE:-}" ]; then
  IMAGE_REPO_BASE_DEFAULT=${CI_REGISTRY_IMAGE}
else
  IMAGE_REPO_BASE_DEFAULT=localhost:5000/navigator
fi

IMAGE_REPO_BASE=${IMAGE_REPO_BASE:-${NAVIGATOR_REGISTRY:-${IMAGE_REPO_BASE_DEFAULT}}}
REGISTRY_HOST=${NAVIGATOR_REGISTRY_HOST:-${IMAGE_REPO_BASE%%/*}}
REGISTRY_NAMESPACE_DEFAULT=${IMAGE_REPO_BASE#*/}

if [ "${REGISTRY_NAMESPACE_DEFAULT}" = "${IMAGE_REPO_BASE}" ]; then
  REGISTRY_NAMESPACE_DEFAULT=navigator
fi

is_local_registry_host() {
  [ "${REGISTRY_HOST}" = "127.0.0.1:5000" ] || [ "${REGISTRY_HOST}" = "localhost:5000" ]
}

registry_reachable() {
  curl -4 -fsS --max-time 2 "http://127.0.0.1:5000/v2/" >/dev/null 2>&1 || \
    curl -4 -fsS --max-time 2 "http://localhost:5000/v2/" >/dev/null 2>&1
}

ensure_local_registry() {
  if registry_reachable; then
    return
  fi

  if ! docker inspect navigator-local-registry >/dev/null 2>&1; then
    docker run -d --restart=always --name navigator-local-registry -p 5000:5000 registry:2 >/dev/null
  else
    if ! docker ps --filter "name=^navigator-local-registry$" --filter "status=running" -q | grep -q .; then
      docker start navigator-local-registry >/dev/null
    fi

    port_map=$(docker port navigator-local-registry 5000/tcp 2>/dev/null || true)
    case "${port_map}" in
      *:5000*)
        ;;
      *)
        docker rm -f navigator-local-registry >/dev/null 2>&1 || true
        docker run -d --restart=always --name navigator-local-registry -p 5000:5000 registry:2 >/dev/null
        ;;
    esac
  fi

  if registry_reachable; then
    return
  fi

  echo "Error: local registry is not reachable at ${REGISTRY_HOST}." >&2
  echo "       Ensure a registry is running on port 5000 (e.g. docker run -d --name navigator-local-registry -p 5000:5000 registry:2)." >&2
  docker ps -a >&2 || true
  docker logs navigator-local-registry >&2 || true
  exit 1
}

REGISTRY_ENDPOINT_DEFAULT=${REGISTRY_HOST}
if is_local_registry_host; then
  REGISTRY_ENDPOINT_DEFAULT=host.docker.internal:5000
fi

REGISTRY_INSECURE_DEFAULT=false
if is_local_registry_host; then
  REGISTRY_INSECURE_DEFAULT=true
fi

export NAVIGATOR_REGISTRY_HOST=${NAVIGATOR_REGISTRY_HOST:-${REGISTRY_HOST}}
export NAVIGATOR_REGISTRY_ENDPOINT=${NAVIGATOR_REGISTRY_ENDPOINT:-${REGISTRY_ENDPOINT_DEFAULT}}
export NAVIGATOR_REGISTRY_NAMESPACE=${NAVIGATOR_REGISTRY_NAMESPACE:-${REGISTRY_NAMESPACE_DEFAULT}}
export NAVIGATOR_REGISTRY_INSECURE=${NAVIGATOR_REGISTRY_INSECURE:-${REGISTRY_INSECURE_DEFAULT}}
export IMAGE_REPO_BASE
export IMAGE_TAG

if [ -n "${CI:-}" ] && [ -n "${CI_REGISTRY:-}" ] && [ -n "${CI_REGISTRY_USER:-}" ] && [ -n "${CI_REGISTRY_PASSWORD:-}" ]; then
  printf '%s' "${CI_REGISTRY_PASSWORD}" | docker login -u "${CI_REGISTRY_USER}" --password-stdin "${CI_REGISTRY}"
  export NAVIGATOR_REGISTRY_USERNAME=${NAVIGATOR_REGISTRY_USERNAME:-${CI_REGISTRY_USER}}
  export NAVIGATOR_REGISTRY_PASSWORD=${NAVIGATOR_REGISTRY_PASSWORD:-${CI_REGISTRY_PASSWORD}}
fi

if is_local_registry_host; then
  ensure_local_registry
fi

for component in server sandbox pki-job; do
  build/scripts/cluster-push-component.sh "${component}"
done

nav cluster admin deploy --name "${CLUSTER_NAME}" --update-kube-config

echo ""
echo "Cluster '${CLUSTER_NAME}' is ready."
echo "KUBECONFIG has been updated."
