#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

MODE=${1:-build}
if [ "${MODE}" != "build" ] && [ "${MODE}" != "fast" ]; then
  echo "usage: $0 [build|fast]" >&2
  exit 1
fi

if [ -n "${IMAGE_TAG:-}" ]; then
  IMAGE_TAG=${IMAGE_TAG}
else
  IMAGE_TAG=dev
fi
ENV_FILE=.env
PUBLISHED_IMAGE_REPO_BASE_DEFAULT=d1i0nduu2f6qxk.cloudfront.net/navigator
LOCAL_REGISTRY_CONTAINER=navigator-local-registry
LOCAL_REGISTRY_ADDR=127.0.0.1:5000

if [ -n "${CI:-}" ] && [ -n "${CI_REGISTRY_IMAGE:-}" ]; then
  IMAGE_REPO_BASE_DEFAULT=${CI_REGISTRY_IMAGE}
elif [ "${MODE}" = "fast" ]; then
  IMAGE_REPO_BASE_DEFAULT=${LOCAL_REGISTRY_ADDR}/navigator
else
  IMAGE_REPO_BASE_DEFAULT=${LOCAL_REGISTRY_ADDR}/navigator
fi

IMAGE_REPO_BASE=${IMAGE_REPO_BASE:-${NAVIGATOR_REGISTRY:-${IMAGE_REPO_BASE_DEFAULT}}}
REGISTRY_HOST=${NAVIGATOR_REGISTRY_HOST:-${IMAGE_REPO_BASE%%/*}}
REGISTRY_NAMESPACE_DEFAULT=${IMAGE_REPO_BASE#*/}

if [ "${REGISTRY_NAMESPACE_DEFAULT}" = "${IMAGE_REPO_BASE}" ]; then
  REGISTRY_NAMESPACE_DEFAULT=navigator
fi

has_env_key() {
  local key=$1
  [ -f "${ENV_FILE}" ] || return 1
  grep -Eq "^[[:space:]]*(export[[:space:]]+)?${key}=" "${ENV_FILE}"
}

append_env_if_missing() {
  local key=$1
  local value=$2
  if has_env_key "${key}"; then
    return
  fi
  if [ -f "${ENV_FILE}" ] && [ -s "${ENV_FILE}" ]; then
    printf "\n%s=%s\n" "${key}" "${value}" >>"${ENV_FILE}"
  else
    printf "%s=%s\n" "${key}" "${value}" >>"${ENV_FILE}"
  fi
}

port_is_in_use() {
  local port=$1
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi

  if command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "${port}" >/dev/null 2>&1
    return $?
  fi

  (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1
}

pick_random_port() {
  local lower=20000
  local upper=60999
  local attempts=256
  local port

  for _ in $(seq 1 "${attempts}"); do
    port=$((RANDOM % (upper - lower + 1) + lower))
    if ! port_is_in_use "${port}"; then
      echo "${port}"
      return 0
    fi
  done

  echo "Error: could not find a free port after ${attempts} attempts." >&2
  return 1
}

CLUSTER_NAME=${CLUSTER_NAME:-$(basename "$PWD")}

if [ -n "${GATEWAY_PORT:-}" ]; then
  RESOLVED_GATEWAY_PORT=${GATEWAY_PORT}
elif [ "${MODE}" = "fast" ]; then
  RESOLVED_GATEWAY_PORT=$(pick_random_port)
else
  RESOLVED_GATEWAY_PORT=8080
fi

NAVIGATOR_CLUSTER=${NAVIGATOR_CLUSTER:-${CLUSTER_NAME}}
GATEWAY_PORT=${RESOLVED_GATEWAY_PORT}

append_env_if_missing "CLUSTER_NAME" "${CLUSTER_NAME}"
append_env_if_missing "GATEWAY_PORT" "${GATEWAY_PORT}"
append_env_if_missing "NAVIGATOR_CLUSTER" "${NAVIGATOR_CLUSTER}"

export CLUSTER_NAME
export GATEWAY_PORT
export NAVIGATOR_CLUSTER

is_local_registry_host() {
  [ "${REGISTRY_HOST}" = "127.0.0.1:5000" ] || [ "${REGISTRY_HOST}" = "localhost:5000" ]
}

registry_reachable() {
  curl -4 -fsS --max-time 2 "http://127.0.0.1:5000/v2/" >/dev/null 2>&1 || \
    curl -4 -fsS --max-time 2 "http://localhost:5000/v2/" >/dev/null 2>&1
}

wait_for_registry_ready() {
  local attempts=${1:-20}
  local delay_s=${2:-1}
  local i

  for i in $(seq 1 "${attempts}"); do
    if registry_reachable; then
      return 0
    fi
    sleep "${delay_s}"
  done

  return 1
}

ensure_local_registry() {
  if docker inspect "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1; then
    local proxy_remote_url
    proxy_remote_url=$(docker inspect "${LOCAL_REGISTRY_CONTAINER}" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | awk -F= '/^REGISTRY_PROXY_REMOTEURL=/{print $2; exit}' || true)
    if [ -n "${proxy_remote_url}" ]; then
      docker rm -f "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1 || true
    fi
  fi

  if ! docker inspect "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1; then
    docker run -d --restart=always --name "${LOCAL_REGISTRY_CONTAINER}" -p 5000:5000 registry:2 >/dev/null
  else
    if ! docker ps --filter "name=^${LOCAL_REGISTRY_CONTAINER}$" --filter "status=running" -q | grep -q .; then
      docker start "${LOCAL_REGISTRY_CONTAINER}" >/dev/null
    fi

    port_map=$(docker port "${LOCAL_REGISTRY_CONTAINER}" 5000/tcp 2>/dev/null || true)
    case "${port_map}" in
      *:5000*)
        ;;
      *)
        docker rm -f "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1 || true
        docker run -d --restart=always --name "${LOCAL_REGISTRY_CONTAINER}" -p 5000:5000 registry:2 >/dev/null
        ;;
    esac
  fi

  if wait_for_registry_ready 20 1; then
    return
  fi

  if registry_reachable; then
    return
  fi

  echo "Error: local registry is not reachable at ${REGISTRY_HOST}." >&2
  echo "       Ensure a registry is running on port 5000 (e.g. docker run -d --name navigator-local-registry -p 5000:5000 registry:2)." >&2
  docker ps -a >&2 || true
  docker logs "${LOCAL_REGISTRY_CONTAINER}" >&2 || true
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

CONTAINER_NAME="navigator-cluster-${CLUSTER_NAME}"
VOLUME_NAME="navigator-cluster-${CLUSTER_NAME}"

if [ "${MODE}" = "fast" ]; then
  if docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1 || docker volume inspect "${VOLUME_NAME}" >/dev/null 2>&1; then
    echo "Recreating cluster '${CLUSTER_NAME}' from scratch..."
    nav cluster admin destroy --name "${CLUSTER_NAME}"
  fi
fi

if [ "${SKIP_IMAGE_PUSH:-}" = "1" ]; then
  echo "Skipping image push (SKIP_IMAGE_PUSH=1; images already in registry)."
elif [ "${MODE}" = "build" ] || [ "${MODE}" = "fast" ]; then
  for component in server sandbox; do
    build/scripts/cluster-push-component.sh "${component}"
  done
fi

DEPLOY_CMD=(nav cluster admin deploy --name "${CLUSTER_NAME}" --port "${GATEWAY_PORT}" --update-kube-config)

if [ -n "${GATEWAY_HOST:-}" ]; then
  DEPLOY_CMD+=(--gateway-host "${GATEWAY_HOST}")

  # Ensure the gateway host resolves from the current environment.
  # On Linux CI runners host.docker.internal is not set automatically
  # (it's a Docker Desktop feature). If the hostname doesn't resolve,
  # add it via the Docker bridge gateway IP.
  if ! getent hosts "${GATEWAY_HOST}" >/dev/null 2>&1; then
    BRIDGE_IP=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)
    if [ -n "${BRIDGE_IP}" ]; then
      echo "Adding /etc/hosts entry: ${BRIDGE_IP} ${GATEWAY_HOST}"
      echo "${BRIDGE_IP} ${GATEWAY_HOST}" >> /etc/hosts
    fi
  fi
fi

if [ -n "${KUBE_PORT:-}" ]; then
  # Explicit port requested — pass it through.
  DEPLOY_CMD+=(--kube-port "${KUBE_PORT}")
else
  # Auto-select a free port so kubectl works during local development.
  DEPLOY_CMD+=(--kube-port)
fi

"${DEPLOY_CMD[@]}"

echo ""
echo "Cluster '${CLUSTER_NAME}' is ready."
echo "KUBECONFIG has been updated."
