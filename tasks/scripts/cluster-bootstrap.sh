#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/container-engine.sh"

# Normalize cluster name: lowercase, replace invalid chars with hyphens
normalize_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//'
}

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
PUBLISHED_IMAGE_REPO_BASE_DEFAULT=ghcr.io/nvidia/openshell
LOCAL_REGISTRY_CONTAINER=openshell-local-registry
LOCAL_REGISTRY_ADDR=127.0.0.1:5000

if [ -n "${CI:-}" ] && [ -n "${CI_REGISTRY_IMAGE:-}" ]; then
  IMAGE_REPO_BASE_DEFAULT=${CI_REGISTRY_IMAGE}
elif [ "${MODE}" = "fast" ]; then
  IMAGE_REPO_BASE_DEFAULT=${LOCAL_REGISTRY_ADDR}/openshell
else
  IMAGE_REPO_BASE_DEFAULT=${LOCAL_REGISTRY_ADDR}/openshell
fi

IMAGE_REPO_BASE=${IMAGE_REPO_BASE:-${OPENSHELL_REGISTRY:-${IMAGE_REPO_BASE_DEFAULT}}}
REGISTRY_HOST=${OPENSHELL_REGISTRY_HOST:-${IMAGE_REPO_BASE%%/*}}
REGISTRY_NAMESPACE_DEFAULT=${IMAGE_REPO_BASE#*/}

if [ "${REGISTRY_NAMESPACE_DEFAULT}" = "${IMAGE_REPO_BASE}" ]; then
  REGISTRY_NAMESPACE_DEFAULT=openshell
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
    # Ensure file ends with newline before appending, but don't add extra blank line
    if [ "$(tail -c1 "${ENV_FILE}" | wc -l)" -eq 0 ]; then
      printf "\n" >>"${ENV_FILE}"
    fi
  fi
  printf "%s=%s\n" "${key}" "${value}" >>"${ENV_FILE}"
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
CLUSTER_NAME=$(normalize_name "${CLUSTER_NAME}")

if [ -n "${GATEWAY_PORT:-}" ]; then
  RESOLVED_GATEWAY_PORT=${GATEWAY_PORT}
elif [ "${MODE}" = "fast" ]; then
  RESOLVED_GATEWAY_PORT=$(pick_random_port)
else
  RESOLVED_GATEWAY_PORT=8080
fi

OPENSHELL_GATEWAY=${OPENSHELL_GATEWAY:-${CLUSTER_NAME}}
GATEWAY_PORT=${RESOLVED_GATEWAY_PORT}

append_env_if_missing "GATEWAY_PORT" "${GATEWAY_PORT}"
append_env_if_missing "OPENSHELL_GATEWAY" "${OPENSHELL_GATEWAY}"

export CLUSTER_NAME
export GATEWAY_PORT
export OPENSHELL_GATEWAY

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
  if ce inspect "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1; then
    local proxy_remote_url
    proxy_remote_url=$(ce inspect "${LOCAL_REGISTRY_CONTAINER}" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | awk -F= '/^REGISTRY_PROXY_REMOTEURL=/{print $2; exit}' || true)
    if [ -n "${proxy_remote_url}" ]; then
      ce rm -f "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1 || true
    fi
  fi

  if ! ce inspect "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1; then
    # --restart=always: on Docker this is managed by the Docker daemon and
    # survives reboots when the daemon is enabled at boot.  On rootless Podman
    # it is handled by conmon within the current login session; it does NOT
    # survive user logout or reboot without a systemd user unit.  This is
    # acceptable here because ensure_local_registry() recreates the container
    # on every cluster bootstrap invocation if it is missing.
    ce run -d --restart=always --name "${LOCAL_REGISTRY_CONTAINER}" -p 5000:5000 registry:2 >/dev/null
  else
    if ! ce ps --filter "name=^${LOCAL_REGISTRY_CONTAINER}$" --filter "status=running" -q | grep -q .; then
      ce start "${LOCAL_REGISTRY_CONTAINER}" >/dev/null
    fi

    port_map=$(ce port "${LOCAL_REGISTRY_CONTAINER}" 5000/tcp 2>/dev/null || true)
    case "${port_map}" in
      *:5000*)
        ;;
      *)
        ce rm -f "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1 || true
        # See --restart=always note above in this function.
        ce run -d --restart=always --name "${LOCAL_REGISTRY_CONTAINER}" -p 5000:5000 registry:2 >/dev/null
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
  echo "       Ensure a registry is running on port 5000 (e.g. ${CONTAINER_ENGINE} run -d --name openshell-local-registry -p 5000:5000 registry:2)." >&2
  ce ps -a >&2 || true
  ce logs "${LOCAL_REGISTRY_CONTAINER}" >&2 || true
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

export OPENSHELL_REGISTRY_HOST=${OPENSHELL_REGISTRY_HOST:-${REGISTRY_HOST}}
export OPENSHELL_REGISTRY_ENDPOINT=${OPENSHELL_REGISTRY_ENDPOINT:-${REGISTRY_ENDPOINT_DEFAULT}}
export OPENSHELL_REGISTRY_NAMESPACE=${OPENSHELL_REGISTRY_NAMESPACE:-${REGISTRY_NAMESPACE_DEFAULT}}
export OPENSHELL_REGISTRY_INSECURE=${OPENSHELL_REGISTRY_INSECURE:-${REGISTRY_INSECURE_DEFAULT}}
export IMAGE_REPO_BASE
export IMAGE_TAG

if [ -n "${CI:-}" ] && [ -n "${CI_REGISTRY:-}" ] && [ -n "${CI_REGISTRY_USER:-}" ] && [ -n "${CI_REGISTRY_PASSWORD:-}" ]; then
  printf '%s' "${CI_REGISTRY_PASSWORD}" | ce login -u "${CI_REGISTRY_USER}" --password-stdin "${CI_REGISTRY}"
  export OPENSHELL_REGISTRY_USERNAME=${OPENSHELL_REGISTRY_USERNAME:-${CI_REGISTRY_USER}}
  export OPENSHELL_REGISTRY_PASSWORD=${OPENSHELL_REGISTRY_PASSWORD:-${CI_REGISTRY_PASSWORD}}
fi

if is_local_registry_host; then
  ensure_local_registry
fi

CONTAINER_NAME="openshell-cluster-${CLUSTER_NAME}"
VOLUME_NAME="openshell-cluster-${CLUSTER_NAME}"

if [ "${MODE}" = "fast" ]; then
  if ce inspect "${CONTAINER_NAME}" >/dev/null 2>&1 || ce volume inspect "${VOLUME_NAME}" >/dev/null 2>&1; then
    echo "Recreating cluster '${CLUSTER_NAME}' from scratch..."
    openshell gateway destroy --name "${CLUSTER_NAME}"
  fi
fi

if [ "${SKIP_IMAGE_PUSH:-}" = "1" ]; then
  echo "Skipping image push (SKIP_IMAGE_PUSH=1; images already in registry)."
elif [ "${MODE}" = "build" ] || [ "${MODE}" = "fast" ]; then
  tasks/scripts/cluster-push-component.sh gateway
fi

# Build the cluster image so it contains the latest Helm chart, manifests,
# and entrypoint from the working tree.  This ensures the k3s container
# always starts with the correct chart version.
if [ "${SKIP_CLUSTER_IMAGE_BUILD:-}" != "1" ]; then
  tasks/scripts/docker-build-image.sh cluster
fi

# In fast/build modes, use the locally-built cluster image rather than the
# remote distribution registry image.  The local image is built by
# `docker-build-image.sh cluster` and contains the bundled Helm chart and
# manifests from the current working tree.
if [ -z "${OPENSHELL_CLUSTER_IMAGE:-}" ]; then
  export OPENSHELL_CLUSTER_IMAGE="openshell/cluster:${IMAGE_TAG}"
fi

DEPLOY_CMD=(openshell gateway start --name "${CLUSTER_NAME}" --port "${GATEWAY_PORT}")

if [ "${CLUSTER_GPU:-0}" = "1" ]; then
  DEPLOY_CMD+=(--gpu)
fi

if [ -n "${GATEWAY_HOST:-}" ]; then
  DEPLOY_CMD+=(--gateway-host "${GATEWAY_HOST}")

  # Ensure the gateway host resolves from the current environment.
  # On Linux CI runners host.docker.internal is not set automatically
  # (it's a Docker Desktop feature). If the hostname doesn't resolve,
  # add it via the Docker bridge gateway IP.
  if ! getent hosts "${GATEWAY_HOST}" >/dev/null 2>&1; then
    BRIDGE_IP=$(ce_network_gateway)
    if [ -n "${BRIDGE_IP}" ]; then
      echo "Adding /etc/hosts entry: ${BRIDGE_IP} ${GATEWAY_HOST}"
      echo "${BRIDGE_IP} ${GATEWAY_HOST}" >> /etc/hosts
    fi
  fi
fi

if [ -n "${OPENSHELL_OIDC_ISSUER:-}" ]; then
  DEPLOY_CMD+=(--oidc-issuer "${OPENSHELL_OIDC_ISSUER}")
  [ -n "${OPENSHELL_OIDC_AUDIENCE:-}" ] && DEPLOY_CMD+=(--oidc-audience "${OPENSHELL_OIDC_AUDIENCE}")
  [ -n "${OPENSHELL_OIDC_ROLES_CLAIM:-}" ] && DEPLOY_CMD+=(--oidc-roles-claim "${OPENSHELL_OIDC_ROLES_CLAIM}")
  [ -n "${OPENSHELL_OIDC_ADMIN_ROLE:-}" ] && DEPLOY_CMD+=(--oidc-admin-role "${OPENSHELL_OIDC_ADMIN_ROLE}")
  [ -n "${OPENSHELL_OIDC_USER_ROLE:-}" ] && DEPLOY_CMD+=(--oidc-user-role "${OPENSHELL_OIDC_USER_ROLE}")
  [ -n "${OPENSHELL_OIDC_SCOPES_CLAIM:-}" ] && DEPLOY_CMD+=(--oidc-scopes-claim "${OPENSHELL_OIDC_SCOPES_CLAIM}")
  [ -n "${OPENSHELL_OIDC_SCOPES:-}" ] && DEPLOY_CMD+=(--oidc-scopes "${OPENSHELL_OIDC_SCOPES}")
fi

"${DEPLOY_CMD[@]}"

# Clear the fast-deploy state file so the next incremental deploy
# recalculates from scratch.  This prevents stale fingerprints from a
# prior session from masking changes that the bootstrap has already baked
# into the freshly pushed images.
DEPLOY_FAST_STATE_FILE=${DEPLOY_FAST_STATE_FILE:-.cache/cluster-deploy-fast.state}
rm -f "${DEPLOY_FAST_STATE_FILE}"

echo ""
echo "Cluster '${CLUSTER_NAME}' is ready."
