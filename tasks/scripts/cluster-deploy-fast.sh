#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Normalize cluster name: lowercase, replace invalid chars with hyphens
normalize_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//'
}

CLUSTER_NAME=${CLUSTER_NAME:-$(basename "$PWD")}
CLUSTER_NAME=$(normalize_name "${CLUSTER_NAME}")
CONTAINER_NAME="openshell-cluster-${CLUSTER_NAME}"
IMAGE_REPO_BASE=${IMAGE_REPO_BASE:-${OPENSHELL_REGISTRY:-127.0.0.1:5000/openshell}}
IMAGE_TAG=${IMAGE_TAG:-dev}
RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE:-debug}
DEPLOY_FAST_MODE=${DEPLOY_FAST_MODE:-auto}
FORCE_HELM_UPGRADE=${FORCE_HELM_UPGRADE:-0}
DEPLOY_FAST_HELM_WAIT=${DEPLOY_FAST_HELM_WAIT:-0}
DEPLOY_FAST_STATE_FILE=${DEPLOY_FAST_STATE_FILE:-.cache/cluster-deploy-fast.state}

overall_start=$(date +%s)

log_duration() {
  local label=$1
  local start=$2
  local end=$3
  echo "${label} took $((end - start))s"
}

if ! docker ps -q --filter "name=^${CONTAINER_NAME}$" --filter "health=healthy" | grep -q .; then
  echo "Error: Cluster container '${CONTAINER_NAME}' is not running or not healthy."
  echo "Start the cluster first with: mise run cluster"
  exit 1
fi

build_gateway=0
build_sandbox=0
needs_helm_upgrade=0
explicit_target=0

previous_gateway_fingerprint=""
previous_sandbox_fingerprint=""
previous_helm_fingerprint=""
current_gateway_fingerprint=""
current_sandbox_fingerprint=""
current_helm_fingerprint=""

if [[ "$#" -gt 0 ]]; then
  explicit_target=1
  build_gateway=0
  build_sandbox=0
  needs_helm_upgrade=0

  for target in "$@"; do
    case "${target}" in
      gateway)
        build_gateway=1
        ;;
      sandbox)
        build_sandbox=1
        ;;
      chart|helm)
        needs_helm_upgrade=1
        ;;
      all)
        build_gateway=1
        build_sandbox=1
        needs_helm_upgrade=1
        ;;
      *)
        echo "Unknown target '${target}'. Use gateway, sandbox, chart, or all."
        exit 1
        ;;
    esac
  done
fi

declare -a changed_files=()
detect_start=$(date +%s)
mapfile -t changed_files < <(
  {
    git diff --name-only
    git diff --name-only --cached
    git ls-files --others --exclude-standard
  } | sort -u
)
detect_end=$(date +%s)
log_duration "Change detection" "${detect_start}" "${detect_end}"

# Track the cluster container ID so we can detect when the cluster was
# recreated (e.g. via bootstrap).  A new container means the k3s state is
# fresh and all images must be rebuilt and pushed regardless of source
# fingerprints.
current_container_id=$(docker inspect --format '{{.Id}}' "${CONTAINER_NAME}" 2>/dev/null || true)

if [[ -f "${DEPLOY_FAST_STATE_FILE}" ]]; then
  while IFS='=' read -r key value; do
    case "${key}" in
      cluster_name)
        previous_cluster_name=${value}
        ;;
      container_id)
        previous_container_id=${value}
        ;;
      gateway)
        previous_gateway_fingerprint=${value}
        ;;
      sandbox)
        previous_sandbox_fingerprint=${value}
        ;;
      helm)
        previous_helm_fingerprint=${value}
        ;;
    esac
  done < "${DEPLOY_FAST_STATE_FILE}"

  if [[ "${previous_cluster_name:-}" != "${CLUSTER_NAME}" ]]; then
    previous_gateway_fingerprint=""
    previous_sandbox_fingerprint=""
    previous_helm_fingerprint=""
  fi

  # Invalidate all previous fingerprints when the cluster container has
  # changed (recreated or replaced).  The new k3s instance has no pushed
  # images so everything must be rebuilt.
  if [[ -n "${current_container_id}" && "${current_container_id}" != "${previous_container_id:-}" ]]; then
    previous_gateway_fingerprint=""
    previous_sandbox_fingerprint=""
    previous_helm_fingerprint=""
  fi
fi

matches_gateway() {
  local path=$1
  case "${path}" in
    Cargo.toml|Cargo.lock|proto/*|deploy/docker/cross-build.sh)
      return 0
      ;;
    crates/navigator-core/*|crates/navigator-providers/*)
      return 0
      ;;
    crates/navigator-router/*)
      return 0
      ;;
    crates/navigator-server/*|deploy/docker/Dockerfile.gateway)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

matches_sandbox() {
  local path=$1
  case "${path}" in
    Cargo.toml|Cargo.lock|proto/*|deploy/docker/cross-build.sh)
      return 0
      ;;
    crates/navigator-core/*|crates/navigator-providers/*)
      return 0
      ;;
    crates/navigator-policy/*|crates/navigator-sandbox/*|deploy/docker/sandbox/*|python/*|pyproject.toml|uv.lock)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

matches_helm() {
  local path=$1
  case "${path}" in
    deploy/helm/openshell/*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

compute_fingerprint() {
  local component=$1
  local payload=""
  local path
  local digest

  # Include the committed state of relevant source paths via git tree
  # hashes.  This ensures that committed changes (e.g. after `git pull`
  # or amend) are detected even when there are no uncommitted edits.
  local committed_trees=""
  case "${component}" in
    gateway)
      committed_trees=$(git ls-tree HEAD Cargo.toml Cargo.lock proto/ deploy/docker/cross-build.sh crates/navigator-core/ crates/navigator-providers/ crates/navigator-router/ crates/navigator-server/ deploy/docker/Dockerfile.gateway 2>/dev/null || true)
      ;;
    sandbox)
      committed_trees=$(git ls-tree HEAD Cargo.toml Cargo.lock proto/ deploy/docker/cross-build.sh crates/navigator-core/ crates/navigator-policy/ crates/navigator-providers/ crates/navigator-sandbox/ deploy/docker/sandbox/ python/ pyproject.toml uv.lock 2>/dev/null || true)
      ;;
    helm)
      committed_trees=$(git ls-tree HEAD deploy/helm/openshell/ 2>/dev/null || true)
      ;;
  esac
  if [[ -n "${committed_trees}" ]]; then
    payload+="${committed_trees}"$'\n'
  fi

  # Layer uncommitted changes on top so dirty files trigger a rebuild too.
  for path in "${changed_files[@]}"; do
    case "${component}" in
      gateway)
        if ! matches_gateway "${path}"; then
          continue
        fi
        ;;
      sandbox)
        if ! matches_sandbox "${path}"; then
          continue
        fi
        ;;
      helm)
        if ! matches_helm "${path}"; then
          continue
        fi
        ;;
    esac

    if [[ -e "${path}" ]]; then
      digest=$(shasum -a 256 "${path}" | cut -d ' ' -f 1)
    else
      digest="__MISSING__"
    fi
    payload+="${path}:${digest}"$'\n'
  done

  if [[ -z "${payload}" ]]; then
    printf ''
  else
    printf '%s' "${payload}" | shasum -a 256 | cut -d ' ' -f 1
  fi
}

current_gateway_fingerprint=$(compute_fingerprint gateway)
current_sandbox_fingerprint=$(compute_fingerprint sandbox)
current_helm_fingerprint=$(compute_fingerprint helm)

if [[ "${explicit_target}" == "0" && "${DEPLOY_FAST_MODE}" == "full" ]]; then
  build_gateway=1
  build_sandbox=1
  needs_helm_upgrade=1
elif [[ "${explicit_target}" == "0" ]]; then
  if [[ "${current_gateway_fingerprint}" != "${previous_gateway_fingerprint}" ]]; then
    build_gateway=1
  fi
  if [[ "${current_sandbox_fingerprint}" != "${previous_sandbox_fingerprint}" ]]; then
    build_sandbox=1
  fi
  if [[ "${current_helm_fingerprint}" != "${previous_helm_fingerprint}" ]]; then
    needs_helm_upgrade=1
  fi
fi

if [[ "${FORCE_HELM_UPGRADE}" == "1" ]]; then
  needs_helm_upgrade=1
fi

# Always run helm upgrade when images are rebuilt so that the
# OPENSHELL_SANDBOX_IMAGE env var on the server pod is set correctly
# and image pull policy is Always (not IfNotPresent from bootstrap).
if [[ "${build_gateway}" == "1" || "${build_sandbox}" == "1" ]]; then
  needs_helm_upgrade=1
fi

echo "Fast deploy plan:"
echo "  build gateway: ${build_gateway}"
echo "  build sandbox: ${build_sandbox}"
echo "  helm upgrade:  ${needs_helm_upgrade}"

if [[ "${explicit_target}" == "0" && "${build_gateway}" == "0" && "${build_sandbox}" == "0" && "${needs_helm_upgrade}" == "0" && "${DEPLOY_FAST_MODE}" != "full" ]]; then
  echo "No new local changes since last deploy."
fi

build_start=$(date +%s)

# Track which components are being rebuilt so we can evict their images
# from the k3s containerd cache after pushing.
declare -a built_components=()

gateway_pid=""
sandbox_pid=""
build_failed=0

if [[ "${build_gateway}" == "1" ]]; then
  if [[ "${build_sandbox}" == "1" ]]; then
    tasks/scripts/docker-build-component.sh gateway &
    gateway_pid=$!
  else
    tasks/scripts/docker-build-component.sh gateway
  fi
fi

if [[ "${build_sandbox}" == "1" ]]; then
  if [[ -n "${gateway_pid}" ]]; then
    tasks/scripts/docker-build-component.sh sandbox --build-arg RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE} &
    sandbox_pid=$!
  else
    tasks/scripts/docker-build-component.sh sandbox --build-arg RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}
  fi
fi

# Wait for parallel builds and fail fast: if either build fails, kill the
# other one immediately instead of letting it run to completion.
if [[ -n "${gateway_pid}" && -n "${sandbox_pid}" ]]; then
  # Both running in parallel — wait for either to finish first.
  if ! wait -n "${gateway_pid}" "${sandbox_pid}" 2>/dev/null; then
    build_failed=1
  fi
  # Whichever finished, wait for the other (or kill it on failure).
  if [[ "${build_failed}" == "1" ]]; then
    echo "Error: a parallel image build failed. Killing remaining build..." >&2
    kill "${gateway_pid}" "${sandbox_pid}" 2>/dev/null || true
    wait "${gateway_pid}" "${sandbox_pid}" 2>/dev/null || true
    exit 1
  fi
  # First build succeeded; wait for the second.
  if ! wait -n "${gateway_pid}" "${sandbox_pid}" 2>/dev/null; then
    echo "Error: a parallel image build failed." >&2
    exit 1
  fi
elif [[ -n "${gateway_pid}" ]]; then
  wait "${gateway_pid}"
elif [[ -n "${sandbox_pid}" ]]; then
  wait "${sandbox_pid}"
fi

build_end=$(date +%s)
log_duration "Image builds" "${build_start}" "${build_end}"

declare -a pushed_images=()

for component in gateway sandbox; do
  var="build_${component//-/_}"
  if [[ "${!var}" == "1" ]]; then
    # Tag may fail with AlreadyExists when the image digest hasn't changed;
    # this is harmless — the registry already has the correct image.
    docker tag "openshell/${component}:${IMAGE_TAG}" "${IMAGE_REPO_BASE}/${component}:${IMAGE_TAG}" 2>/dev/null || true
    pushed_images+=("${IMAGE_REPO_BASE}/${component}:${IMAGE_TAG}")
    built_components+=("${component}")
  fi
done

if [[ "${#pushed_images[@]}" -gt 0 ]]; then
  push_start=$(date +%s)
  echo "Pushing updated images to local registry..."
  for image_ref in "${pushed_images[@]}"; do
    docker push "${image_ref}"
  done
  push_end=$(date +%s)
  log_duration "Image push" "${push_start}" "${push_end}"
fi

# Always evict rebuilt images from k3s's containerd store so new pods pull
# the updated image from the registry.  Without this, k3s may use a cached
# copy even when the registry has a newer version with the same tag.
if [[ "${#built_components[@]}" -gt 0 ]]; then
  echo "Evicting stale images from k3s: ${built_components[*]}"
  for component in "${built_components[@]}"; do
    docker exec "${CONTAINER_NAME}" crictl rmi "${IMAGE_REPO_BASE}/${component}:${IMAGE_TAG}" >/dev/null 2>&1 || true
  done
fi

if [[ "${needs_helm_upgrade}" == "1" ]]; then
  helm_start=$(date +%s)
  echo "Upgrading helm release..."
  helm_wait_args=()
  if [[ "${DEPLOY_FAST_HELM_WAIT}" == "1" ]]; then
    helm_wait_args+=(--wait)
  fi

  # grpcEndpoint must be explicitly set to https:// because the chart always
  # terminates mTLS (there is no server.tls.enabled toggle). Without this,
  # a prior Helm override or chart default change could silently regress
  # sandbox callbacks to plaintext.
  # Retrieve the existing handshake secret from the running release, or generate
  # a new one if this is the first deploy with the mandatory secret.
  EXISTING_SECRET=$(helm get values openshell -n openshell -o json 2>/dev/null \
    | grep -o '"sshHandshakeSecret":"[^"]*"' \
    | cut -d'"' -f4) || true
  SSH_HANDSHAKE_SECRET="${EXISTING_SECRET:-$(openssl rand -hex 32)}"

  helm upgrade openshell deploy/helm/openshell \
    --namespace openshell \
    --set image.repository=${IMAGE_REPO_BASE}/gateway \
    --set image.tag=${IMAGE_TAG} \
    --set image.pullPolicy=Always \
    --set-string server.grpcEndpoint=https://openshell.openshell.svc.cluster.local:8080 \
    --set server.sandboxImage=${IMAGE_REPO_BASE}/sandbox:${IMAGE_TAG} \
    --set server.tls.certSecretName=openshell-server-tls \
    --set server.tls.clientCaSecretName=openshell-server-client-ca \
    --set server.tls.clientTlsSecretName=openshell-client-tls \
    --set server.sshHandshakeSecret=${SSH_HANDSHAKE_SECRET} \
    "${helm_wait_args[@]}"
  helm_end=$(date +%s)
  log_duration "Helm upgrade" "${helm_start}" "${helm_end}"
fi

if [[ "${#pushed_images[@]}" -gt 0 ]]; then
  rollout_start=$(date +%s)
  echo "Restarting deployment to pick up updated images..."
  if kubectl get statefulset/openshell -n openshell >/dev/null 2>&1; then
    kubectl rollout restart statefulset/openshell -n openshell
    kubectl rollout status statefulset/openshell -n openshell
  elif kubectl get deployment/openshell -n openshell >/dev/null 2>&1; then
    kubectl rollout restart deployment/openshell -n openshell
    kubectl rollout status deployment/openshell -n openshell
  else
    echo "Warning: no openshell workload found to roll out in namespace 'openshell'."
  fi
  rollout_end=$(date +%s)
  log_duration "Rollout" "${rollout_start}" "${rollout_end}"
else
  echo "No image updates to roll out."
fi

if [[ "${explicit_target}" == "0" ]]; then
  mkdir -p "$(dirname "${DEPLOY_FAST_STATE_FILE}")"
  cat > "${DEPLOY_FAST_STATE_FILE}" <<EOF
cluster_name=${CLUSTER_NAME}
container_id=${current_container_id}
gateway=${current_gateway_fingerprint}
sandbox=${current_sandbox_fingerprint}
helm=${current_helm_fingerprint}
EOF
fi

overall_end=$(date +%s)
log_duration "Total deploy" "${overall_start}" "${overall_end}"

echo "Deploy complete!"
