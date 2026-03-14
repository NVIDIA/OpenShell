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

# Run a command inside the cluster container with KUBECONFIG pre-configured.
cluster_exec() {
  docker exec "${CONTAINER_NAME}" sh -c "KUBECONFIG=/etc/rancher/k3s/k3s.yaml $*"
}

# Path inside the container where the chart is copied for helm upgrades.
CONTAINER_CHART_DIR=/tmp/openshell-chart

build_gateway=0
build_supervisor=0
needs_helm_upgrade=0
explicit_target=0

previous_gateway_fingerprint=""
previous_supervisor_fingerprint=""
previous_helm_fingerprint=""
current_gateway_fingerprint=""
current_supervisor_fingerprint=""
current_helm_fingerprint=""

if [[ "$#" -gt 0 ]]; then
  explicit_target=1
  build_gateway=0
  build_supervisor=0
  needs_helm_upgrade=0

  for target in "$@"; do
    case "${target}" in
      gateway)
        build_gateway=1
        ;;
      supervisor|sandbox)
        build_supervisor=1
        ;;
      chart|helm)
        needs_helm_upgrade=1
        ;;
      all)
        build_gateway=1
        build_supervisor=1
        needs_helm_upgrade=1
        ;;
      *)
        echo "Unknown target '${target}'. Use gateway, supervisor, chart, or all."
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
      supervisor)
        previous_supervisor_fingerprint=${value}
        ;;
      helm)
        previous_helm_fingerprint=${value}
        ;;
    esac
  done < "${DEPLOY_FAST_STATE_FILE}"

  if [[ "${previous_cluster_name:-}" != "${CLUSTER_NAME}" ]]; then
    previous_gateway_fingerprint=""
    previous_supervisor_fingerprint=""
    previous_helm_fingerprint=""
  fi

  # Invalidate gateway and helm fingerprints when the cluster container has
  # changed (recreated or replaced).  The new k3s instance has no pushed
  # images so the gateway must be rebuilt and helm must be re-applied.
  # The supervisor is NOT invalidated here because it is already built into
  # the cluster image — a fresh cluster already has the correct supervisor
  # binary, so rebuilding it would be redundant.
  if [[ -n "${current_container_id}" && "${current_container_id}" != "${previous_container_id:-}" ]]; then
    previous_gateway_fingerprint=""
    previous_helm_fingerprint=""
  fi
fi

matches_gateway() {
  local path=$1
  case "${path}" in
    Cargo.toml|Cargo.lock|proto/*|deploy/docker/cross-build.sh)
      return 0
      ;;
    crates/openshell-core/*|crates/openshell-providers/*)
      return 0
      ;;
    crates/openshell-router/*)
      return 0
      ;;
    crates/openshell-server/*|deploy/docker/Dockerfile.gateway)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

matches_supervisor() {
  local path=$1
  case "${path}" in
    Cargo.toml|Cargo.lock|proto/*|deploy/docker/cross-build.sh)
      return 0
      ;;
    crates/openshell-core/*|crates/openshell-policy/*|crates/openshell-router/*)
      return 0
      ;;
    crates/openshell-sandbox/*)
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
      committed_trees=$(git ls-tree HEAD Cargo.toml Cargo.lock proto/ deploy/docker/cross-build.sh crates/openshell-core/ crates/openshell-providers/ crates/openshell-router/ crates/openshell-server/ deploy/docker/Dockerfile.gateway 2>/dev/null || true)
      ;;
    supervisor)
      committed_trees=$(git ls-tree HEAD Cargo.toml Cargo.lock proto/ deploy/docker/cross-build.sh crates/openshell-core/ crates/openshell-policy/ crates/openshell-router/ crates/openshell-sandbox/ 2>/dev/null || true)
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
      supervisor)
        if ! matches_supervisor "${path}"; then
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
current_supervisor_fingerprint=$(compute_fingerprint supervisor)
current_helm_fingerprint=$(compute_fingerprint helm)

if [[ "${explicit_target}" == "0" && "${DEPLOY_FAST_MODE}" == "full" ]]; then
  build_gateway=1
  build_supervisor=1
  needs_helm_upgrade=1
elif [[ "${explicit_target}" == "0" ]]; then
  if [[ "${current_gateway_fingerprint}" != "${previous_gateway_fingerprint}" ]]; then
    build_gateway=1
  fi
  if [[ "${current_supervisor_fingerprint}" != "${previous_supervisor_fingerprint}" ]]; then
    build_supervisor=1
  fi
  if [[ "${current_helm_fingerprint}" != "${previous_helm_fingerprint}" ]]; then
    needs_helm_upgrade=1
  fi
fi

if [[ "${FORCE_HELM_UPGRADE}" == "1" ]]; then
  needs_helm_upgrade=1
fi

# Always run helm upgrade when the gateway image is rebuilt so that
# the image tag and pull policy are set correctly.
if [[ "${build_gateway}" == "1" ]]; then
  needs_helm_upgrade=1
fi

echo "Fast deploy plan:"
echo "  build gateway:    ${build_gateway}"
echo "  build supervisor: ${build_supervisor}"
echo "  helm upgrade:     ${needs_helm_upgrade}"

if [[ "${explicit_target}" == "0" && "${build_gateway}" == "0" && "${build_supervisor}" == "0" && "${needs_helm_upgrade}" == "0" && "${DEPLOY_FAST_MODE}" != "full" ]]; then
  echo "No new local changes since last deploy."
fi

build_start=$(date +%s)

# Track which components are being rebuilt for rollout decisions.
declare -a built_components=()

if [[ "${build_gateway}" == "1" ]]; then
  tasks/scripts/docker-build-component.sh gateway
fi

# Build the supervisor binary and docker cp it into the running k3s cluster.
# The binary lives at /opt/openshell/bin/openshell-sandbox on the node
# filesystem and is mounted into sandbox pods via a hostPath volume.
if [[ "${build_supervisor}" == "1" ]]; then
  echo "Building supervisor binary..."
  supervisor_start=$(date +%s)

  # Detect the cluster container's architecture so we cross-compile correctly.
  # Container objects lack an Architecture field (the Go template emits a
  # stray newline before erroring), so inspect the container's *image* instead.
  _cluster_image=$(docker inspect --format '{{.Config.Image}}' "${CONTAINER_NAME}" 2>/dev/null)
  CLUSTER_ARCH=$(docker image inspect --format '{{.Architecture}}' "${_cluster_image}" 2>/dev/null || echo "amd64")

  # Build the supervisor binary using docker buildx with a lightweight build.
  # We use the same cross-build.sh helpers as the full cluster image but only
  # compile openshell-sandbox, then extract the binary via --output.
  SUPERVISOR_BUILD_DIR=$(mktemp -d)
  trap 'rm -rf "${SUPERVISOR_BUILD_DIR}"' EXIT

  # Compute cargo version from git tags for the supervisor binary.
  SUPERVISOR_VERSION_ARGS=()
  if [[ -n "${OPENSHELL_CARGO_VERSION:-}" ]]; then
    SUPERVISOR_VERSION_ARGS=(--build-arg "OPENSHELL_CARGO_VERSION=${OPENSHELL_CARGO_VERSION}")
  else
    _cargo_version=$(uv run python tasks/scripts/release.py get-version --cargo 2>/dev/null || true)
    if [[ -n "${_cargo_version}" ]]; then
      SUPERVISOR_VERSION_ARGS=(--build-arg "OPENSHELL_CARGO_VERSION=${_cargo_version}")
    fi
  fi

  docker buildx build \
    --file deploy/docker/Dockerfile.cluster \
    --target supervisor-builder \
    --build-arg "BUILDARCH=$(docker version --format '{{.Server.Arch}}')" \
    --build-arg "TARGETARCH=${CLUSTER_ARCH}" \
    ${SUPERVISOR_VERSION_ARGS[@]+"${SUPERVISOR_VERSION_ARGS[@]}"} \
    --output "type=local,dest=${SUPERVISOR_BUILD_DIR}" \
    --platform "linux/${CLUSTER_ARCH}" \
    .

  # Copy the built binary into the running k3s container
  docker exec "${CONTAINER_NAME}" mkdir -p /opt/openshell/bin
  docker cp "${SUPERVISOR_BUILD_DIR}/build/out/openshell-sandbox" \
    "${CONTAINER_NAME}:/opt/openshell/bin/openshell-sandbox"
  docker exec "${CONTAINER_NAME}" chmod 755 /opt/openshell/bin/openshell-sandbox

  built_components+=("supervisor")
  supervisor_end=$(date +%s)
  log_duration "Supervisor build + deploy" "${supervisor_start}" "${supervisor_end}"
fi

build_end=$(date +%s)
log_duration "Builds" "${build_start}" "${build_end}"

# Push rebuilt gateway image to local registry.
declare -a pushed_images=()

if [[ "${build_gateway}" == "1" ]]; then
  docker tag "openshell/gateway:${IMAGE_TAG}" "${IMAGE_REPO_BASE}/gateway:${IMAGE_TAG}" 2>/dev/null || true
  pushed_images+=("${IMAGE_REPO_BASE}/gateway:${IMAGE_TAG}")
  built_components+=("gateway")
fi

if [[ "${#pushed_images[@]}" -gt 0 ]]; then
  push_start=$(date +%s)
  echo "Pushing updated images to local registry..."
  for image_ref in "${pushed_images[@]}"; do
    docker push "${image_ref}"
  done
  push_end=$(date +%s)
  log_duration "Image push" "${push_start}" "${push_end}"
fi

# Evict rebuilt gateway image from k3s containerd cache so new pods pull
# the updated image from the registry.
if [[ "${build_gateway}" == "1" ]]; then
  echo "Evicting stale gateway image from k3s..."
  docker exec "${CONTAINER_NAME}" crictl rmi "${IMAGE_REPO_BASE}/gateway:${IMAGE_TAG}" >/dev/null 2>&1 || true
fi

if [[ "${needs_helm_upgrade}" == "1" ]]; then
  helm_start=$(date +%s)
  echo "Upgrading helm release..."
  helm_wait_args=""
  if [[ "${DEPLOY_FAST_HELM_WAIT}" == "1" ]]; then
    helm_wait_args="--wait"
  fi

  # Copy the local chart source into the container so helm can read it.
  docker exec "${CONTAINER_NAME}" rm -rf "${CONTAINER_CHART_DIR}"
  docker cp deploy/helm/openshell "${CONTAINER_NAME}:${CONTAINER_CHART_DIR}"

  # grpcEndpoint must be explicitly set to https:// because the chart always
  # terminates mTLS (there is no server.tls.enabled toggle). Without this,
  # a prior Helm override or chart default change could silently regress
  # sandbox callbacks to plaintext.
  # Retrieve the existing handshake secret from the running release, or generate
  # a new one if this is the first deploy with the mandatory secret.
  EXISTING_SECRET=$(cluster_exec "helm get values openshell -n openshell -o json 2>/dev/null \
    | grep -o '\"sshHandshakeSecret\":\"[^\"]*\"' \
    | cut -d'\"' -f4") || true
  SSH_HANDSHAKE_SECRET="${EXISTING_SECRET:-$(openssl rand -hex 32)}"

  cluster_exec "helm upgrade openshell ${CONTAINER_CHART_DIR} \
    --namespace openshell \
    --set image.repository=${IMAGE_REPO_BASE}/gateway \
    --set image.tag=${IMAGE_TAG} \
    --set image.pullPolicy=Always \
    --set-string server.grpcEndpoint=https://openshell.openshell.svc.cluster.local:8080 \
    --set server.tls.certSecretName=openshell-server-tls \
    --set server.tls.clientCaSecretName=openshell-server-client-ca \
    --set server.tls.clientTlsSecretName=openshell-client-tls \
    --set server.sshHandshakeSecret=${SSH_HANDSHAKE_SECRET} \
    ${helm_wait_args}"
  helm_end=$(date +%s)
  log_duration "Helm upgrade" "${helm_start}" "${helm_end}"
fi

if [[ "${build_gateway}" == "1" ]]; then
  rollout_start=$(date +%s)
  echo "Restarting gateway to pick up updated image..."
  if cluster_exec "kubectl get statefulset/openshell -n openshell" >/dev/null 2>&1; then
    cluster_exec "kubectl rollout restart statefulset/openshell -n openshell"
    cluster_exec "kubectl rollout status statefulset/openshell -n openshell"
  elif cluster_exec "kubectl get deployment/openshell -n openshell" >/dev/null 2>&1; then
    cluster_exec "kubectl rollout restart deployment/openshell -n openshell"
    cluster_exec "kubectl rollout status deployment/openshell -n openshell"
  else
    echo "Warning: no openshell workload found to roll out in namespace 'openshell'."
  fi
  rollout_end=$(date +%s)
  log_duration "Gateway rollout" "${rollout_start}" "${rollout_end}"
fi

if [[ "${build_supervisor}" == "1" ]]; then
  echo "Supervisor binary updated on cluster node."
  echo "Existing sandbox pods will use the new binary on next restart."
  echo "New sandbox pods will use the updated binary immediately (hostPath mount)."
fi

if [[ "${explicit_target}" == "0" ]]; then
  mkdir -p "$(dirname "${DEPLOY_FAST_STATE_FILE}")"
  cat > "${DEPLOY_FAST_STATE_FILE}" <<EOF
cluster_name=${CLUSTER_NAME}
container_id=${current_container_id}
gateway=${current_gateway_fingerprint}
supervisor=${current_supervisor_fingerprint}
helm=${current_helm_fingerprint}
EOF
fi

overall_end=$(date +%s)
log_duration "Total deploy" "${overall_start}" "${overall_end}"

echo "Deploy complete!"
