#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME=${CLUSTER_NAME:-$(basename "$PWD")}
CONTAINER_NAME="navigator-cluster-${CLUSTER_NAME}"
IMAGE_REPO_BASE=${IMAGE_REPO_BASE:-${NAVIGATOR_REGISTRY:-localhost:5000/navigator}}
IMAGE_TAG=${IMAGE_TAG:-dev}
RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE:-debug}
DEPLOY_FAST_MODE=${DEPLOY_FAST_MODE:-auto}
FORCE_HELM_UPGRADE=${FORCE_HELM_UPGRADE:-0}
DEPLOY_FAST_HELM_WAIT=${DEPLOY_FAST_HELM_WAIT:-0}

overall_start=$(date +%s)

log_duration() {
  local label=$1
  local start=$2
  local end=$3
  echo "${label} took $((end - start))s"
}

if ! docker ps -q --filter "name=${CONTAINER_NAME}" | grep -q .; then
  echo "Error: Cluster container '${CONTAINER_NAME}' is not running."
  echo "Start the cluster first with: mise run cluster"
  exit 1
fi

build_server=0
build_sandbox=0
build_pki_job=0
needs_helm_upgrade=0
explicit_target=0

if [[ "$#" -gt 0 ]]; then
  explicit_target=1
  build_server=0
  build_sandbox=0
  build_pki_job=0
  needs_helm_upgrade=0

  for target in "$@"; do
    case "${target}" in
      server)
        build_server=1
        ;;
      sandbox)
        build_sandbox=1
        ;;
      pki-job)
        build_pki_job=1
        ;;
      chart|helm)
        needs_helm_upgrade=1
        ;;
      all)
        build_server=1
        build_sandbox=1
        build_pki_job=1
        needs_helm_upgrade=1
        ;;
      *)
        echo "Unknown target '${target}'. Use server, sandbox, pki-job, chart, or all."
        exit 1
        ;;
    esac
  done
fi

declare -a changed_files=()
if [[ "${explicit_target}" == "0" ]]; then
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
fi

if [[ "${explicit_target}" == "0" && "${DEPLOY_FAST_MODE}" == "full" ]]; then
  build_server=1
  build_sandbox=1
  build_pki_job=1
  needs_helm_upgrade=1
elif [[ "${explicit_target}" == "0" ]]; then
  for path in "${changed_files[@]}"; do
    case "${path}" in
      Cargo.toml|Cargo.lock|proto/*|deploy/docker/cross-build.sh)
        build_server=1
        build_sandbox=1
        ;;
      crates/navigator-core/*|crates/navigator-providers/*)
        build_server=1
        build_sandbox=1
        ;;
      crates/navigator-router/*)
        build_server=1
        ;;
      crates/navigator-server/*|deploy/docker/Dockerfile.server)
        build_server=1
        ;;
      crates/navigator-sandbox/*|deploy/docker/Dockerfile.sandbox|python/*|pyproject.toml|uv.lock|dev-sandbox-policy.rego)
        build_sandbox=1
        ;;
      deploy/docker/Dockerfile.pki-job)
        build_pki_job=1
        ;;
      deploy/helm/navigator/*)
        needs_helm_upgrade=1
        ;;
    esac
  done
fi

if [[ "${FORCE_HELM_UPGRADE}" == "1" ]]; then
  needs_helm_upgrade=1
fi

echo "Fast deploy plan:"
echo "  build server:  ${build_server}"
echo "  build sandbox: ${build_sandbox}"
echo "  build pki-job: ${build_pki_job}"
echo "  helm upgrade:  ${needs_helm_upgrade}"

if [[ "${explicit_target}" == "0" && "${#changed_files[@]}" -eq 0 && "${DEPLOY_FAST_MODE}" != "full" ]]; then
  echo "No local changes detected."
fi

build_start=$(date +%s)

# Capture the sandbox image ID before rebuild so we can detect if it changed.
sandbox_image_id_before=""
if [[ "${build_sandbox}" == "1" ]]; then
  sandbox_image_id_before=$(docker images -q "navigator-sandbox:${IMAGE_TAG}" 2>/dev/null || true)
fi

server_pid=""
sandbox_pid=""

if [[ "${build_server}" == "1" ]]; then
  if [[ "${build_sandbox}" == "1" ]]; then
    build/scripts/docker-build-component.sh server &
    server_pid=$!
  else
    build/scripts/docker-build-component.sh server
  fi
fi

if [[ "${build_sandbox}" == "1" ]]; then
  if [[ -n "${server_pid}" ]]; then
    build/scripts/docker-build-component.sh sandbox --build-arg RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE} &
    sandbox_pid=$!
  else
    build/scripts/docker-build-component.sh sandbox --build-arg RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}
  fi
fi

if [[ -n "${server_pid}" ]]; then
  wait "${server_pid}"
fi

if [[ -n "${sandbox_pid}" ]]; then
  wait "${sandbox_pid}"
fi

if [[ "${build_pki_job}" == "1" ]]; then
  build/scripts/docker-build-component.sh pki-job
fi

build_end=$(date +%s)
log_duration "Image builds" "${build_start}" "${build_end}"

declare -a pushed_images=()

# Detect whether the sandbox image actually changed by comparing the Docker
# image ID before and after the build.  This is a content-addressable hash so
# identical builds produce the same ID regardless of registry digest quirks.
sandbox_image_changed=0
if [[ "${build_sandbox}" == "1" ]]; then
  sandbox_image_id_after=$(docker images -q "navigator-sandbox:${IMAGE_TAG}" 2>/dev/null || true)
  if [[ -n "${sandbox_image_id_before}" && -n "${sandbox_image_id_after}" \
        && "${sandbox_image_id_before}" != "${sandbox_image_id_after}" ]]; then
    sandbox_image_changed=1
  elif [[ -z "${sandbox_image_id_before}" && -n "${sandbox_image_id_after}" ]]; then
    # First build — treat as changed
    sandbox_image_changed=1
  fi
fi

if [[ "${build_server}" == "1" ]]; then
  docker tag "navigator-server:${IMAGE_TAG}" "${IMAGE_REPO_BASE}/server:${IMAGE_TAG}"
  pushed_images+=("${IMAGE_REPO_BASE}/server:${IMAGE_TAG}")
fi

if [[ "${build_sandbox}" == "1" ]]; then
  docker tag "navigator-sandbox:${IMAGE_TAG}" "${IMAGE_REPO_BASE}/sandbox:${IMAGE_TAG}"
  pushed_images+=("${IMAGE_REPO_BASE}/sandbox:${IMAGE_TAG}")
fi

if [[ "${build_pki_job}" == "1" ]]; then
  docker tag "navigator-pki-job:${IMAGE_TAG}" "${IMAGE_REPO_BASE}/pki-job:${IMAGE_TAG}"
  pushed_images+=("${IMAGE_REPO_BASE}/pki-job:${IMAGE_TAG}")
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

# If the sandbox image changed, evict the stale copy from k3s's containerd
# store so new sandbox pods pull the updated image from the registry.
# Without this, k3s uses its cached copy (imagePullPolicy defaults to
# IfNotPresent for non-:latest tags) and sandbox pods run stale code.
if [[ "${sandbox_image_changed}" == "1" ]]; then
  echo "Sandbox image changed (${sandbox_image_id_before:-<none>} -> ${sandbox_image_id_after}), evicting stale image from k3s..."
  docker exec "${CONTAINER_NAME}" crictl rmi "${IMAGE_REPO_BASE}/sandbox:${IMAGE_TAG}" >/dev/null 2>&1 || true
fi

if [[ "${needs_helm_upgrade}" == "1" ]]; then
  helm_start=$(date +%s)
  echo "Upgrading helm release..."
  helm_wait_args=()
  if [[ "${DEPLOY_FAST_HELM_WAIT}" == "1" ]]; then
    helm_wait_args+=(--wait)
  fi

  helm upgrade navigator deploy/helm/navigator \
    --namespace navigator \
    --set image.repository=${IMAGE_REPO_BASE}/server \
    --set image.tag=${IMAGE_TAG} \
    --set image.pullPolicy=Always \
    --set server.sandboxImage=${IMAGE_REPO_BASE}/sandbox:${IMAGE_TAG} \
    --set gateway.tls.enabled=true \
    --set gateway.tls.listenerPort=443 \
    --set gateway.tls.jobImage=${IMAGE_REPO_BASE}/pki-job:${IMAGE_TAG} \
    "${helm_wait_args[@]}"
  helm_end=$(date +%s)
  log_duration "Helm upgrade" "${helm_start}" "${helm_end}"
fi

if [[ "${#pushed_images[@]}" -gt 0 ]]; then
  rollout_start=$(date +%s)
  echo "Restarting deployment to pick up updated images..."
  if kubectl get statefulset/navigator -n navigator >/dev/null 2>&1; then
    kubectl rollout restart statefulset/navigator -n navigator
    kubectl rollout status statefulset/navigator -n navigator
  elif kubectl get deployment/navigator -n navigator >/dev/null 2>&1; then
    kubectl rollout restart deployment/navigator -n navigator
    kubectl rollout status deployment/navigator -n navigator
  else
    echo "Warning: no navigator workload found to roll out in namespace 'navigator'."
  fi
  rollout_end=$(date +%s)
  log_duration "Rollout" "${rollout_start}" "${rollout_end}"
else
  echo "No image updates to roll out."
fi

overall_end=$(date +%s)
log_duration "Total deploy" "${overall_start}" "${overall_end}"

echo "Deploy complete!"
