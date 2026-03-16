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
CARGO_BUILD_PROFILE=${OPENSHELL_CARGO_PROFILE:-}
if [[ -z "${CARGO_BUILD_PROFILE}" ]]; then
  if [[ -n "${CI:-}" ]]; then
    CARGO_BUILD_PROFILE="release"
  else
    CARGO_BUILD_PROFILE=${RUST_BUILD_PROFILE:-local-fast}
  fi
fi
DEPLOY_FAST_MODE=${DEPLOY_FAST_MODE:-auto}
FORCE_HELM_UPGRADE=${FORCE_HELM_UPGRADE:-0}
DEPLOY_FAST_HELM_WAIT=${DEPLOY_FAST_HELM_WAIT:-0}
DEPLOY_FAST_READINESS_TIMEOUT_SECONDS=${DEPLOY_FAST_READINESS_TIMEOUT_SECONDS:-90}
DEPLOY_FAST_READINESS_POLL_SECONDS=${DEPLOY_FAST_READINESS_POLL_SECONDS:-2}
DEPLOY_FAST_SUPERVISOR_RECONCILE=${DEPLOY_FAST_SUPERVISOR_RECONCILE:-rolling-delete}
DEPLOY_FAST_SUPERVISOR_RECONCILE_TIMEOUT_SECONDS=${DEPLOY_FAST_SUPERVISOR_RECONCILE_TIMEOUT_SECONDS:-90}
DEPLOY_FAST_STATE_FILE=${DEPLOY_FAST_STATE_FILE:-.cache/cluster-deploy-fast.state}
DEPLOY_TX_ID=${DEPLOY_TX_ID:-"tx-$(date +%Y%m%d-%H%M%S)-$RANDOM"}
DEPLOY_REPORT_DIR=${DEPLOY_REPORT_DIR:-.cache/deploy-reports}
DEPLOY_REPORT_FILE="${DEPLOY_REPORT_DIR}/${DEPLOY_TX_ID}.md"

overall_start=$(date +%s)

log_duration() {
  local label=$1
  local start=$2
  local end=$3
  echo "${label} took $((end - start))s"
}

sha256_16() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print substr($1, 1, 16)}'
  else
    shasum -a 256 "$1" | awk '{print substr($1, 1, 16)}'
  fi
}

sha256_16_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print substr($1, 1, 16)}'
  else
    shasum -a 256 | awk '{print substr($1, 1, 16)}'
  fi
}

detect_rust_scope() {
  local dockerfile=$1
  local rust_from
  rust_from=$(grep -E '^FROM --platform=\$BUILDPLATFORM rust:[^ ]+' "$dockerfile" | head -n1 | sed -E 's/^FROM --platform=\$BUILDPLATFORM rust:([^ ]+).*/\1/' || true)
  if [[ -n "${rust_from}" ]]; then
    echo "rust-${rust_from}"
    return
  fi

  if grep -q "rustup.rs" "$dockerfile"; then
    echo "rustup-stable"
    return
  fi

  echo "no-rust"
}

change_detection_duration=0
builds_duration=0
supervisor_duration=0
image_push_duration=0
helm_upgrade_duration=0
gateway_rollout_duration=0
supervisor_reconcile_duration=0
readiness_duration=0
total_duration=0
gateway_deployed_digest=""
gateway_target_digest=""
skip_gateway_reconcile=0
skip_gateway_reconcile_reason=""
readiness_gate_status="pending"
readiness_failure_reason=""
supervisor_reconcile_performed=0
supervisor_reconcile_restarted_pods=0
supervisor_reconcile_waits=0
supervisor_reconcile_expected_running=0
supervisor_reconcile_failure_reason=""

state_gateway_fingerprint=""
state_supervisor_fingerprint=""
state_helm_fingerprint=""

mkdir -p "${DEPLOY_REPORT_DIR}"

case "${DEPLOY_FAST_SUPERVISOR_RECONCILE}" in
  rolling-delete|none)
    ;;
  *)
    echo "Error: DEPLOY_FAST_SUPERVISOR_RECONCILE must be 'rolling-delete' or 'none' (got '${DEPLOY_FAST_SUPERVISOR_RECONCILE}')."
    exit 1
    ;;
esac

if ! docker ps -q --filter "name=^${CONTAINER_NAME}$" --filter "health=healthy" | grep -q .; then
  echo "Error: Cluster container '${CONTAINER_NAME}' is not running or not healthy."
  echo "Start the cluster first with: mise run cluster"
  exit 1
fi

# Run a command inside the cluster container with KUBECONFIG pre-configured.
cluster_exec() {
  docker exec "${CONTAINER_NAME}" sh -c "KUBECONFIG=/etc/rancher/k3s/k3s.yaml $*"
}

gateway_workload_kind() {
  if cluster_exec "kubectl get statefulset/openshell -n openshell" >/dev/null 2>&1; then
    echo "statefulset"
    return
  fi
  if cluster_exec "kubectl get deployment/openshell -n openshell" >/dev/null 2>&1; then
    echo "deployment"
    return
  fi
  echo ""
}

wait_for_gateway_ready() {
  local timeout_s=${1:-90}
  local poll_s=${2:-2}
  local deadline
  local workload_kind
  local desired_replicas
  local ready_replicas
  local reason="unknown"

  deadline=$(( $(date +%s) + timeout_s ))

  while true; do
    if ! cluster_exec "kubectl get --raw='/readyz'" >/dev/null 2>&1; then
      reason="apiserver_not_ready"
    elif ! docker exec "${CONTAINER_NAME}" test -x /opt/openshell/bin/openshell-sandbox >/dev/null 2>&1; then
      reason="supervisor_binary_missing"
    else
      workload_kind=$(gateway_workload_kind)
      if [[ -z "${workload_kind}" ]]; then
        reason="gateway_workload_missing"
      else
        desired_replicas=$(cluster_exec "kubectl get ${workload_kind}/openshell -n openshell -o jsonpath='{.spec.replicas}'" 2>/dev/null || true)
        ready_replicas=$(cluster_exec "kubectl get ${workload_kind}/openshell -n openshell -o jsonpath='{.status.readyReplicas}'" 2>/dev/null || true)
        if [[ -z "${desired_replicas}" ]]; then
          desired_replicas=1
        fi
        if [[ -z "${ready_replicas}" ]]; then
          ready_replicas=0
        fi
        if [[ "${ready_replicas}" -ge "${desired_replicas}" ]]; then
          return 0
        fi
        reason="gateway_not_ready:${ready_replicas}/${desired_replicas}"
      fi
    fi

    if [[ $(date +%s) -ge "${deadline}" ]]; then
      readiness_failure_reason="${reason}"
      return 1
    fi

    sleep "${poll_s}"
  done
}

list_running_sandbox_pods() {
  cluster_exec "kubectl get pods -n openshell -l 'openshell.ai/managed-by=openshell,openshell.ai/sandbox-id' --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.metadata.name}{\"\\n\"}{end}'" 2>/dev/null || true
}

count_running_sandbox_pods() {
  local markers
  markers=$(cluster_exec "kubectl get pods -n openshell -l 'openshell.ai/managed-by=openshell,openshell.ai/sandbox-id' --field-selector=status.phase=Running -o jsonpath='{range .items[*]}x{end}'" 2>/dev/null || true)
  if [[ -z "${markers}" ]]; then
    echo "0"
    return
  fi
  echo "${#markers}"
}

wait_for_running_sandboxes_ready() {
  local expected_count=$1
  local timeout_s=${2:-90}
  local poll_s=${3:-2}
  local deadline
  local running_count

  if [[ "${expected_count}" -le 0 ]]; then
    return 0
  fi

  deadline=$(( $(date +%s) + timeout_s ))

  while true; do
    running_count=$(count_running_sandbox_pods)
    if [[ "${running_count}" -ge "${expected_count}" ]]; then
      if cluster_exec "kubectl wait --for=condition=Ready pod -n openshell -l 'openshell.ai/managed-by=openshell,openshell.ai/sandbox-id' --field-selector=status.phase=Running --timeout=1s" >/dev/null 2>&1; then
        return 0
      fi
      supervisor_reconcile_failure_reason="sandbox_pods_not_ready"
    else
      supervisor_reconcile_failure_reason="sandbox_pod_count:${running_count}/${expected_count}"
    fi

    if [[ $(date +%s) -ge "${deadline}" ]]; then
      if [[ -z "${supervisor_reconcile_failure_reason}" ]]; then
        supervisor_reconcile_failure_reason="sandbox_reconcile_timeout"
      fi
      return 1
    fi

    sleep "${poll_s}"
  done
}

reconcile_supervisor_pods() {
  local mode=$1
  local timeout_s=$2
  local poll_s=$3
  local reconcile_start
  local reconcile_end
  local pod_name
  local -a sandbox_pods=()

  if [[ "${mode}" == "none" ]]; then
    echo "Supervisor reconcile mode is 'none'; skipping running sandbox pod restart."
    return 0
  fi

  while IFS= read -r pod_name; do
    if [[ -n "${pod_name}" ]]; then
      sandbox_pods+=("${pod_name}")
    fi
  done < <(list_running_sandbox_pods)

  supervisor_reconcile_expected_running=${#sandbox_pods[@]}
  if [[ "${supervisor_reconcile_expected_running}" -eq 0 ]]; then
    echo "No running sandbox pods found for supervisor reconcile."
    return 0
  fi

  supervisor_reconcile_performed=1
  reconcile_start=$(date +%s)
  echo "Reconciling ${supervisor_reconcile_expected_running} running sandbox pod(s) after supervisor update..."

  for pod_name in "${sandbox_pods[@]}"; do
    echo "Restarting sandbox pod ${pod_name}..."
    cluster_exec "kubectl delete pod ${pod_name} -n openshell --wait=true --timeout=${timeout_s}s" >/dev/null
    supervisor_reconcile_restarted_pods=$((supervisor_reconcile_restarted_pods + 1))

    if ! wait_for_running_sandboxes_ready "${supervisor_reconcile_expected_running}" "${timeout_s}" "${poll_s}"; then
      echo "Error: sandbox pod readiness did not recover after restarting ${pod_name} (${supervisor_reconcile_failure_reason})."
      return 1
    fi
    supervisor_reconcile_waits=$((supervisor_reconcile_waits + 1))
  done

  reconcile_end=$(date +%s)
  log_duration "Supervisor pod reconcile" "${reconcile_start}" "${reconcile_end}"
  supervisor_reconcile_duration=$((reconcile_end - reconcile_start))
  return 0
}

run_readiness_gate() {
  local gate_start
  local gate_end

  gate_start=$(date +%s)
  echo "Running readiness gate..."

  if ! wait_for_gateway_ready "${DEPLOY_FAST_READINESS_TIMEOUT_SECONDS}" "${DEPLOY_FAST_READINESS_POLL_SECONDS}"; then
    gate_end=$(date +%s)
    readiness_duration=$((gate_end - gate_start))
    readiness_gate_status="failed"
    if [[ -z "${readiness_failure_reason}" ]]; then
      readiness_failure_reason="unknown"
    fi
    echo "Error: readiness gate failed (${readiness_failure_reason})."
    cluster_exec "kubectl get pods -n openshell -o wide" || true
    return 1
  fi

  gate_end=$(date +%s)
  readiness_duration=$((gate_end - gate_start))
  readiness_gate_status="passed"
  echo "Readiness gate passed."
  return 0
}

# Best-effort: find the currently running gateway image digest from pod status.
get_deployed_gateway_digest() {
  local image_id

  while IFS= read -r image_id; do
    case "${image_id}" in
      *"${IMAGE_REPO_BASE}/gateway@"*)
        printf '%s\n' "${image_id##*@}"
        return 0
        ;;
    esac
  done < <(
    cluster_exec "kubectl get pods -n openshell -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.imageID}{\"\\n\"}{end}{end}'" 2>/dev/null || true
  )

  return 1
}

# Best-effort: resolve the pushed gateway tag to a digest from local docker metadata.
get_tagged_gateway_digest() {
  local repo_digest

  while IFS= read -r repo_digest; do
    case "${repo_digest}" in
      "${IMAGE_REPO_BASE}/gateway@"*)
        printf '%s\n' "${repo_digest##*@}"
        return 0
        ;;
    esac
  done < <(
    docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${IMAGE_REPO_BASE}/gateway:${IMAGE_TAG}" 2>/dev/null || true
  )

  return 1
}

# Path inside the container where the chart is copied for helm upgrades.
CONTAINER_CHART_DIR=/tmp/openshell-chart

build_gateway=0
build_supervisor=0
needs_helm_upgrade=0
explicit_target=0
targets_requested="${*:-auto}"
helm_requested_by_gateway_build=0

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
while IFS= read -r path; do
  changed_files+=("${path}")
done < <(
  {
    git diff --name-only
    git diff --name-only --cached
    git ls-files --others --exclude-standard
  } | sort -u
)
detect_end=$(date +%s)
log_duration "Change detection" "${detect_start}" "${detect_end}"
change_detection_duration=$((detect_end - detect_start))
changed_files_count=${#changed_files[@]}

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
if [[ "${build_gateway}" == "1" && "${needs_helm_upgrade}" == "0" ]]; then
  needs_helm_upgrade=1
  helm_requested_by_gateway_build=1
fi

echo "Fast deploy plan:"
echo "  build gateway:    ${build_gateway}"
echo "  build supervisor: ${build_supervisor}"
echo "  helm upgrade:     ${needs_helm_upgrade}"
echo "  cargo profile:    ${CARGO_BUILD_PROFILE}"
echo "  readiness timeout:${DEPLOY_FAST_READINESS_TIMEOUT_SECONDS}s"
echo "  supervisor reconcile: ${DEPLOY_FAST_SUPERVISOR_RECONCILE}"

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
  # Use the dedicated supervisor-export target to avoid copying the entire
  # builder filesystem (target cache) back to the host.
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

  SUPERVISOR_PROFILE_ARGS=(--build-arg "OPENSHELL_CARGO_PROFILE=${CARGO_BUILD_PROFILE}")
  SUPERVISOR_RUST_SCOPE=${RUST_TOOLCHAIN_SCOPE:-$(detect_rust_scope "deploy/docker/Dockerfile.cluster")}
  SUPERVISOR_LOCK_HASH=$(sha256_16 Cargo.lock)
  SUPERVISOR_SCOPE_INPUT="v2|cluster|base|${SUPERVISOR_LOCK_HASH}|${SUPERVISOR_RUST_SCOPE}|${CARGO_BUILD_PROFILE}"
  SUPERVISOR_CACHE_SCOPE=$(printf '%s' "${SUPERVISOR_SCOPE_INPUT}" | sha256_16_stdin)

  docker buildx build \
    --file deploy/docker/Dockerfile.cluster \
    --target supervisor-export \
    --build-arg "BUILDARCH=$(docker version --format '{{.Server.Arch}}')" \
    --build-arg "TARGETARCH=${CLUSTER_ARCH}" \
    --build-arg "CARGO_TARGET_CACHE_SCOPE=${SUPERVISOR_CACHE_SCOPE}" \
    ${SUPERVISOR_PROFILE_ARGS[@]+"${SUPERVISOR_PROFILE_ARGS[@]}"} \
    ${SUPERVISOR_VERSION_ARGS[@]+"${SUPERVISOR_VERSION_ARGS[@]}"} \
    --output "type=local,dest=${SUPERVISOR_BUILD_DIR}" \
    --platform "linux/${CLUSTER_ARCH}" \
    .

  # Copy the built binary into the running k3s container
  docker exec "${CONTAINER_NAME}" mkdir -p /opt/openshell/bin
  docker cp "${SUPERVISOR_BUILD_DIR}/openshell-sandbox" \
    "${CONTAINER_NAME}:/opt/openshell/bin/openshell-sandbox"
  docker exec "${CONTAINER_NAME}" chmod 755 /opt/openshell/bin/openshell-sandbox

  reconcile_supervisor_pods \
    "${DEPLOY_FAST_SUPERVISOR_RECONCILE}" \
    "${DEPLOY_FAST_SUPERVISOR_RECONCILE_TIMEOUT_SECONDS}" \
    "${DEPLOY_FAST_READINESS_POLL_SECONDS}"

  built_components+=("supervisor")
  supervisor_end=$(date +%s)
  log_duration "Supervisor build + deploy" "${supervisor_start}" "${supervisor_end}"
  supervisor_duration=$((supervisor_end - supervisor_start))
fi

build_end=$(date +%s)
log_duration "Builds" "${build_start}" "${build_end}"
builds_duration=$((build_end - build_start))

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
  image_push_duration=$((push_end - push_start))
fi

# If the pushed gateway digest is already running, skip gateway-only reconcile.
# This avoids unnecessary helm+rollout churn when an explicit gateway build
# produces the same digest.
if [[ "${build_gateway}" == "1" ]]; then
  gateway_deployed_digest=$(get_deployed_gateway_digest || true)
  gateway_target_digest=$(get_tagged_gateway_digest || true)

  if [[ -n "${gateway_target_digest}" && -n "${gateway_deployed_digest}" && "${gateway_target_digest}" == "${gateway_deployed_digest}" ]]; then
    skip_gateway_reconcile=1
    skip_gateway_reconcile_reason="digest_already_deployed"
    echo "Gateway digest ${gateway_target_digest} is already deployed."

    if [[ "${helm_requested_by_gateway_build}" == "1" && "${FORCE_HELM_UPGRADE}" != "1" ]]; then
      needs_helm_upgrade=0
      echo "Skipping helm upgrade (it was only requested for gateway image refresh)."
    fi
  fi
fi

# Evict rebuilt gateway image from k3s containerd cache so new pods pull
# the updated image from the registry.
if [[ "${build_gateway}" == "1" && "${skip_gateway_reconcile}" == "0" ]]; then
  echo "Evicting stale gateway image from k3s..."
  docker exec "${CONTAINER_NAME}" crictl rmi "${IMAGE_REPO_BASE}/gateway:${IMAGE_TAG}" >/dev/null 2>&1 || true
fi

if [[ "${needs_helm_upgrade}" == "1" ]]; then
  helm_start=$(date +%s)
  echo "Upgrading helm release..."
  helm_wait_args=""
  helm_timeout_args="--timeout ${DEPLOY_FAST_READINESS_TIMEOUT_SECONDS}s"
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

  # Retrieve the host gateway IP from the entrypoint-rendered HelmChart CR so
  # that hostAliases for host.openshell.internal are preserved across fast deploys.
  HOST_GATEWAY_IP=$(cluster_exec "kubectl -n kube-system get helmchart openshell -o jsonpath='{.spec.valuesContent}' 2>/dev/null \
    | grep hostGatewayIP | awk '{print \$2}'" 2>/dev/null) || true
  HOST_GATEWAY_ARGS=""
  if [[ -n "${HOST_GATEWAY_IP}" ]]; then
    HOST_GATEWAY_ARGS="--set server.hostGatewayIP=${HOST_GATEWAY_IP}"
  fi

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
    ${HOST_GATEWAY_ARGS} \
    ${helm_wait_args} \
    ${helm_timeout_args}"
  helm_end=$(date +%s)
  log_duration "Helm upgrade" "${helm_start}" "${helm_end}"
  helm_upgrade_duration=$((helm_end - helm_start))
fi

if [[ "${build_gateway}" == "1" && "${skip_gateway_reconcile}" == "0" ]]; then
  rollout_start=$(date +%s)
  echo "Restarting gateway to pick up updated image..."
  if cluster_exec "kubectl get statefulset/openshell -n openshell" >/dev/null 2>&1; then
    cluster_exec "kubectl rollout restart statefulset/openshell -n openshell"
    cluster_exec "kubectl rollout status statefulset/openshell -n openshell --timeout=${DEPLOY_FAST_READINESS_TIMEOUT_SECONDS}s"
  elif cluster_exec "kubectl get deployment/openshell -n openshell" >/dev/null 2>&1; then
    cluster_exec "kubectl rollout restart deployment/openshell -n openshell"
    cluster_exec "kubectl rollout status deployment/openshell -n openshell --timeout=${DEPLOY_FAST_READINESS_TIMEOUT_SECONDS}s"
  else
    echo "Warning: no openshell workload found to roll out in namespace 'openshell'."
  fi
  rollout_end=$(date +%s)
  log_duration "Gateway rollout" "${rollout_start}" "${rollout_end}"
  gateway_rollout_duration=$((rollout_end - rollout_start))
elif [[ "${build_gateway}" == "1" ]]; then
  echo "Skipping gateway rollout (digest unchanged)."
fi

if [[ "${build_supervisor}" == "1" ]]; then
  echo "Supervisor binary updated on cluster node."
  if [[ "${DEPLOY_FAST_SUPERVISOR_RECONCILE}" == "none" ]]; then
    echo "Running sandbox pods keep their current supervisor until they restart."
  elif [[ "${supervisor_reconcile_performed}" == "1" ]]; then
    echo "Reconciled ${supervisor_reconcile_restarted_pods} running sandbox pod(s) to pick up the new supervisor."
  else
    echo "No running sandbox pods required reconcile."
  fi
  echo "New sandbox pods use the updated binary immediately (hostPath mount)."
fi

run_readiness_gate

# Keep deploy state aligned even when explicit targets are used.
# For explicit runs, update only the components we actually reconciled so auto
# mode remains accurate for untouched components.
state_gateway_fingerprint="${current_gateway_fingerprint}"
state_supervisor_fingerprint="${current_supervisor_fingerprint}"
state_helm_fingerprint="${current_helm_fingerprint}"

if [[ "${explicit_target}" == "1" ]]; then
  state_gateway_fingerprint="${previous_gateway_fingerprint:-}"
  state_supervisor_fingerprint="${previous_supervisor_fingerprint:-}"
  state_helm_fingerprint="${previous_helm_fingerprint:-}"

  if [[ "${build_gateway}" == "1" ]]; then
    state_gateway_fingerprint="${current_gateway_fingerprint}"
  fi
  if [[ "${build_supervisor}" == "1" ]]; then
    state_supervisor_fingerprint="${current_supervisor_fingerprint}"
  fi
  if [[ "${needs_helm_upgrade}" == "1" ]]; then
    state_helm_fingerprint="${current_helm_fingerprint}"
  fi
fi

mkdir -p "$(dirname "${DEPLOY_FAST_STATE_FILE}")"
cat > "${DEPLOY_FAST_STATE_FILE}" <<EOF
cluster_name=${CLUSTER_NAME}
container_id=${current_container_id}
gateway=${state_gateway_fingerprint}
supervisor=${state_supervisor_fingerprint}
helm=${state_helm_fingerprint}
EOF

overall_end=$(date +%s)
log_duration "Total deploy" "${overall_start}" "${overall_end}"
total_duration=$((overall_end - overall_start))

cat > "${DEPLOY_REPORT_FILE}" <<EOF
# Cluster Deploy Report

- transaction_id: \`${DEPLOY_TX_ID}\`
- timestamp_utc: \`$(date -u +"%Y-%m-%dT%H:%M:%SZ")\`
- cluster_name: \`${CLUSTER_NAME}\`
- container_name: \`${CONTAINER_NAME}\`
- explicit_target: \`${explicit_target}\`
- targets_requested: \`${targets_requested}\`
- deploy_fast_mode: \`${DEPLOY_FAST_MODE}\`
- cargo_build_profile: \`${CARGO_BUILD_PROFILE}\`
- changed_files_count: \`${changed_files_count}\`

## Plan

- build_gateway: \`${build_gateway}\`
- build_supervisor: \`${build_supervisor}\`
- helm_upgrade: \`${needs_helm_upgrade}\`
- force_helm_upgrade: \`${FORCE_HELM_UPGRADE}\`
- helm_requested_by_gateway_build: \`${helm_requested_by_gateway_build}\`
- gateway_reconcile_skipped: \`${skip_gateway_reconcile}\`
- gateway_reconcile_skip_reason: \`${skip_gateway_reconcile_reason}\`
- readiness_timeout_seconds: \`${DEPLOY_FAST_READINESS_TIMEOUT_SECONDS}\`
- readiness_poll_seconds: \`${DEPLOY_FAST_READINESS_POLL_SECONDS}\`
- supervisor_reconcile_mode: \`${DEPLOY_FAST_SUPERVISOR_RECONCILE}\`
- supervisor_reconcile_timeout_seconds: \`${DEPLOY_FAST_SUPERVISOR_RECONCILE_TIMEOUT_SECONDS}\`
- supervisor_reconcile_performed: \`${supervisor_reconcile_performed}\`
- supervisor_reconcile_restarted_pods: \`${supervisor_reconcile_restarted_pods}\`
- supervisor_reconcile_waits: \`${supervisor_reconcile_waits}\`
- supervisor_reconcile_expected_running: \`${supervisor_reconcile_expected_running}\`
- supervisor_reconcile_failure_reason: \`${supervisor_reconcile_failure_reason}\`

## Fingerprints

- gateway_previous: \`${previous_gateway_fingerprint}\`
- gateway_current: \`${current_gateway_fingerprint}\`
- gateway_state_written: \`${state_gateway_fingerprint}\`
- supervisor_previous: \`${previous_supervisor_fingerprint}\`
- supervisor_current: \`${current_supervisor_fingerprint}\`
- supervisor_state_written: \`${state_supervisor_fingerprint}\`
- helm_previous: \`${previous_helm_fingerprint}\`
- helm_current: \`${current_helm_fingerprint}\`
- helm_state_written: \`${state_helm_fingerprint}\`

## Gateway Digests

- deployed_before: \`${gateway_deployed_digest}\`
- target_after_push: \`${gateway_target_digest}\`

## Readiness

- readiness_gate_status: \`${readiness_gate_status}\`
- readiness_failure_reason: \`${readiness_failure_reason}\`

## Durations Seconds

- change_detection: \`${change_detection_duration}\`
- builds_total: \`${builds_duration}\`
- supervisor_build_deploy: \`${supervisor_duration}\`
- supervisor_reconcile: \`${supervisor_reconcile_duration}\`
- image_push: \`${image_push_duration}\`
- helm_upgrade: \`${helm_upgrade_duration}\`
- gateway_rollout: \`${gateway_rollout_duration}\`
- readiness_gate: \`${readiness_duration}\`
- total: \`${total_duration}\`
EOF

echo "Deploy report: ${DEPLOY_REPORT_FILE}"

echo "Deploy complete!"
