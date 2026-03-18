#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: cluster-deploy-fast-test.sh [scenario...]

Repeatable validation harness for tasks/scripts/cluster-deploy-fast.sh.

Scenarios:
  noop                    Validate clean-tree auto deploy is a no-op after state is primed
  gateway-auto            Gateway-only change triggers gateway rebuild + Helm upgrade
  supervisor-auto         Supervisor-only change triggers supervisor refresh only
  shared-auto             Shared change triggers gateway + supervisor rebuild
  helm-auto               Helm-only change triggers Helm upgrade only
  unrelated-auto          Unrelated change stays a no-op
  explicit-targets        Explicit targets override change detection
  gateway-cache           Compare cold vs warm gateway rebuild after a code change
  supervisor-cache        Compare cold vs warm supervisor rebuild after a code change
  container-invalidation  Mismatched container ID invalidates gateway + Helm state

If no scenarios are provided, the full suite runs.

Environment:
  CLUSTER_NAME                    Override cluster name to test against
  FAST_DEPLOY_TEST_REPORT_DIR     Output directory (default: .cache/cluster-deploy-fast-test/<timestamp>)
  FAST_DEPLOY_TEST_KEEP_WORKTREES Keep temporary worktrees when set to 1
  FAST_DEPLOY_TEST_SKIP_CACHE     Skip the cache timing scenarios when set to 1
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
RUN_ID=$(date +"%Y%m%d-%H%M%S")
REPORT_DIR=${FAST_DEPLOY_TEST_REPORT_DIR:-"${REPO_ROOT}/.cache/cluster-deploy-fast-test/${RUN_ID}"}
WORKTREE_ROOT="${REPORT_DIR}/worktrees"
LOG_DIR="${REPORT_DIR}/logs"
STATE_DIR="${REPORT_DIR}/state"
CACHE_DIR="${REPORT_DIR}/buildkit-cache"
SUMMARY_TSV="${REPORT_DIR}/summary.tsv"
SUMMARY_MD="${REPORT_DIR}/summary.md"
KEEP_WORKTREES=${FAST_DEPLOY_TEST_KEEP_WORKTREES:-0}
SKIP_CACHE=${FAST_DEPLOY_TEST_SKIP_CACHE:-0}

normalize_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//'
}

ROOT_BASENAME=$(basename "${REPO_ROOT}")
CLUSTER_NAME=${CLUSTER_NAME:-$(normalize_name "${ROOT_BASENAME}")}

mkdir -p "${WORKTREE_ROOT}" "${LOG_DIR}" "${STATE_DIR}" "${CACHE_DIR}"

declare -a SCENARIOS=()
if [[ "$#" -gt 0 ]]; then
  SCENARIOS=("$@")
else
  SCENARIOS=(
    noop
    gateway-auto
    supervisor-auto
    shared-auto
    helm-auto
    unrelated-auto
    explicit-targets
    gateway-cache
    supervisor-cache
    container-invalidation
  )
fi

if [[ "${SKIP_CACHE}" == "1" ]]; then
  declare -a filtered=()
  filtered=()
  for scenario in "${SCENARIOS[@]}"; do
    if [[ "${scenario}" != "gateway-cache" && "${scenario}" != "supervisor-cache" ]]; then
      filtered+=("${scenario}")
    fi
  done
  SCENARIOS=("${filtered[@]}")
fi

declare -a CREATED_WORKTREES=()

cleanup() {
  if [[ "${KEEP_WORKTREES}" == "1" ]]; then
    return
  fi

  local dir
  for dir in "${CREATED_WORKTREES[@]:-}"; do
    if [[ -d "${dir}" ]]; then
      git -C "${REPO_ROOT}" worktree remove --force "${dir}" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

buildx_driver() {
  local -a builder_args=()
  local ctx

  if [[ -n "${DOCKER_BUILDER:-}" ]]; then
    builder_args=(--builder "${DOCKER_BUILDER}")
  elif [[ -z "${DOCKER_PLATFORM:-}" && -z "${CI:-}" ]]; then
    ctx=$(docker context inspect --format '{{.Name}}' 2>/dev/null || echo default)
    builder_args=(--builder "${ctx}")
  fi

  docker buildx inspect ${builder_args[@]+"${builder_args[@]}"} 2>/dev/null \
    | awk -F': ' '/Driver:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}'
}

current_cluster_container_id() {
  docker inspect --format '{{.Id}}' "openshell-cluster-${CLUSTER_NAME}" 2>/dev/null || true
}

require_cluster() {
  if ! docker ps -q --filter "name=^openshell-cluster-${CLUSTER_NAME}$" --filter "health=healthy" | grep -q .; then
    echo "Error: cluster container 'openshell-cluster-${CLUSTER_NAME}' is not running or healthy." >&2
    echo "Start it first with: mise run cluster" >&2
    exit 1
  fi
}

create_worktree() {
  local name=$1
  local dir="${WORKTREE_ROOT}/${name}"
  rm -rf "${dir}"
  git -C "${REPO_ROOT}" worktree add --detach "${dir}" HEAD >/dev/null
  CREATED_WORKTREES+=("${dir}")
  printf '%s\n' "${dir}"
}

append_marker() {
  local file=$1
  local marker=$2
  printf '\n%s\n' "${marker}" >> "${file}"
}

extract_plan_value() {
  local log_file=$1
  local label=$2
  awk -F': +' -v pattern="${label}" '$0 ~ pattern {print $2; exit}' "${log_file}"
}

extract_duration() {
  local log_file=$1
  local label=$2
  awk -v prefix="${label} took " 'index($0, prefix) == 1 {sub(/^.* took /, "", $0); sub(/s$/, "", $0); print; exit}' "${log_file}"
}

count_cached_lines() {
  local log_file=$1
  grep -c " CACHED" "${log_file}" 2>/dev/null || true
}

check_required_patterns() {
  local log_file=$1
  local patterns=${2:-}
  local pattern

  if [[ -z "${patterns}" ]]; then
    return 0
  fi

  IFS='|' read -r -a pattern_array <<< "${patterns}"
  for pattern in "${pattern_array[@]}"; do
    if ! grep -Fq "${pattern}" "${log_file}"; then
      return 1
    fi
  done

  return 0
}

record_result() {
  local scenario=$1
  local mode=$2
  local expected=$3
  local observed=$4
  local pass=$5
  local total_duration=$6
  local build_duration=$7
  local cached_lines=$8
  local notes=$9

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${scenario}" "${mode}" "${expected}" "${observed}" "${pass}" \
    "${total_duration}" "${build_duration}" "${cached_lines}" "${notes}" >> "${SUMMARY_TSV}"
}

write_summary_md() {
  {
    echo "# Fast Deploy Cache Test Summary"
    echo
    echo "- Cluster: \`${CLUSTER_NAME}\`"
    echo "- Buildx driver: \`${BUILDX_DRIVER:-unknown}\`"
    echo "- Report dir: \`${REPORT_DIR}\`"
    echo
    echo "| Scenario | Mode | Expected | Observed | Pass | Total (s) | Builds (s) | Cached lines | Notes |"
    echo "|---|---|---|---|---|---:|---:|---:|---|"
    awk -F '\t' 'NR > 1 {printf "| %s | %s | `%s` | `%s` | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6, $7, $8, $9}' "${SUMMARY_TSV}"
  } > "${SUMMARY_MD}"
}

run_fast_deploy() {
  local worktree=$1
  local state_file=$2
  local log_file=$3
  shift 3

  local start end status
  start=$(date +%s)
  (
    cd "${worktree}"
    env \
      BUILDKIT_PROGRESS=plain \
      CLUSTER_NAME="${CLUSTER_NAME}" \
      DEPLOY_FAST_STATE_FILE="${state_file}" \
      DOCKER_BUILD_CACHE_DIR="${CACHE_DIR}" \
      "$@" \
      ./tasks/scripts/cluster-deploy-fast.sh
  ) >"${log_file}" 2>&1 || status=$?
  status=${status:-0}
  end=$(date +%s)
  printf '%s\n' $((end - start))
  return "${status}"
}

run_fast_deploy_args() {
  local worktree=$1
  local state_file=$2
  local log_file=$3
  shift 3

  local start end status
  start=$(date +%s)
  (
    cd "${worktree}"
    env \
      BUILDKIT_PROGRESS=plain \
      CLUSTER_NAME="${CLUSTER_NAME}" \
      DEPLOY_FAST_STATE_FILE="${state_file}" \
      DOCKER_BUILD_CACHE_DIR="${CACHE_DIR}" \
      ./tasks/scripts/cluster-deploy-fast.sh "$@"
  ) >"${log_file}" 2>&1 || status=$?
  status=${status:-0}
  end=$(date +%s)
  printf '%s\n' $((end - start))
  return "${status}"
}

validate_plan() {
  local log_file=$1
  local expected_gateway=$2
  local expected_supervisor=$3
  local expected_helm=$4

  local gateway supervisor helm
  gateway=$(extract_plan_value "${log_file}" "build gateway")
  supervisor=$(extract_plan_value "${log_file}" "build supervisor")
  helm=$(extract_plan_value "${log_file}" "helm upgrade")

  if [[ "${gateway}" == "${expected_gateway}" && "${supervisor}" == "${expected_supervisor}" && "${helm}" == "${expected_helm}" ]]; then
    printf '%s\n' "build gateway=${gateway}, build supervisor=${supervisor}, helm upgrade=${helm}"
    return 0
  fi

  printf '%s\n' "build gateway=${gateway:-missing}, build supervisor=${supervisor:-missing}, helm upgrade=${helm:-missing}"
  return 1
}

clear_cache() {
  rm -rf "${CACHE_DIR}"
  mkdir -p "${CACHE_DIR}"
}

prime_state() {
  local name=$1
  local worktree state_file log_file
  worktree=$(create_worktree "${name}-prime")
  state_file="${STATE_DIR}/${name}.state"
  log_file="${LOG_DIR}/${name}-prime.log"
  run_fast_deploy "${worktree}" "${state_file}" "${log_file}" >/dev/null
}

run_auto_scenario() {
  local scenario=$1
  local file=$2
  local marker=$3
  local expected_gateway=$4
  local expected_supervisor=$5
  local expected_helm=$6
  local note=$7
  local required_patterns=${8:-}

  local worktree state_file log_file total_duration build_duration observed pass
  worktree=$(create_worktree "${scenario}")
  state_file="${STATE_DIR}/${scenario}.state"
  log_file="${LOG_DIR}/${scenario}.log"

  prime_state "${scenario}"
  append_marker "${worktree}/${file}" "${marker}"

  total_duration=$(run_fast_deploy "${worktree}" "${state_file}" "${log_file}")
  build_duration=$(extract_duration "${log_file}" "Builds")
  if observed=$(validate_plan "${log_file}" "${expected_gateway}" "${expected_supervisor}" "${expected_helm}"); then
    pass=PASS
  else
    pass=FAIL
  fi

  if [[ "${pass}" == "PASS" ]] && ! check_required_patterns "${log_file}" "${required_patterns}"; then
    pass=FAIL
    note="${note}; missing expected deploy log pattern"
  fi

  record_result \
    "${scenario}" \
    "auto" \
    "build gateway=${expected_gateway}, build supervisor=${expected_supervisor}, helm upgrade=${expected_helm}" \
    "${observed}" \
    "${pass}" \
    "${total_duration}" \
    "${build_duration:-n/a}" \
    "$(count_cached_lines "${log_file}")" \
    "${note}"
}

run_noop_scenario() {
  local scenario=noop
  local worktree state_file log_file total_duration build_duration observed pass notes
  worktree=$(create_worktree "${scenario}")
  state_file="${STATE_DIR}/${scenario}.state"
  log_file="${LOG_DIR}/${scenario}.log"

  prime_state "${scenario}"

  total_duration=$(run_fast_deploy "${worktree}" "${state_file}" "${log_file}")
  build_duration=$(extract_duration "${log_file}" "Builds")
  if observed=$(validate_plan "${log_file}" 0 0 0); then
    pass=PASS
  else
    pass=FAIL
  fi
  notes="clean tree should print no-op plan"

  if ! grep -q "No new local changes since last deploy." "${log_file}"; then
    pass=FAIL
    notes="missing no-op message"
  fi

  record_result \
    "${scenario}" \
    "auto" \
    "build gateway=0, build supervisor=0, helm upgrade=0" \
    "${observed}" \
    "${pass}" \
    "${total_duration}" \
    "${build_duration:-n/a}" \
    "$(count_cached_lines "${log_file}")" \
    "${notes}"
}

run_explicit_targets_scenario() {
  local scenario=explicit-targets
  local target worktree state_file log_file total_duration build_duration observed pass expected notes

  for target in gateway supervisor chart all; do
    worktree=$(create_worktree "${scenario}-${target}")
    state_file="${STATE_DIR}/${scenario}-${target}.state"
    log_file="${LOG_DIR}/${scenario}-${target}.log"

    total_duration=$(run_fast_deploy_args "${worktree}" "${state_file}" "${log_file}" "${target}")
    build_duration=$(extract_duration "${log_file}" "Builds")

    case "${target}" in
      gateway)
        if observed=$(validate_plan "${log_file}" 1 0 1); then
          pass=PASS
        else
          pass=FAIL
        fi
        expected="build gateway=1, build supervisor=0, helm upgrade=1"
        ;;
      supervisor)
        if observed=$(validate_plan "${log_file}" 0 1 0); then
          pass=PASS
        else
          pass=FAIL
        fi
        expected="build gateway=0, build supervisor=1, helm upgrade=0"
        ;;
      chart)
        if observed=$(validate_plan "${log_file}" 0 0 1); then
          pass=PASS
        else
          pass=FAIL
        fi
        expected="build gateway=0, build supervisor=0, helm upgrade=1"
        ;;
      all)
        if observed=$(validate_plan "${log_file}" 1 1 1); then
          pass=PASS
        else
          pass=FAIL
        fi
        expected="build gateway=1, build supervisor=1, helm upgrade=1"
        ;;
    esac
    notes="explicit target ${target}"
    record_result \
      "${scenario}:${target}" \
      "explicit" \
      "${expected}" \
      "${observed}" \
      "${pass}" \
      "${total_duration}" \
      "${build_duration:-n/a}" \
      "$(count_cached_lines "${log_file}")" \
      "${notes}"
  done
}

run_cache_scenario() {
  local scenario=$1
  local file=$2
  local marker=$3
  local target=$4

  local worktree state_file cold_log warm_log cold_total warm_total cold_build warm_build cold_cached warm_cached pass notes
  worktree=$(create_worktree "${scenario}")
  state_file="${STATE_DIR}/${scenario}.state"
  cold_log="${LOG_DIR}/${scenario}-cold.log"
  warm_log="${LOG_DIR}/${scenario}-warm.log"

  append_marker "${worktree}/${file}" "${marker}"
  clear_cache

  cold_total=$(run_fast_deploy_args "${worktree}" "${state_file}" "${cold_log}" "${target}")
  cold_build=$(extract_duration "${cold_log}" "Builds")
  cold_cached=$(count_cached_lines "${cold_log}")

  warm_total=$(run_fast_deploy_args "${worktree}" "${state_file}" "${warm_log}" "${target}")
  warm_build=$(extract_duration "${warm_log}" "Builds")
  warm_cached=$(count_cached_lines "${warm_log}")

  pass=FAIL
  notes="warm rebuild should be faster or show cache hits"

  if [[ -n "${cold_build:-}" && -n "${warm_build:-}" && "${cold_build}" =~ ^[0-9]+$ && "${warm_build}" =~ ^[0-9]+$ && "${cold_build}" -gt 0 ]]; then
    if [[ "${warm_build}" -le $((cold_build * 70 / 100)) ]]; then
      pass=PASS
      notes="warm build improved by at least 30%"
    fi
  fi

  if [[ "${pass}" != "PASS" && "${warm_cached}" =~ ^[0-9]+$ && "${warm_cached}" -gt "${cold_cached:-0}" ]]; then
    pass=PASS
    notes="warm build showed more cache hits"
  fi

  record_result \
    "${scenario}:cold" \
    "cache" \
    "first rebuild of ${target} after cache clear" \
    "total=${cold_total}s, builds=${cold_build:-n/a}s" \
    "INFO" \
    "${cold_total}" \
    "${cold_build:-n/a}" \
    "${cold_cached}" \
    "baseline cold run"

  record_result \
    "${scenario}:warm" \
    "cache" \
    "second rebuild of ${target} should reuse cache" \
    "total=${warm_total}s, builds=${warm_build:-n/a}s" \
    "${pass}" \
    "${warm_total}" \
    "${warm_build:-n/a}" \
    "${warm_cached}" \
    "${notes}"
}

run_container_invalidation_scenario() {
  local scenario=container-invalidation
  local worktree state_file prime_log rerun_log total_duration build_duration observed pass container_id notes
  worktree=$(create_worktree "${scenario}")
  state_file="${STATE_DIR}/${scenario}.state"
  prime_log="${LOG_DIR}/${scenario}-prime.log"
  rerun_log="${LOG_DIR}/${scenario}.log"

  run_fast_deploy "${worktree}" "${state_file}" "${prime_log}" >/dev/null
  container_id=$(current_cluster_container_id)
  if [[ -z "${container_id}" ]]; then
    echo "Error: could not determine cluster container ID for invalidation scenario." >&2
    exit 1
  fi

  sed -i.bak "s|^container_id=.*$|container_id=invalidated-${container_id#sha256:}|" "${state_file}"
  rm -f "${state_file}.bak"

  total_duration=$(run_fast_deploy "${worktree}" "${state_file}" "${rerun_log}")
  build_duration=$(extract_duration "${rerun_log}" "Builds")
  if observed=$(validate_plan "${rerun_log}" 1 0 1); then
    pass=PASS
  else
    pass=FAIL
  fi
  notes="mismatched container ID should invalidate gateway and helm only"

  if [[ "${pass}" == "PASS" ]] && ! check_required_patterns "${rerun_log}" "Restarting gateway to pick up updated image...|Upgrading helm release..."; then
    pass=FAIL
    notes="${notes}; missing expected deploy log pattern"
  fi

  record_result \
    "${scenario}" \
    "auto" \
    "build gateway=1, build supervisor=0, helm upgrade=1" \
    "${observed}" \
    "${pass}" \
    "${total_duration}" \
    "${build_duration:-n/a}" \
    "$(count_cached_lines "${rerun_log}")" \
    "${notes}"
}

printf 'scenario\tmode\texpected\tobserved\tpass\ttotal_seconds\tbuild_seconds\tcached_lines\tnotes\n' > "${SUMMARY_TSV}"

require_cluster
BUILDX_DRIVER=$(buildx_driver || true)

for scenario in "${SCENARIOS[@]}"; do
  case "${scenario}" in
    noop)
      run_noop_scenario
      ;;
    gateway-auto)
      run_auto_scenario \
        "gateway-auto" \
        "crates/openshell-server/src/main.rs" \
        "// fast deploy cache test: gateway-auto ${RUN_ID}" \
        1 0 1 \
        "gateway-only source change" \
        "Pushing updated images to local registry...|Restarting gateway to pick up updated image...|Upgrading helm release..."
      ;;
    supervisor-auto)
      run_auto_scenario \
        "supervisor-auto" \
        "crates/openshell-sandbox/src/main.rs" \
        "// fast deploy cache test: supervisor-auto ${RUN_ID}" \
        0 1 0 \
        "supervisor-only source change" \
        "Supervisor binary updated on cluster node."
      ;;
    shared-auto)
      run_auto_scenario \
        "shared-auto" \
        "crates/openshell-policy/src/lib.rs" \
        "// fast deploy cache test: shared-auto ${RUN_ID}" \
        1 1 0 \
        "shared dependency change should rebuild both binaries" \
        "Restarting gateway to pick up updated image...|Supervisor binary updated on cluster node."
      ;;
    helm-auto)
      run_auto_scenario \
        "helm-auto" \
        "deploy/helm/openshell/values.yaml" \
        "# fast deploy cache test: helm-auto ${RUN_ID}" \
        0 0 1 \
        "chart-only change" \
        "Upgrading helm release..."
      ;;
    unrelated-auto)
      run_auto_scenario \
        "unrelated-auto" \
        "README.md" \
        "<!-- fast deploy cache test: unrelated-auto ${RUN_ID} -->" \
        0 0 0 \
        "unrelated file should stay a no-op" \
        "No new local changes since last deploy."
      ;;
    explicit-targets)
      run_explicit_targets_scenario
      ;;
    gateway-cache)
      run_cache_scenario \
        "gateway-cache" \
        "crates/openshell-server/src/main.rs" \
        "// fast deploy cache test: gateway-cache ${RUN_ID}" \
        "gateway"
      ;;
    supervisor-cache)
      run_cache_scenario \
        "supervisor-cache" \
        "crates/openshell-sandbox/src/main.rs" \
        "// fast deploy cache test: supervisor-cache ${RUN_ID}" \
        "supervisor"
      ;;
    container-invalidation)
      run_container_invalidation_scenario
      ;;
    *)
      echo "Unknown scenario '${scenario}'" >&2
      exit 1
      ;;
  esac
done

write_summary_md

echo "Fast deploy cache test report written to:"
echo "  ${SUMMARY_MD}"
