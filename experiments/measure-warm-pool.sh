#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/wait-ready.sh"

EXPERIMENT_ID="warm-pool"
CONFIG="default"
RUNS=""
NAMESPACE="${NAMESPACE:-default}"
WARM_POOL_NAME="${WARM_POOL_NAME:-openshell-warm-pool}"
TEMPLATE_NAME="${TEMPLATE_NAME:-openshell-warm}"
CLAIM_TIMEOUT="${CLAIM_TIMEOUT:-60}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Measure warm pool claim-to-ready latency across configurations.

Options:
  --config CONFIG   Configuration to run: default, aggressive, burst, all
  --runs N          Number of runs (default: 10 for default/aggressive, 5 for burst)
  --namespace NS    Kubernetes namespace (default: default)
  --pool NAME       SandboxWarmPool name (default: openshell-warm-pool)
  --template NAME   SandboxTemplate name (default: openshell-warm)
  --timeout SECS    Claim readiness timeout in seconds (default: 60)
  -h, --help        Show this help

Configurations:
  default     Claim from warm pool with default readiness probes (periodSeconds=10)
  aggressive  Claim from warm pool with aggressive probes (periodSeconds=1)
  burst       5 simultaneous claims to measure burst behavior and pool replenishment
  all         Run all configurations sequentially
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)    CONFIG="$2"; shift 2 ;;
    --runs)      RUNS="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --pool)      WARM_POOL_NAME="$2"; shift 2 ;;
    --template)  TEMPLATE_NAME="$2"; shift 2 ;;
    --timeout)   CLAIM_TIMEOUT="$2"; shift 2 ;;
    -h|--help)   usage ;;
    *)           log "ERROR: Unknown option: $1"; usage ;;
  esac
done

default_runs_for_config() {
  case "$1" in
    burst) echo 5 ;;
    *)     echo 10 ;;
  esac
}

check_prerequisites() {
  log "Checking prerequisites..."

  if ! kubectl get sandboxwarmpool "$WARM_POOL_NAME" -n "$NAMESPACE" &>/dev/null; then
    log "ERROR: SandboxWarmPool '$WARM_POOL_NAME' not found in namespace '$NAMESPACE'"
    log "Create it first: kubectl apply -f ${SCRIPT_DIR}/manifests/warm-pool.yaml"
    exit 1
  fi

  local ready_replicas
  ready_replicas=$(kubectl get sandboxwarmpool "$WARM_POOL_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
  local desired_replicas
  desired_replicas=$(kubectl get sandboxwarmpool "$WARM_POOL_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

  if [[ "$ready_replicas" == "0" || -z "$ready_replicas" ]]; then
    log "ERROR: SandboxWarmPool has no ready replicas (desired: ${desired_replicas})"
    log "Wait for pool provisioning before running measurements"
    exit 1
  fi

  log "Pool status: ${ready_replicas}/${desired_replicas} replicas ready"
}

wait_pool_replenished() {
  local min_ready="${1:-1}"
  local timeout="${2:-120}"
  local elapsed=0

  while (( elapsed < timeout )); do
    local ready
    ready=$(kubectl get sandboxwarmpool "$WARM_POOL_NAME" -n "$NAMESPACE" \
      -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    if [[ -n "$ready" ]] && (( ready >= min_ready )); then
      return 0
    fi
    if (( elapsed % 10 == 0 && elapsed > 0 )); then
      log "Waiting for pool replenishment... (${ready:-0} ready, need ${min_ready}, ${elapsed}s/${timeout}s)"
    fi
    sleep 1
    (( elapsed++ ))
  done

  log "WARN: Pool did not replenish to ${min_ready} replicas within ${timeout}s"
  return 1
}

get_claimed_sandbox_name() {
  local claim_name="$1"
  kubectl get sandboxclaim "$claim_name" -n "$NAMESPACE" \
    -o jsonpath='{.status.sandboxRef.name}' 2>/dev/null || echo ""
}

get_sandbox_pod_name() {
  local sandbox_name="$1"
  kubectl get pods -n "$NAMESPACE" \
    -l "sandbox.agents.x-k8s.io/name=$sandbox_name" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo ""
}

wait_claim_bound() {
  local claim_name="$1"
  local timeout="${2:-$CLAIM_TIMEOUT}"
  local deadline=$(( $(date +%s) + timeout ))

  while (( $(date +%s) < deadline )); do
    local phase
    phase=$(kubectl get sandboxclaim "$claim_name" -n "$NAMESPACE" \
      -o jsonpath='{.status.phase}' 2>/dev/null || echo "")

    if [[ "$phase" == "Bound" ]]; then
      return 0
    fi
    if [[ "$phase" == "Failed" ]]; then
      log "WARN: Claim $claim_name failed"
      return 1
    fi

    sleep 1
  done

  local final_phase
  final_phase=$(kubectl get sandboxclaim "$claim_name" -n "$NAMESPACE" \
    -o jsonpath='{.status.phase}' 2>/dev/null || echo "unknown")
  log "WARN: Claim $claim_name not bound after ${timeout}s (phase: ${final_phase})"
  return 1
}

wait_claimed_sandbox_ready() {
  local claim_name="$1"
  local timeout="${2:-$CLAIM_TIMEOUT}"

  local sandbox_name
  sandbox_name=$(get_claimed_sandbox_name "$claim_name")
  if [[ -z "$sandbox_name" ]]; then
    log "WARN: No sandbox assigned to claim $claim_name"
    return 1
  fi

  wait_for_sandbox_ready "$sandbox_name" "$NAMESPACE" "$timeout"
}

cleanup_claim() {
  local claim_name="$1"
  kubectl delete sandboxclaim "$claim_name" -n "$NAMESPACE" --ignore-not-found --wait=false 2>/dev/null || true
}

create_claim_yaml() {
  local claim_name="$1"
  cat <<YAML
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${claim_name}
  namespace: ${NAMESPACE}
spec:
  warmPoolRef:
    name: ${WARM_POOL_NAME}
YAML
}

patch_readiness_probe() {
  local period_seconds="$1"
  log "Patching SandboxTemplate ${TEMPLATE_NAME}: readinessProbe.periodSeconds=${period_seconds}"
  kubectl patch sandboxtemplate "$TEMPLATE_NAME" -n "$NAMESPACE" --type='json' \
    -p="[{\"op\":\"replace\",\"path\":\"/spec/podTemplateSpec/spec/containers/0/readinessProbe/periodSeconds\",\"value\":${period_seconds}}]"
}

save_original_probe_period() {
  kubectl get sandboxtemplate "$TEMPLATE_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.spec.podTemplateSpec.spec.containers[0].readinessProbe.periodSeconds}' 2>/dev/null || echo "10"
}

run_single_config() {
  local config="$1"
  local num_runs="$2"
  local csv_file="${RESULTS_DIR}/warm-pool-${config}.csv"

  log "Starting warm-pool measurement: config=${config}, runs=${num_runs}"
  ensure_results_dir
  write_csv_header "$csv_file"

  for (( i=1; i<=num_runs; i++ )); do
    local claim_name="wp-${config}-run-${i}"
    local status="ok"

    # Wait for at least 1 replica before claiming
    if ! wait_pool_replenished 1 60; then
      log "WARN: Pool exhausted, recording run ${i} as pool-exhausted"
      local ts
      ts=$(capture_timestamp)
      write_csv_row "$csv_file" "$i" "$config" "$ts" "" "" "" "pool-exhausted"
      continue
    fi

    log "Run ${i}/${num_runs}: creating claim ${claim_name}"

    local create_ts
    create_ts=$(capture_timestamp)

    if ! create_claim_yaml "$claim_name" | kubectl apply -f - 2>/dev/null; then
      log "WARN: Failed to create claim ${claim_name}"
      write_csv_row "$csv_file" "$i" "$config" "$create_ts" "" "" "" "create-failed"
      cleanup_claim "$claim_name"
      continue
    fi

    # Wait for claim to bind and sandbox to be ready
    if wait_claim_bound "$claim_name" "$CLAIM_TIMEOUT"; then
      local sandbox_name
      sandbox_name=$(get_claimed_sandbox_name "$claim_name")

      if [[ -n "$sandbox_name" ]] && wait_for_sandbox_ready "$sandbox_name" "$NAMESPACE" "$CLAIM_TIMEOUT"; then
        local ready_ts
        ready_ts=$(capture_timestamp)
        local delta_ms
        delta_ms=$(( (ready_ts - create_ts) / 1000000 ))

        local pod_name
        pod_name=$(get_sandbox_pod_name "$sandbox_name")

        if [[ -n "$pod_name" ]]; then
          local events_file="${RESULTS_DIR}/events-wp-${config}-run-${i}.json"
          collect_pod_events "$pod_name" "$NAMESPACE" > "$events_file"
        fi

        write_csv_row "$csv_file" "$i" "$config" "$create_ts" "$ready_ts" "$delta_ms" "${pod_name:-unknown}" "$status"
        log "Run ${i}: ${delta_ms}ms (sandbox: ${sandbox_name}, pod: ${pod_name:-unknown})"
      else
        status="sandbox-not-ready"
        write_csv_row "$csv_file" "$i" "$config" "$create_ts" "" "" "${sandbox_name:-unknown}" "$status"
        log "Run ${i}: sandbox not ready (${sandbox_name:-unknown})"
      fi
    else
      status="bind-timeout"
      write_csv_row "$csv_file" "$i" "$config" "$create_ts" "" "" "" "$status"
      log "Run ${i}: claim bind timeout"
    fi

    cleanup_claim "$claim_name"
    sleep 2
  done

  log "Results written to ${csv_file}"
  compute_stats "$csv_file"
}

run_burst_config() {
  local num_runs="$1"
  local burst_size=5
  local csv_file="${RESULTS_DIR}/warm-pool-burst.csv"

  log "Starting warm-pool burst measurement: runs=${num_runs}, burst_size=${burst_size}"
  ensure_results_dir
  write_csv_header "$csv_file"

  for (( round=1; round<=num_runs; round++ )); do
    log "Burst round ${round}/${num_runs}: submitting ${burst_size} simultaneous claims"

    # Wait for pool to have enough replicas
    if ! wait_pool_replenished "$burst_size" 120; then
      log "WARN: Pool has fewer than ${burst_size} ready replicas for round ${round}"
    fi

    local pool_ready_before
    pool_ready_before=$(kubectl get sandboxwarmpool "$WARM_POOL_NAME" -n "$NAMESPACE" \
      -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    log "Pool state before burst: ${pool_ready_before} ready"

    # Create all claims simultaneously
    local create_ts
    create_ts=$(capture_timestamp)

    declare -a claim_names=()
    for (( j=1; j<=burst_size; j++ )); do
      local claim_name="wp-burst-r${round}-c${j}"
      claim_names+=("$claim_name")
      create_claim_yaml "$claim_name" | kubectl apply -f - 2>/dev/null &
    done
    wait  # Wait for all kubectl apply commands

    # Wait for each claim and record individual times
    for (( j=0; j<burst_size; j++ )); do
      local claim_name="${claim_names[$j]}"
      local run_label="${round}.$((j+1))"
      local status="ok"

      if wait_claim_bound "$claim_name" "$CLAIM_TIMEOUT"; then
        local sandbox_name
        sandbox_name=$(get_claimed_sandbox_name "$claim_name")

        if [[ -n "$sandbox_name" ]] && wait_for_sandbox_ready "$sandbox_name" "$NAMESPACE" "$CLAIM_TIMEOUT"; then
          local ready_ts
          ready_ts=$(capture_timestamp)
          local delta_ms
          delta_ms=$(( (ready_ts - create_ts) / 1000000 ))

          local pod_name
          pod_name=$(get_sandbox_pod_name "$sandbox_name")

          write_csv_row "$csv_file" "$run_label" "burst" "$create_ts" "$ready_ts" "$delta_ms" "${pod_name:-unknown}" "$status"
          log "  Claim ${claim_name}: ${delta_ms}ms (sandbox: ${sandbox_name})"
        else
          status="sandbox-not-ready"
          write_csv_row "$csv_file" "$run_label" "burst" "$create_ts" "" "" "${sandbox_name:-unknown}" "$status"
          log "  Claim ${claim_name}: sandbox not ready"
        fi
      else
        local claim_phase
        claim_phase=$(kubectl get sandboxclaim "$claim_name" -n "$NAMESPACE" \
          -o jsonpath='{.status.phase}' 2>/dev/null || echo "unknown")
        if [[ "$claim_phase" == "Pending" ]]; then
          status="pool-exhausted"
        else
          status="bind-timeout"
        fi
        write_csv_row "$csv_file" "$run_label" "burst" "$create_ts" "" "" "" "$status"
        log "  Claim ${claim_name}: ${status} (phase: ${claim_phase})"
      fi
    done

    # Clean up all claims from this round
    for claim_name in "${claim_names[@]}"; do
      cleanup_claim "$claim_name"
    done

    # Wait for pool to replenish before next round
    if (( round < num_runs )); then
      log "Waiting for pool replenishment before next burst round..."
      wait_pool_replenished "$burst_size" 180 || true
    fi

    unset claim_names
  done

  log "Results written to ${csv_file}"
  compute_stats "$csv_file"
}

run_config() {
  local config="$1"
  local num_runs="${RUNS:-$(default_runs_for_config "$config")}"

  case "$config" in
    default)
      run_single_config "default" "$num_runs"
      ;;
    aggressive)
      local original_period
      original_period=$(save_original_probe_period)
      log "Saving original readinessProbe periodSeconds: ${original_period}"

      patch_readiness_probe 1
      trap 'patch_readiness_probe '"$original_period"'; _cleanup_on_exit' EXIT
      trap 'patch_readiness_probe '"$original_period"'; _cleanup_on_exit; exit 130' INT TERM

      log "Waiting for pool to stabilize with aggressive probes..."
      sleep 10
      wait_pool_replenished 1 120 || true

      run_single_config "aggressive" "$num_runs"

      log "Restoring original readinessProbe periodSeconds: ${original_period}"
      patch_readiness_probe "$original_period"
      trap _cleanup_on_exit EXIT
      trap - INT TERM
      ;;
    burst)
      run_burst_config "$num_runs"
      ;;
    *)
      log "ERROR: Unknown config: $config"
      exit 1
      ;;
  esac
}

# Main
check_prerequisites

case "$CONFIG" in
  all)
    run_config "default"
    run_config "aggressive"
    run_config "burst"
    ;;
  default|aggressive|burst)
    run_config "$CONFIG"
    ;;
  *)
    log "ERROR: Invalid config: $CONFIG (must be default, aggressive, burst, or all)"
    exit 1
    ;;
esac

log "Warm-pool measurement complete."
