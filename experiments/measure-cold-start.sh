#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/wait-ready.sh"

EXPERIMENT_ID="cold-start"
CONFIG="prepulled"
RUNS=""
NAMESPACE="${NAMESPACE:-default}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-ghcr.io/nvidia/openshell/sandbox:latest}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Measure sandbox cold-start latency across configurations.

Options:
  --config CONFIG   Configuration to run: prepulled (default), noprepull, vanilla, all
  --runs N          Number of runs (default: 10 for prepulled/vanilla, 5 for noprepull)
  --namespace NS    Kubernetes namespace (default: default)
  --image IMAGE     Sandbox image override
  -h, --help        Show this help

Configurations:
  prepulled   Create sandboxes via openshell CLI with images pre-pulled (N=10)
  noprepull   Create sandboxes via openshell CLI without pre-pulled images (N=5)
  vanilla     Create vanilla Agent Sandbox pods without OpenShell (N=10)
  all         Run all configurations sequentially
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)   CONFIG="$2"; shift 2 ;;
    --runs)     RUNS="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --image)    SANDBOX_IMAGE="$2"; shift 2 ;;
    -h|--help)  usage ;;
    *)          log "ERROR: Unknown option: $1"; usage ;;
  esac
done

default_runs_for_config() {
  case "$1" in
    noprepull) echo 5 ;;
    *)         echo 10 ;;
  esac
}


cleanup_sandbox() {
  local name="$1"
  local kind="${2:-sandbox}"
  case "$kind" in
    sandbox)
      openshell sandbox delete "$name" --force 2>/dev/null || true
      kubectl delete sandbox "$name" -n "$NAMESPACE" --ignore-not-found --wait=false 2>/dev/null || true
      ;;
    vanilla)
      kubectl delete sandbox "$name" -n "$NAMESPACE" --ignore-not-found --wait=false 2>/dev/null || true
      ;;
  esac
  # Wait for pod cleanup
  local elapsed=0
  while (( elapsed < 30 )); do
    if ! kubectl get sandbox "$name" -n "$NAMESPACE" &>/dev/null; then
      return 0
    fi
    sleep 1
    (( elapsed++ ))
  done
}

get_sandbox_pod() {
  local name="$1"
  kubectl get pods -n "$NAMESPACE" \
    -l "sandbox.agents.x-k8s.io/name=$name" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo ""
}

run_openshell_config() {
  local config="$1"
  local num_runs="$2"
  local csv_file="${RESULTS_DIR}/cold-start-${config}.csv"

  log "Starting cold-start measurement: config=${config}, runs=${num_runs}"
  ensure_results_dir
  write_csv_header "$csv_file"

  for (( i=1; i<=num_runs; i++ )); do
    local sandbox_name="cold-${config}-run-${i}"
    local status="ok"

    log "Run ${i}/${num_runs}: creating sandbox ${sandbox_name}"

    local create_ts
    create_ts=$(capture_timestamp)

    if ! openshell sandbox create --name "$sandbox_name" --from base 2>/dev/null; then
      log "WARN: Failed to create sandbox ${sandbox_name}"
      status="create-failed"
      write_csv_row "$csv_file" "$i" "$config" "$create_ts" "" "" "$sandbox_name" "$status"
      cleanup_sandbox "$sandbox_name" "sandbox"
      continue
    fi

    if wait_for_sandbox_ready "$sandbox_name" "$NAMESPACE" 120; then
      local ready_ts
      ready_ts=$(capture_timestamp)
      local delta_ms
      delta_ms=$(( (ready_ts - create_ts) / 1000000 ))

      local pod_name
      pod_name=$(get_sandbox_pod "$sandbox_name")

      local phase_deltas=",,,,"
      if [[ -n "$pod_name" ]]; then
        local events_file="${RESULTS_DIR}/events-${config}-run-${i}.json"
        collect_pod_events "$pod_name" "$NAMESPACE" > "$events_file"
        phase_deltas=$(extract_phase_deltas "$(cat "$events_file")" "$create_ts")
      fi

      IFS=',' read -r sched_ms pull_ms init_ms sup_ms ssh_ms <<< "$phase_deltas"
      write_csv_row "$csv_file" "$i" "$config" "$create_ts" "$ready_ts" "$delta_ms" "${pod_name:-unknown}" "$status" "$sched_ms" "$pull_ms" "$init_ms" "$sup_ms" "$ssh_ms"
      log "Run ${i}: ${delta_ms}ms (pod: ${pod_name:-unknown})"
    else
      status="timeout"
      write_csv_row "$csv_file" "$i" "$config" "$create_ts" "" "" "$sandbox_name" "$status"
      log "Run ${i}: TIMEOUT"
    fi

    cleanup_sandbox "$sandbox_name" "sandbox"
    sleep 2
  done

  log "Results written to ${csv_file}"
  compute_stats "$csv_file"
}

run_vanilla_config() {
  local num_runs="$1"
  local csv_file="${RESULTS_DIR}/cold-start-vanilla.csv"

  log "Starting cold-start measurement: config=vanilla, runs=${num_runs}"
  ensure_results_dir
  write_csv_header "$csv_file"

  for (( i=1; i<=num_runs; i++ )); do
    local sandbox_name="vanilla-run-${i}"
    local status="ok"

    log "Run ${i}/${num_runs}: creating vanilla sandbox ${sandbox_name}"

    local create_ts
    create_ts=$(capture_timestamp)

    if ! kubectl apply -n "$NAMESPACE" -f - <<YAML
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata:
  name: ${sandbox_name}
spec:
  podTemplateSpec:
    spec:
      containers:
      - name: sandbox
        image: ${SANDBOX_IMAGE}
YAML
    then
      log "WARN: Failed to create vanilla sandbox ${sandbox_name}"
      status="create-failed"
      write_csv_row "$csv_file" "$i" "vanilla" "$create_ts" "" "" "$sandbox_name" "$status"
      cleanup_sandbox "$sandbox_name" "vanilla"
      continue
    fi

    if wait_for_sandbox_ready "$sandbox_name" "$NAMESPACE" 120; then
      local ready_ts
      ready_ts=$(capture_timestamp)
      local delta_ms
      delta_ms=$(( (ready_ts - create_ts) / 1000000 ))

      local pod_name
      pod_name=$(get_sandbox_pod "$sandbox_name")

      local phase_deltas=",,,,"
      if [[ -n "$pod_name" ]]; then
        local events_file="${RESULTS_DIR}/events-vanilla-run-${i}.json"
        collect_pod_events "$pod_name" "$NAMESPACE" > "$events_file"
        phase_deltas=$(extract_phase_deltas "$(cat "$events_file")" "$create_ts")
      fi

      IFS=',' read -r sched_ms pull_ms init_ms sup_ms ssh_ms <<< "$phase_deltas"
      write_csv_row "$csv_file" "$i" "vanilla" "$create_ts" "$ready_ts" "$delta_ms" "${pod_name:-unknown}" "$status" "$sched_ms" "$pull_ms" "$init_ms" "$sup_ms" "$ssh_ms"
      log "Run ${i}: ${delta_ms}ms (pod: ${pod_name:-unknown})"
    else
      status="timeout"
      write_csv_row "$csv_file" "$i" "vanilla" "$create_ts" "" "" "$sandbox_name" "$status"
      log "Run ${i}: TIMEOUT"
    fi

    cleanup_sandbox "$sandbox_name" "vanilla"
    sleep 2
  done

  log "Results written to ${csv_file}"
  compute_stats "$csv_file"
}

run_config() {
  local config="$1"
  local num_runs="${RUNS:-$(default_runs_for_config "$config")}"

  case "$config" in
    prepulled|noprepull)
      run_openshell_config "$config" "$num_runs"
      ;;
    vanilla)
      run_vanilla_config "$num_runs"
      ;;
    *)
      log "ERROR: Unknown config: $config"
      exit 1
      ;;
  esac
}

case "$CONFIG" in
  all)
    run_config "prepulled"
    run_config "noprepull"
    run_config "vanilla"
    ;;
  prepulled|noprepull|vanilla)
    run_config "$CONFIG"
    ;;
  *)
    log "ERROR: Invalid config: $CONFIG (must be prepulled, noprepull, vanilla, or all)"
    exit 1
    ;;
esac

log "Cold-start measurement complete."
