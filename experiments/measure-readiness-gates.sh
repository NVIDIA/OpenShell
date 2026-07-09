#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/wait-ready.sh"

EXPERIMENT_ID="readiness-gates"
RUNS=10
NAMESPACE="${NAMESPACE:-default}"
MANIFEST="${SCRIPT_DIR}/manifests/readiness-gate-pod.yaml"
CSV_FILE="${RESULTS_DIR}/readiness-gates.csv"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Measure ReadinessGate condition flip-to-Ready latency.

Options:
  --runs N          Number of runs (default: 10)
  --namespace NS    Kubernetes namespace (default: default)
  -h, --help        Show this help
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)      RUNS="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    -h|--help)   usage ;;
    *)           log "ERROR: Unknown option: $1"; usage ;;
  esac
done

wait_pod_running() {
  local pod="$1"
  local timeout="${2:-120}"
  local elapsed=0
  while (( elapsed < timeout )); do
    local phase
    phase=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
    if [[ "$phase" == "Running" ]]; then
      return 0
    fi
    if [[ "$phase" == "Failed" || "$phase" == "Succeeded" ]]; then
      log "Pod $pod terminated with phase: $phase"
      return 1
    fi
    sleep 1
    (( elapsed++ ))
  done
  log "Timeout: pod $pod not Running after ${timeout}s"
  return 1
}

log "Starting readiness-gate measurement: runs=${RUNS}"
ensure_results_dir
write_csv_header "$CSV_FILE"

for (( i=1; i<=RUNS; i++ )); do
  POD="readiness-gate-run-${i}"
  status="ok"

  log "Run ${i}/${RUNS}: creating pod ${POD}"

  sed "s/readiness-gate-test-PLACEHOLDER/${POD}/" "$MANIFEST" | \
    kubectl apply -n "$NAMESPACE" -f -

  if ! wait_pod_running "$POD" 120; then
    status="not-running"
    write_csv_row "$CSV_FILE" "$i" "readiness-gate" "" "" "" "$POD" "$status"
    kubectl delete pod "$POD" -n "$NAMESPACE" --ignore-not-found --wait=false 2>/dev/null || true
    continue
  fi

  patch_ts=$(capture_timestamp)

  kubectl patch pod "$POD" -n "$NAMESPACE" \
    --type=json --subresource=status \
    -p '[{"op":"add","path":"/status/conditions/-","value":{"type":"sandbox.openshell.io/claimed","status":"True","lastTransitionTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}]'

  if wait_for_pod_ready "$POD" "$NAMESPACE" 60; then
    ready_ts=$(capture_timestamp)
    delta_ms=$(( (ready_ts - patch_ts) / 1000000 ))

    write_csv_row "$CSV_FILE" "$i" "readiness-gate" "$patch_ts" "$ready_ts" "$delta_ms" "$POD" "$status"
    log "Run ${i}: ${delta_ms}ms"
  else
    status="timeout"
    write_csv_row "$CSV_FILE" "$i" "readiness-gate" "$patch_ts" "" "" "$POD" "$status"
    log "Run ${i}: TIMEOUT"
  fi

  kubectl delete pod "$POD" -n "$NAMESPACE" --ignore-not-found --wait=false 2>/dev/null || true
  sleep 2
done

log "Results written to ${CSV_FILE}"
compute_stats "$CSV_FILE"
log "Readiness-gate measurement complete."
