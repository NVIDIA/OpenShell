#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/wait-ready.sh"

EXPERIMENT_ID="sidecar-readiness"
RUNS=10
NAMESPACE="${NAMESPACE:-default}"
MANIFEST="${SCRIPT_DIR}/manifests/sidecar-readiness.yaml"
CSV_FILE="${RESULTS_DIR}/sidecar-readiness.csv"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Measure sidecar readiness pattern latency (signal file to pod Ready).

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

wait_container_running() {
  local pod="$1"
  local container="$2"
  local timeout="${3:-120}"
  local elapsed=0
  while (( elapsed < timeout )); do
    local running
    running=$(kubectl get pod "$pod" -n "$NAMESPACE" \
      -o jsonpath="{.status.containerStatuses[?(@.name==\"${container}\")].state.running.startedAt}" \
      2>/dev/null || echo "")
    if [[ -n "$running" ]]; then
      return 0
    fi
    sleep 1
    (( elapsed++ ))
  done
  log "Timeout: container $container in pod $pod not Running after ${timeout}s"
  return 1
}

log "Starting sidecar-readiness measurement: runs=${RUNS}"
ensure_results_dir
write_csv_header "$CSV_FILE"

for (( i=1; i<=RUNS; i++ )); do
  POD="sidecar-readiness-run-${i}"
  status="ok"

  log "Run ${i}/${RUNS}: creating pod ${POD}"

  sed "s/sidecar-readiness-test-PLACEHOLDER/${POD}/" "$MANIFEST" | \
    kubectl apply -n "$NAMESPACE" -f -

  if ! wait_container_running "$POD" "sandbox" 120; then
    status="not-running"
    write_csv_row "$CSV_FILE" "$i" "sidecar-readiness" "" "" "" "$POD" "$status"
    kubectl delete pod "$POD" -n "$NAMESPACE" --ignore-not-found --wait=false 2>/dev/null || true
    continue
  fi

  signal_ts=$(capture_timestamp)

  kubectl exec "$POD" -n "$NAMESPACE" -c sandbox -- touch /tmp/signal/ready

  if wait_for_pod_ready "$POD" "$NAMESPACE" 60; then
    ready_ts=$(capture_timestamp)
    delta_ms=$(( (ready_ts - signal_ts) / 1000000 ))

    write_csv_row "$CSV_FILE" "$i" "sidecar-readiness" "$signal_ts" "$ready_ts" "$delta_ms" "$POD" "$status"
    log "Run ${i}: ${delta_ms}ms"
  else
    status="timeout"
    write_csv_row "$CSV_FILE" "$i" "sidecar-readiness" "$signal_ts" "" "" "$POD" "$status"
    log "Run ${i}: TIMEOUT"
  fi

  kubectl delete pod "$POD" -n "$NAMESPACE" --ignore-not-found --wait=false 2>/dev/null || true
  sleep 2
done

log "Results written to ${CSV_FILE}"
compute_stats "$CSV_FILE"
log "Sidecar-readiness measurement complete."
