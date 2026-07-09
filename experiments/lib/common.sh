#!/usr/bin/env bash
# Shared measurement functions for warm pool experiments.
# Source this file from experiment scripts: source "$(dirname "$0")/../lib/common.sh"

set -euo pipefail

EXPERIMENT_ID="${EXPERIMENT_ID:-unknown}"
RESULTS_DIR="${RESULTS_DIR:-experiments/results}"

CLEANUP_RESOURCES=()
register_cleanup() { CLEANUP_RESOURCES+=("$1"); }
deregister_cleanup() { CLEANUP_RESOURCES=("${CLEANUP_RESOURCES[@]/$1}"); }
_cleanup_on_exit() {
  for res in "${CLEANUP_RESOURCES[@]}"; do
    [[ -z "$res" ]] && continue
    log "Cleaning up: $res"
    kubectl delete $res --ignore-not-found --wait=false 2>/dev/null || true
  done
}
trap _cleanup_on_exit EXIT

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

ensure_results_dir() {
  mkdir -p "$RESULTS_DIR"
}

capture_timestamp() {
  if command -v gdate &>/dev/null; then
    gdate +%s%N
  elif date +%s%N | grep -qv N; then
    date +%s%N
  else
    # Fallback: seconds with 000000000 appended (no nanosecond support)
    echo "$(date +%s)000000000"
  fi
}

write_csv_header() {
  local file="$1"
  echo "run,experiment,config,create_ts,ready_ts,delta_ms,pod,status,scheduled_ms,pulled_ms,init_ms,supervisor_ms,ssh_ms" > "$file"
}

write_csv_row() {
  local file="$1"
  local run="$2"
  local config="$3"
  local create_ts="$4"
  local ready_ts="$5"
  local delta_ms="$6"
  local pod="$7"
  local row_status="$8"
  local scheduled_ms="${9:-}"
  local pulled_ms="${10:-}"
  local init_ms="${11:-}"
  local supervisor_ms="${12:-}"
  local ssh_ms="${13:-}"
  echo "${run},${EXPERIMENT_ID},${config},${create_ts},${ready_ts},${delta_ms},${pod},${row_status},${scheduled_ms},${pulled_ms},${init_ms},${supervisor_ms},${ssh_ms}" >> "$file"
}

_iso_to_epoch() {
  local ts="$1"
  if [[ -z "$ts" || "$ts" == "null" ]]; then
    echo ""
    return
  fi
  if command -v gdate &>/dev/null; then
    gdate -d "$ts" +%s 2>/dev/null || echo ""
  else
    date -d "$ts" +%s 2>/dev/null || echo ""
  fi
}

_event_ts() {
  local events_json="$1"
  local reason="$2"
  local pick="${3:-first}"
  local selector=".reason == \"$reason\""
  if [[ "$reason" == *"|"* ]]; then
    local r1="${reason%%|*}"
    local r2="${reason#*|}"
    selector=".reason == \"$r1\" or .reason == \"$r2\""
  fi
  if [[ "$pick" == "last" ]]; then
    echo "$events_json" | jq -r "[.items[] | select($selector)] | last | (.lastTimestamp // .eventTime // null)" 2>/dev/null
  else
    echo "$events_json" | jq -r "[.items[] | select($selector)] | first | (.lastTimestamp // .eventTime // null)" 2>/dev/null
  fi
}

extract_phase_deltas() {
  local events_json="$1"
  local create_ts="$2"
  local create_s=$((create_ts / 1000000000))

  local sched_ts pull_ts init_ts start_ts
  sched_ts=$(_event_ts "$events_json" "Scheduled" "first")
  pull_ts=$(_event_ts "$events_json" "Pulled|Pulling" "last")
  init_ts=$(_event_ts "$events_json" "Created" "first")
  start_ts=$(_event_ts "$events_json" "Started" "last")

  local sched_ms="" pull_ms="" init_ms="" start_ms=""

  local epoch
  epoch=$(_iso_to_epoch "$sched_ts")
  [[ -n "$epoch" ]] && sched_ms=$(( (epoch - create_s) * 1000 ))

  epoch=$(_iso_to_epoch "$pull_ts")
  [[ -n "$epoch" ]] && pull_ms=$(( (epoch - create_s) * 1000 ))

  epoch=$(_iso_to_epoch "$init_ts")
  [[ -n "$epoch" ]] && init_ms=$(( (epoch - create_s) * 1000 ))

  epoch=$(_iso_to_epoch "$start_ts")
  [[ -n "$epoch" ]] && start_ms=$(( (epoch - create_s) * 1000 ))

  echo "${sched_ms},${pull_ms},${init_ms},${start_ms},"
}

collect_pod_events() {
  local pod="$1"
  local ns="${2:-default}"
  kubectl get events \
    --namespace="$ns" \
    --field-selector="involvedObject.name=$pod,involvedObject.kind=Pod" \
    --sort-by='.lastTimestamp' \
    -o json 2>/dev/null || echo '{"items":[]}'
}

detect_adoption() {
  local pod_name="$1"
  local ns="${2:-default}"
  if [[ -z "$pod_name" ]]; then
    echo "unknown"
    return
  fi

  local events_json
  events_json=$(collect_pod_events "$pod_name" "$ns")

  local scheduled_count
  scheduled_count=$(echo "$events_json" | \
    jq '[.items[] | select(.reason == "Scheduled")] | length' 2>/dev/null || echo "0")

  local pulled_count
  pulled_count=$(echo "$events_json" | \
    jq '[.items[] | select(.reason == "Pulling" or .reason == "Pulled")] | length' 2>/dev/null || echo "0")

  if (( scheduled_count == 0 && pulled_count == 0 )); then
    echo "warm-adopted"
  else
    echo "cold-fallback"
  fi
}

compute_stats() {
  local csv_file="$1"
  if [[ ! -f "$csv_file" ]]; then
    log "ERROR: CSV file not found: $csv_file"
    return 1
  fi

  awk -F',' '
  NR == 1 { next }
  $8 != "ok" { skipped++; next }
  $6 == "" { skipped++; next }
  {
    v = $6 + 0
    n++
    vals[n] = v
    sum += v
    if (n == 1 || v < min) min = v
    if (n == 1 || v > max) max = v
  }
  END {
    if (n == 0) {
      print "No data rows found."
      exit 1
    }

    # Sort values (insertion sort)
    for (i = 2; i <= n; i++) {
      key = vals[i]
      j = i - 1
      while (j >= 1 && vals[j] > key) {
        vals[j+1] = vals[j]
        j--
      }
      vals[j+1] = key
    }

    p50_idx = int(n * 0.5 + 0.5)
    p90_idx = int(n * 0.9 + 0.5)
    if (p50_idx < 1) p50_idx = 1
    if (p90_idx < 1) p90_idx = 1
    if (p50_idx > n) p50_idx = n
    if (p90_idx > n) p90_idx = n

    mean = sum / n
    printf "\n--- Statistics (%d samples) ---\n", n
    printf "  min:  %10.1f ms\n", min
    printf "  max:  %10.1f ms\n", max
    printf "  mean: %10.1f ms\n", mean
    printf "  p50:  %10.1f ms\n", vals[p50_idx]
    printf "  p90:  %10.1f ms\n", vals[p90_idx]
    printf "-------------------------------\n"
    if (skipped > 0) printf "  (%d non-ok rows excluded)\n", skipped
  }
  ' "$csv_file"
}
