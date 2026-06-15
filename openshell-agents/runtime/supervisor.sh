#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || { echo "missing required env: $name" >&2; exit 1; }
}

require_env OPENSHELL_AGENT_HARNESS

RUNTIME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$RUNTIME_DIR/.." && pwd)"
PROMPT_FILE="$PAYLOAD_DIR/agent-prompt.md"
ADAPTER="$PAYLOAD_DIR/runtime/harnesses/$OPENSHELL_AGENT_HARNESS/exec.sh"
RUN_MODE="${OPENSHELL_AGENT_RUN_MODE:-once}"
POLL_INTERVAL_SECONDS="${OPENSHELL_AGENT_POLL_INTERVAL_SECONDS:-900}"
MAX_TRANSIENT_FAILURES="${OPENSHELL_AGENT_MAX_TRANSIENT_FAILURES:-5}"
HEARTBEAT_SECONDS="${OPENSHELL_AGENT_HEARTBEAT_SECONDS:-60}"
MAX_SLEEP_SECONDS=86400

[[ -f "$PROMPT_FILE" ]] || { echo "missing agent prompt: $PROMPT_FILE" >&2; exit 1; }
[[ -x "$ADAPTER" ]] || { echo "missing harness adapter: $ADAPTER" >&2; exit 1; }

case "$RUN_MODE" in
    once|watch) ;;
    *) echo "unsupported agent run mode: $RUN_MODE" >&2; exit 2 ;;
esac
[[ "$POLL_INTERVAL_SECONDS" =~ ^[0-9]+$ ]] || { echo "OPENSHELL_AGENT_POLL_INTERVAL_SECONDS must be an integer" >&2; exit 2; }
[[ "$MAX_TRANSIENT_FAILURES" =~ ^[0-9]+$ ]] || { echo "OPENSHELL_AGENT_MAX_TRANSIENT_FAILURES must be an integer" >&2; exit 2; }
[[ "$HEARTBEAT_SECONDS" =~ ^[0-9]+$ ]] || { echo "OPENSHELL_AGENT_HEARTBEAT_SECONDS must be an integer" >&2; exit 2; }
[[ "$POLL_INTERVAL_SECONDS" -gt 0 ]] || { echo "OPENSHELL_AGENT_POLL_INTERVAL_SECONDS must be greater than zero" >&2; exit 2; }

json_string_field() {
    local json="$1"
    local key="$2"
    printf '%s' "$json" | sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\1/p"
}

json_number_field() {
    local json="$1"
    local key="$2"
    printf '%s' "$json" | sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p"
}

valid_result_json() {
    local json="$1"

    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$json" | jq -e 'type == "object"' >/dev/null 2>&1
        return
    fi
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$json" | python3 -c '
import json
import sys

try:
    value = json.load(sys.stdin)
except Exception:
    sys.exit(1)

sys.exit(0 if isinstance(value, dict) else 1)
' >/dev/null 2>&1
        return
    fi
    return 1
}

classify_transient_failure() {
    local output_file="$1"
    grep -Eiq 'stream disconnected before completion|failed to connect to websocket|Reconnecting\.\.\.|Broken pipe|Connection to sandbox closed by remote host|peer closed connection without sending TLS close_notify' "$output_file"
}

safe_sleep_seconds() {
    local value="$1"

    if [[ ! "$value" =~ ^[0-9]+$ ]] || [[ "$value" -le 0 ]]; then
        printf '%s\n' "$POLL_INTERVAL_SECONDS"
        return
    fi
    if [[ "$value" -gt "$MAX_SLEEP_SECONDS" ]]; then
        printf '%s\n' "$MAX_SLEEP_SECONDS"
        return
    fi
    printf '%s\n' "$value"
}

sleep_with_heartbeat() {
    local total_seconds="$1"
    local reason="$2"
    local remaining="$total_seconds"

    if [[ "$HEARTBEAT_SECONDS" -le 0 ]]; then
        sleep "$remaining"
        return
    fi

    while [[ "$remaining" -gt 0 ]]; do
        local chunk="$remaining"
        if [[ "$chunk" -gt "$HEARTBEAT_SECONDS" ]]; then
            chunk="$HEARTBEAT_SECONDS"
        fi

        sleep "$chunk"
        remaining=$((remaining - chunk))

        if [[ "$remaining" -gt 0 ]]; then
            echo "openshell-agent: still waiting ($reason); next cycle in ${remaining}s" >&2
        fi
    done
}

active_cycle_heartbeat() {
    local active_cycle="$1"
    local elapsed=0
    local sleep_pid=""

    trap 'if [[ -n "${sleep_pid:-}" ]]; then kill "$sleep_pid" 2>/dev/null || true; wait "$sleep_pid" 2>/dev/null || true; fi; exit 0' TERM INT EXIT

    while true; do
        sleep "$HEARTBEAT_SECONDS" &
        sleep_pid=$!
        wait "$sleep_pid" || exit 0
        sleep_pid=""
        elapsed=$((elapsed + HEARTBEAT_SECONDS))
        echo "openshell-agent: still running $RUN_MODE cycle $active_cycle with harness $OPENSHELL_AGENT_HARNESS after ${elapsed}s" >&2
    done
}

retry_watch_cycle() {
    local reason="$1"
    transient_failures=$((transient_failures + 1))

    if [[ "$MAX_TRANSIENT_FAILURES" -gt 0 ]]; then
        if [[ $((transient_failures % MAX_TRANSIENT_FAILURES)) -eq 0 ]]; then
            echo "openshell-agent: transient watch failure $transient_failures ($reason); still retrying in ${transient_backoff_seconds}s" >&2
        else
            echo "openshell-agent: transient watch failure $transient_failures ($reason); retrying in ${transient_backoff_seconds}s" >&2
        fi
    else
        echo "openshell-agent: transient watch failure $transient_failures ($reason); retrying in ${transient_backoff_seconds}s" >&2
    fi
    sleep_with_heartbeat "$transient_backoff_seconds" "$reason"
    transient_backoff_seconds=$((transient_backoff_seconds * 2))
    cap_transient_backoff
}

cap_transient_backoff() {
    if [[ "$transient_backoff_seconds" -gt "$POLL_INTERVAL_SECONDS" ]]; then
        transient_backoff_seconds="$POLL_INTERVAL_SECONDS"
    fi
    if [[ "$transient_backoff_seconds" -gt "$MAX_SLEEP_SECONDS" ]]; then
        transient_backoff_seconds="$MAX_SLEEP_SECONDS"
    fi
}

run_cycle() {
    local output_file="$1"
    local heartbeat_pid=""

    if [[ "$HEARTBEAT_SECONDS" -gt 0 ]]; then
        active_cycle_heartbeat "$cycle" &
        heartbeat_pid=$!
    fi

    set +e
    bash "$ADAPTER" "$PROMPT_FILE" 2>&1 | tee "$output_file"
    local status=${PIPESTATUS[0]}
    set -e

    if [[ -n "$heartbeat_pid" ]]; then
        kill "$heartbeat_pid" 2>/dev/null || true
        wait "$heartbeat_pid" 2>/dev/null || true
    fi

    return "$status"
}

cycle=0
transient_failures=0
transient_backoff_seconds=30
cap_transient_backoff

while true; do
    cycle=$((cycle + 1))
    echo "openshell-agent: starting $RUN_MODE cycle $cycle with harness $OPENSHELL_AGENT_HARNESS" >&2
    output_file="$(mktemp /tmp/openshell-agent-cycle.XXXXXX)"

    if run_cycle "$output_file"; then
        harness_status=0
    else
        harness_status=$?
    fi

    result_line="$(grep -E '^OPENSHELL_AGENT_RESULT[[:space:]]+' "$output_file" | tail -n 1 || true)"
    result_json="${result_line#OPENSHELL_AGENT_RESULT }"

    if [[ -z "$result_line" ]]; then
        if [[ "$RUN_MODE" == "once" ]]; then
            rm -f "$output_file"
            if [[ "$harness_status" -ne 0 ]]; then
                exit "$harness_status"
            fi
            exit 1
        fi
        retry_reason="missing OPENSHELL_AGENT_RESULT after harness exit $harness_status"
        if classify_transient_failure "$output_file"; then
            retry_reason="$retry_reason; upstream transport failure detected"
        fi
        rm -f "$output_file"
        retry_watch_cycle "$retry_reason"
        continue
    fi

    if ! valid_result_json "$result_json"; then
        rm -f "$output_file"
        if [[ "$RUN_MODE" == "once" ]]; then
            echo "openshell-agent: malformed OPENSHELL_AGENT_RESULT JSON" >&2
            exit 1
        fi
        retry_watch_cycle "malformed OPENSHELL_AGENT_RESULT JSON"
        continue
    fi

    status="$(json_string_field "$result_json" status)"
    reason="$(json_string_field "$result_json" reason)"
    next_poll_seconds="$(json_number_field "$result_json" next_poll_seconds)"
    next_poll_seconds="$(safe_sleep_seconds "$next_poll_seconds")"
    [[ -n "$reason" ]] || reason="unspecified"

    rm -f "$output_file"

    case "$status" in
        complete)
            echo "openshell-agent: complete ($reason)" >&2
            exit 0
            ;;
        waiting|blocked)
            if [[ "$RUN_MODE" == "once" ]]; then
                echo "openshell-agent: $status ($reason)" >&2
                exit 0
            fi
            transient_failures=0
            transient_backoff_seconds=30
            echo "openshell-agent: $status ($reason); sleeping ${next_poll_seconds}s outside harness" >&2
            sleep_with_heartbeat "$next_poll_seconds" "$reason"
            ;;
        transient_failure)
            if [[ "$RUN_MODE" == "once" ]]; then
                echo "openshell-agent: transient failure ($reason)" >&2
                exit 1
            fi
            retry_watch_cycle "$reason"
            ;;
        terminal_failure)
            echo "openshell-agent: terminal failure ($reason)" >&2
            exit 1
            ;;
        *)
            if [[ "$RUN_MODE" == "once" ]]; then
                echo "openshell-agent: invalid OPENSHELL_AGENT_RESULT status: ${status:-<missing>}" >&2
                exit 1
            fi
            retry_watch_cycle "invalid OPENSHELL_AGENT_RESULT status: ${status:-<missing>}"
            ;;
    esac
done
