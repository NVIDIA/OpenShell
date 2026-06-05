#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || { echo "missing required env: $name" >&2; exit 1; }
}

require_env OPENSHELL_AGENT_HARNESS

PROMPT_FILE="${OPENSHELL_AGENT_PROMPT:-/sandbox/payload/agent-prompt.md}"
ADAPTER="/sandbox/payload/runtime/harnesses/$OPENSHELL_AGENT_HARNESS/exec.sh"
RUN_MODE="${OPENSHELL_AGENT_RUN_MODE:-once}"
POLL_INTERVAL_SECONDS="${OPENSHELL_AGENT_POLL_INTERVAL_SECONDS:-900}"
MAX_TRANSIENT_FAILURES="${OPENSHELL_AGENT_MAX_TRANSIENT_FAILURES:-5}"

[[ -f "$PROMPT_FILE" ]] || { echo "missing agent prompt: $PROMPT_FILE" >&2; exit 1; }
[[ -x "$ADAPTER" ]] || { echo "missing harness adapter: $ADAPTER" >&2; exit 1; }

case "$RUN_MODE" in
    once|watch) ;;
    *) echo "unsupported agent run mode: $RUN_MODE" >&2; exit 2 ;;
esac
[[ "$POLL_INTERVAL_SECONDS" =~ ^[0-9]+$ ]] || { echo "OPENSHELL_AGENT_POLL_INTERVAL_SECONDS must be an integer" >&2; exit 2; }
[[ "$MAX_TRANSIENT_FAILURES" =~ ^[0-9]+$ ]] || { echo "OPENSHELL_AGENT_MAX_TRANSIENT_FAILURES must be an integer" >&2; exit 2; }
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

classify_transient_failure() {
    local output_file="$1"
    grep -Eiq 'stream disconnected before completion|failed to connect to websocket|Reconnecting\.\.\.|Broken pipe|Connection to sandbox closed by remote host|peer closed connection without sending TLS close_notify' "$output_file"
}

run_cycle() {
    local output_file="$1"

    set +e
    bash "$ADAPTER" "$PROMPT_FILE" 2>&1 | tee "$output_file"
    local status=${PIPESTATUS[0]}
    set -e

    return "$status"
}

cycle=0
transient_failures=0
transient_backoff_seconds=30

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
            exit "$harness_status"
        fi
        if [[ "$harness_status" -ne 0 ]] && classify_transient_failure "$output_file" && [[ "$transient_failures" -lt "$MAX_TRANSIENT_FAILURES" ]]; then
            transient_failures=$((transient_failures + 1))
            echo "openshell-agent: transient harness failure $transient_failures/$MAX_TRANSIENT_FAILURES; retrying in ${transient_backoff_seconds}s" >&2
            rm -f "$output_file"
            sleep "$transient_backoff_seconds"
            transient_backoff_seconds=$((transient_backoff_seconds * 2))
            if [[ "$transient_backoff_seconds" -gt "$POLL_INTERVAL_SECONDS" ]]; then
                transient_backoff_seconds="$POLL_INTERVAL_SECONDS"
            fi
            continue
        fi
        echo "openshell-agent: watch-mode harness exited without OPENSHELL_AGENT_RESULT" >&2
        rm -f "$output_file"
        if [[ "$harness_status" -ne 0 ]]; then
            exit "$harness_status"
        fi
        exit 1
    fi

    status="$(json_string_field "$result_json" status)"
    reason="$(json_string_field "$result_json" reason)"
    next_poll_seconds="$(json_number_field "$result_json" next_poll_seconds)"
    [[ -n "$next_poll_seconds" ]] || next_poll_seconds="$POLL_INTERVAL_SECONDS"
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
            sleep "$next_poll_seconds"
            ;;
        transient_failure)
            if [[ "$transient_failures" -ge "$MAX_TRANSIENT_FAILURES" ]]; then
                echo "openshell-agent: transient failure limit reached ($reason)" >&2
                exit 1
            fi
            transient_failures=$((transient_failures + 1))
            echo "openshell-agent: transient failure $transient_failures/$MAX_TRANSIENT_FAILURES ($reason); retrying in ${transient_backoff_seconds}s" >&2
            sleep "$transient_backoff_seconds"
            transient_backoff_seconds=$((transient_backoff_seconds * 2))
            if [[ "$transient_backoff_seconds" -gt "$POLL_INTERVAL_SECONDS" ]]; then
                transient_backoff_seconds="$POLL_INTERVAL_SECONDS"
            fi
            ;;
        terminal_failure|failed|failure)
            echo "openshell-agent: terminal failure ($reason)" >&2
            exit 1
            ;;
        *)
            echo "openshell-agent: invalid OPENSHELL_AGENT_RESULT status: ${status:-<missing>}" >&2
            exit 1
            ;;
    esac
done
