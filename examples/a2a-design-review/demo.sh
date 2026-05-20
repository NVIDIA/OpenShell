#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENSHELL_BIN="${OPENSHELL_BIN:-openshell}"
DEMO_RUN_ID="${DEMO_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
DEMO_ROUNDS="${DEMO_ROUNDS:-2}"
DEMO_LOCAL_ONLY="${DEMO_LOCAL_ONLY:-0}"
DEMO_KEEP_SANDBOXES="${DEMO_KEEP_SANDBOXES:-0}"
DEMO_REPO="${DEMO_REPO:-NVIDIA/OpenShell}"
DEMO_OUTPUT="${DEMO_OUTPUT:-${SCRIPT_DIR}/design-review-${DEMO_RUN_ID}.md}"

ROLES=(planner security implementation critic)
LOCAL_PORTS=(18081 18082 18083 18084)

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-a2a-design-review.XXXXXX")"
PAYLOAD_DIR="${TMP_DIR}/payload"
LOG_DIR="${TMP_DIR}/logs"
mkdir -p "$PAYLOAD_DIR" "$LOG_DIR"

BOLD='\033[1m'
CYAN='\033[36m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
RESET='\033[0m'

PIDS=()
SANDBOXES=()

step() {
    printf "\n${BOLD}${CYAN}==> %s${RESET}\n\n" "$1"
}

info() {
    printf "  %b\n" "$*"
}

fail() {
    printf "\n${RED}error:${RESET} %s\n" "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done

    if [[ "$DEMO_LOCAL_ONLY" != "1" && "$DEMO_KEEP_SANDBOXES" != "1" ]]; then
        for sandbox in "${SANDBOXES[@]:-}"; do
            "$OPENSHELL_BIN" sandbox delete "$sandbox" >/dev/null 2>&1 || true
        done
    fi

    if [[ $status -eq 0 ]]; then
        rm -rf "$TMP_DIR"
    else
        printf "\n${YELLOW}Logs kept at: %s${RESET}\n" "$LOG_DIR"
    fi
}
trap cleanup EXIT

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

prepare_payload() {
    cp "${SCRIPT_DIR}/a2a-agent.mjs" "${PAYLOAD_DIR}/a2a-agent.mjs"
}

issue_args() {
    if [[ -n "${DEMO_ISSUE_URL:-}" ]]; then
        printf '%s\n' "--issue-url" "$DEMO_ISSUE_URL"
    elif [[ "${DEMO_USE_SAMPLE_ISSUE:-1}" == "1" ]]; then
        printf '%s\n' "--issue-file" "${SCRIPT_DIR}/sample-issue.json"
    else
        printf '%s\n' "--repo" "$DEMO_REPO"
    fi
}

run_orchestrator() {
    local -a agent_args=("$@")
    local -a issue
    mapfile -t issue < <(issue_args)

    node "${SCRIPT_DIR}/orchestrator.mjs" \
        "${issue[@]}" \
        --rounds "$DEMO_ROUNDS" \
        --output "$DEMO_OUTPUT" \
        "${agent_args[@]}"
}

wait_for_http() {
    local url="$1"
    local label="$2"
    for _ in $(seq 1 60); do
        if curl -fsS "${url}/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    fail "${label} did not become healthy at ${url}"
}

run_local() {
    local -a agent_args=()

    step "Starting local A2A agents"
    for i in "${!ROLES[@]}"; do
        local role="${ROLES[$i]}"
        local port="${LOCAL_PORTS[$i]}"
        node "${SCRIPT_DIR}/a2a-agent.mjs" --role "$role" --host 127.0.0.1 --port "$port" \
            >"${LOG_DIR}/${role}.log" 2>&1 &
        PIDS+=("$!")
        local url="http://127.0.0.1:${port}"
        wait_for_http "$url" "$role"
        agent_args+=(--agent "${role}=${url}")
        info "${role} listening at ${url}"
    done

    step "Running A2A design review"
    run_orchestrator "${agent_args[@]}"
}

wait_for_sandbox() {
    local name="$1"
    for _ in $(seq 1 90); do
        if "$OPENSHELL_BIN" sandbox get "$name" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail "sandbox ${name} did not become visible"
}

expose_service() {
    local name="$1"
    local role="$2"
    local output url

    for _ in $(seq 1 60); do
        if output="$(NO_COLOR=1 "$OPENSHELL_BIN" service expose "$name" 8080 "$role" 2>&1)"; then
            url="$(printf '%s\n' "$output" | sed -n 's/^  URL: //p' | tail -1)"
            [[ -n "$url" ]] || fail "service expose for ${name}/${role} did not print a URL"
            printf '%s\n' "$url"
            return 0
        fi
        sleep 1
    done

    printf '%s\n' "$output" >&2
    fail "failed to expose ${role} service on ${name}"
}

run_openshell() {
    local -a agent_args=()

    require_command "$OPENSHELL_BIN"
    require_command curl
    "$OPENSHELL_BIN" status >/dev/null 2>&1 || fail "OpenShell gateway is not reachable; run: mise run gateway:docker"
    "$OPENSHELL_BIN" sandbox list >/dev/null 2>&1 || fail "OpenShell sandbox API is not healthy; restart the gateway and confirm 'openshell sandbox list' works"

    prepare_payload

    step "Starting A2A agents in OpenShell sandboxes"
    for role in "${ROLES[@]}"; do
        local name="a2a-review-${DEMO_RUN_ID}-${role}"
        SANDBOXES+=("$name")
        "$OPENSHELL_BIN" sandbox delete "$name" >/dev/null 2>&1 || true
        "$OPENSHELL_BIN" sandbox create \
            --name "$name" \
            --from base \
            --policy "${SCRIPT_DIR}/policy.yaml" \
            --upload "${PAYLOAD_DIR}:/sandbox" \
            --no-tty \
            -- node /sandbox/payload/a2a-agent.mjs --role "$role" --host 127.0.0.1 --port 8080 \
            >"${LOG_DIR}/${role}.log" 2>&1 &
        PIDS+=("$!")
        wait_for_sandbox "$name"
        info "started ${role} sandbox ${name}"
    done

    step "Exposing A2A services through the gateway"
    for i in "${!ROLES[@]}"; do
        local role="${ROLES[$i]}"
        local name="${SANDBOXES[$i]}"
        local url
        url="$(expose_service "$name" "$role")"
        wait_for_http "$url" "${role} service"
        agent_args+=(--agent "${role}=${url}")
        info "${role} Agent Card: ${url}/.well-known/agent-card.json"
    done

    step "Running A2A design review"
    run_orchestrator "${agent_args[@]}"
}

main() {
    require_command node

    if [[ "$DEMO_LOCAL_ONLY" == "1" ]]; then
        run_local
    else
        run_openshell
    fi

    printf "\n${BOLD}${GREEN}Demo complete.${RESET}\n"
    printf "  Review artifact: %s\n" "$DEMO_OUTPUT"
}

main "$@"
