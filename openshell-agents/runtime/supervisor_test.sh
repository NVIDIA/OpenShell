#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SUPERVISOR_UNDER_TEST="${SUPERVISOR_UNDER_TEST:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/supervisor.sh}"

fail() {
    printf 'not ok - %s\n' "$*" >&2
    exit 1
}

assert_contains() {
    local file="$1"
    local expected="$2"
    if ! grep -Fq "$expected" "$file"; then
        printf 'missing expected text: %s\n' "$expected" >&2
        printf '%s\n' '--- output ---' >&2
        sed -n '1,200p' "$file" >&2
        fail "assert_contains failed"
    fi
}

make_payload() {
    local dir="$1"
    local adapter_body="$2"

    mkdir -p "$dir/runtime/harnesses/test"
    printf 'test prompt\n' > "$dir/agent-prompt.md"
    cat > "$dir/runtime/harnesses/test/exec.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
$adapter_body
EOF
    chmod +x "$dir/runtime/harnesses/test/exec.sh"
}

run_supervisor() {
    local payload_dir="$1"
    local mode="$2"
    local output_file="$3"

    set +e
    OPENSHELL_AGENT_PAYLOAD_DIR="$payload_dir" \
        OPENSHELL_AGENT_HARNESS=test \
        OPENSHELL_AGENT_RUN_MODE="$mode" \
        OPENSHELL_AGENT_POLL_INTERVAL_SECONDS=1 \
        OPENSHELL_AGENT_MAX_TRANSIENT_FAILURES=2 \
        OPENSHELL_AGENT_TEST_STATE="${OPENSHELL_AGENT_TEST_STATE:-}" \
        bash "$SUPERVISOR_UNDER_TEST" > "$output_file" 2>&1
    local status=$?
    set -e
    return "$status"
}

test_once_requires_sentinel() {
    local tmp
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" "exit 0"

    if run_supervisor "$tmp/payload" once "$tmp/output"; then
        fail "once mode succeeded without sentinel"
    fi
    printf 'ok - once requires sentinel\n'
}

test_watch_retries_missing_sentinel_until_complete() {
    local tmp
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" '
state_file="${OPENSHELL_AGENT_TEST_STATE:?}"
count=0
if [[ -f "$state_file" ]]; then
    count="$(cat "$state_file")"
fi
count=$((count + 1))
printf "%s\n" "$count" > "$state_file"
if [[ "$count" -lt 3 ]]; then
    printf "%s\n" "ERROR: stream disconnected before completion" >&2
    exit 1
fi
printf "%s\n" "OPENSHELL_AGENT_RESULT {\"status\":\"complete\",\"reason\":\"done\"}"
'

    OPENSHELL_AGENT_TEST_STATE="$tmp/state" run_supervisor "$tmp/payload" watch "$tmp/output"
    assert_contains "$tmp/output" "transient watch failure 1"
    assert_contains "$tmp/output" "transient watch failure 2"
    assert_contains "$tmp/output" "openshell-agent: complete (done)"
    printf 'ok - watch retries missing sentinel until complete\n'
}

test_watch_retries_invalid_status_until_complete() {
    local tmp
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" '
state_file="${OPENSHELL_AGENT_TEST_STATE:?}"
count=0
if [[ -f "$state_file" ]]; then
    count="$(cat "$state_file")"
fi
count=$((count + 1))
printf "%s\n" "$count" > "$state_file"
if [[ "$count" -lt 2 ]]; then
    printf "%s\n" "OPENSHELL_AGENT_RESULT {\"status\":\"nonsense\",\"reason\":\"bad\"}"
    exit 0
fi
printf "%s\n" "OPENSHELL_AGENT_RESULT {\"status\":\"complete\",\"reason\":\"done\"}"
'

    OPENSHELL_AGENT_TEST_STATE="$tmp/state" run_supervisor "$tmp/payload" watch "$tmp/output"
    assert_contains "$tmp/output" "invalid OPENSHELL_AGENT_RESULT status: nonsense"
    assert_contains "$tmp/output" "openshell-agent: complete (done)"
    printf 'ok - watch retries invalid status until complete\n'
}

test_watch_retries_malformed_terminal_json_until_complete() {
    local tmp
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" '
state_file="${OPENSHELL_AGENT_TEST_STATE:?}"
count=0
if [[ -f "$state_file" ]]; then
    count="$(cat "$state_file")"
fi
count=$((count + 1))
printf "%s\n" "$count" > "$state_file"
if [[ "$count" -lt 2 ]]; then
    printf "%s\n" "OPENSHELL_AGENT_RESULT {\"status\":\"complete\""
    exit 0
fi
printf "%s\n" "OPENSHELL_AGENT_RESULT {\"status\":\"complete\",\"reason\":\"done\"}"
'

    OPENSHELL_AGENT_TEST_STATE="$tmp/state" run_supervisor "$tmp/payload" watch "$tmp/output"
    assert_contains "$tmp/output" "malformed OPENSHELL_AGENT_RESULT JSON"
    assert_contains "$tmp/output" "openshell-agent: complete (done)"
    printf 'ok - watch retries malformed terminal JSON until complete\n'
}

test_watch_retries_failed_alias_until_complete() {
    local tmp
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" '
state_file="${OPENSHELL_AGENT_TEST_STATE:?}"
count=0
if [[ -f "$state_file" ]]; then
    count="$(cat "$state_file")"
fi
count=$((count + 1))
printf "%s\n" "$count" > "$state_file"
if [[ "$count" -lt 2 ]]; then
    printf "%s\n" "OPENSHELL_AGENT_RESULT {\"status\":\"failed\",\"reason\":\"legacy\"}"
    exit 0
fi
printf "%s\n" "OPENSHELL_AGENT_RESULT {\"status\":\"complete\",\"reason\":\"done\"}"
'

    OPENSHELL_AGENT_TEST_STATE="$tmp/state" run_supervisor "$tmp/payload" watch "$tmp/output"
    assert_contains "$tmp/output" "invalid OPENSHELL_AGENT_RESULT status: failed"
    assert_contains "$tmp/output" "openshell-agent: complete (done)"
    printf 'ok - watch retries failed alias until complete\n'
}

test_watch_terminal_failure_exits() {
    local tmp
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" 'printf "%s\n" "OPENSHELL_AGENT_RESULT {\"status\":\"terminal_failure\",\"reason\":\"fatal\"}"'

    if run_supervisor "$tmp/payload" watch "$tmp/output"; then
        fail "watch mode succeeded after terminal failure"
    fi
    assert_contains "$tmp/output" "openshell-agent: terminal failure (fatal)"
    printf 'ok - watch terminal failure exits\n'
}

test_once_requires_sentinel
test_watch_retries_missing_sentinel_until_complete
test_watch_retries_invalid_status_until_complete
test_watch_retries_malformed_terminal_json_until_complete
test_watch_retries_failed_alias_until_complete
test_watch_terminal_failure_exits
