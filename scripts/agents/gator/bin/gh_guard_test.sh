#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRAPPER="$SCRIPT_DIR/gh"

assert_status() {
    local expected="$1"
    local actual="$2"
    local name="$3"

    if [[ "$actual" -ne "$expected" ]]; then
        printf 'FAIL: %s: expected status %s, got %s\n' "$name" "$expected" "$actual" >&2
        exit 1
    fi
}

make_mock_gh() {
    local dir="$1"
    local existing_body="$2"
    export MOCK_EXISTING_BODY="$existing_body"

    cat > "$dir/mock-gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >> "$MOCK_GH_LOG"

if [[ "$1" == "api" && "$2" == "repos/NVIDIA/OpenShell/pulls/1865" ]]; then
    printf '%s\n' '0e4d7af7722fbedce2307d571b0c937a1eb3250f'
    exit 0
fi

if [[ "$1" == "api" && "$2" == "repos/NVIDIA/OpenShell/issues/1865/comments" ]]; then
    if [[ -n "$MOCK_EXISTING_BODY" ]]; then
        jq -Rn --arg body "$MOCK_EXISTING_BODY" '$body'
    fi
    exit 0
fi

if [[ "$1" == "api" && "$2" == "repos/NVIDIA/OpenShell/pulls/1865/reviews" ]]; then
    exit 0
fi

if [[ "$1" == "api" && "$*" == *"repos/NVIDIA/OpenShell/issues/1865/comments"* ]]; then
    printf '%s\n' 'posted'
    exit 0
fi

printf '%s\n' 'unhandled mock-gh call' >&2
exit 2
MOCK
    chmod +x "$dir/mock-gh"
}

run_case() {
    local name="$1"
    local existing_body="$2"
    local post_body="$3"
    local expected_status="$4"

    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    export MOCK_GH_LOG="$tmp/gh.log"
    make_mock_gh "$tmp" "$existing_body"

    printf '{"body":%s}\n' "$(jq -Rn --arg body "$post_body" '$body')" > "$tmp/body.json"

    set +e
    OPENSHELL_REAL_GH="$tmp/mock-gh" "$WRAPPER" api --method POST repos/NVIDIA/OpenShell/issues/1865/comments --input "$tmp/body.json" >/tmp/gh-wrapper-test.out 2>/tmp/gh-wrapper-test.err
    local status=$?
    set -e

    assert_status "$expected_status" "$status" "$name"
    rm -rf "$tmp"
    trap - RETURN
}

same_sha_body='> **gator-agent**

## PR Review Status

Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`'

run_case "blocks duplicate marked comment" \
    "$same_sha_body" \
    '> **gator-agent**

## Re-check After CI Update' \
    20

run_case "allows first marked comment" \
    '> **gator-agent**

## PR Review Status

Head SHA: `different-sha`' \
    '> **gator-agent**

## PR Review Status' \
    0

run_case "allows unmarked comment" \
    "$same_sha_body" \
    '/ok to test 0e4d7af7722fbedce2307d571b0c937a1eb3250f' \
    0

run_case "allows terminal cleanup" \
    "$same_sha_body" \
    '> **gator-agent**

## Monitoring Complete' \
    0

run_case "blocks new reviewer failure disposition" \
    '' \
    '> **gator-agent**

## Blocked

Gator is blocked from completing the required independent re-review for current head `0e4d7af7722fbedce2307d571b0c937a1eb3250f` because the `principal-engineer-reviewer` sub-agent failed before producing a review result due to a Codex token refresh/authentication error.' \
    20

run_case "ignores legacy reviewer failure disposition" \
    '> **gator-agent**

## Blocked

Gator is blocked from completing the required independent re-review for current head `0e4d7af7722fbedce2307d571b0c937a1eb3250f` because the `principal-engineer-reviewer` sub-agent failed before producing a review result due to a Codex token refresh/authentication error.' \
    '> **gator-agent**

## PR Review Status

Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`' \
    0

printf 'PASS: gh same-SHA guard tests\n'
