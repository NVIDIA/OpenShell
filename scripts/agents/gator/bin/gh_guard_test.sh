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
    local current_is_draft="${3:-false}"
    local lookup_failure="${4:-}"
    export MOCK_EXISTING_BODY="$existing_body"
    export MOCK_CURRENT_IS_DRAFT="$current_is_draft"
    export MOCK_LOOKUP_FAILURE="$lookup_failure"

    cat > "$dir/mock-gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >> "$MOCK_GH_LOG"

if [[ "$1" == "api" && "$2" == "repos/NVIDIA/OpenShell/pulls/1865" ]]; then
    [[ "$MOCK_LOOKUP_FAILURE" != "pull" ]] || exit 1
    jq -n --arg sha '0e4d7af7722fbedce2307d571b0c937a1eb3250f' --argjson draft "$MOCK_CURRENT_IS_DRAFT" '{head:{sha:$sha},draft:$draft}'
    exit 0
fi

if [[ "$1" == "api" && "$2" == "repos/NVIDIA/OpenShell/issues/1865/comments" ]]; then
    [[ "$MOCK_LOOKUP_FAILURE" != "comments" ]] || exit 1
    if [[ -n "$MOCK_EXISTING_BODY" ]]; then
        jq -Rn --arg body "$MOCK_EXISTING_BODY" '$body'
    fi
    exit 0
fi

if [[ "$1" == "api" && "$2" == "repos/NVIDIA/OpenShell/pulls/1865/reviews" ]]; then
    [[ "$MOCK_LOOKUP_FAILURE" != "reviews" ]] || exit 1
    exit 0
fi

if [[ "$1" == "api" && "$*" == *"repos/NVIDIA/OpenShell/pulls/1865/reviews"* ]]; then
    printf '%s\n' 'review posted'
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
    local current_is_draft="${5:-false}"
    local lookup_failure="${6:-}"

    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    export MOCK_GH_LOG="$tmp/gh.log"
    make_mock_gh "$tmp" "$existing_body" "$current_is_draft" "$lookup_failure"

    printf '{"body":%s}\n' "$(jq -Rn --arg body "$post_body" '$body')" > "$tmp/body.json"

    set +e
    OPENSHELL_REAL_GH="$tmp/mock-gh" "$WRAPPER" api --method POST repos/NVIDIA/OpenShell/issues/1865/comments --input "$tmp/body.json" >/tmp/gh-wrapper-test.out 2>/tmp/gh-wrapper-test.err
    local status=$?
    set -e

    assert_status "$expected_status" "$status" "$name"
    rm -rf "$tmp"
    trap - RETURN
}

run_review_case() {
    local name="$1"
    local existing_body="$2"
    local expected_status="$3"

    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    export MOCK_GH_LOG="$tmp/gh.log"
    make_mock_gh "$tmp" "$existing_body"

    jq -n \
        --arg body '> **gator-agent**

## PR Review Status

The review is ready for author follow-up.

<details>
<summary>Gator metadata</summary>

- Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`' \
        --arg payload '- Gator payload: `5`

</details>' \
        --arg inline_body '> **gator-agent**

**Warning:** Keep this validation bound to the accepted value.' \
        '{
            event: "COMMENT",
            body: ($body + "\n" + $payload),
            comments: [{
                path: "crates/example/src/lib.rs",
                line: 42,
                side: "RIGHT",
                body: $inline_body
            }]
        }' > "$tmp/review.json"

    set +e
    OPENSHELL_REAL_GH="$tmp/mock-gh" "$WRAPPER" api --method POST repos/NVIDIA/OpenShell/pulls/1865/reviews --input "$tmp/review.json" >/tmp/gh-wrapper-test.out 2>/tmp/gh-wrapper-test.err
    local status=$?
    set -e

    assert_status "$expected_status" "$status" "$name"
    rm -rf "$tmp"
    trap - RETURN
}

same_sha_body='> **gator-agent**

## PR Review Status

Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`
Gator payload: `5`'

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

## Follow-Up Needed' \
    0

run_case "allows first versioned review disposition" \
    '' \
    '> **gator-agent**

## PR Review Status

Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`
Gator payload: `5`' \
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

run_case "allows a same-SHA author nudge" \
    "$same_sha_body" \
    '> **gator-agent**

## Author Follow-Up Nudge

This PR has been in `gator:in-review` for more than 48 business hours with unresolved review feedback.

@author, please respond to the review comments or push an update.' \
    0

run_case "blocks a same-SHA status comment that is not a TTL nudge" \
    "$same_sha_body" \
    '> **gator-agent**

## CI Update

Checks completed for the current head.' \
    20

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

Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`
Gator payload: `5`' \
    0

draft_blocked_body='> **gator-agent**

## Blocked

Gator is blocked because PR #1865 is still marked as a draft.

Next action: @author, mark the pull request ready for review.

Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`'

run_case "ignores draft blocker after PR is ready" \
    "$draft_blocked_body" \
    '> **gator-agent**

## PR Review Status

Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`
Gator payload: `5`' \
    0 \
    false

run_case "blocks duplicate draft blocker while PR remains draft" \
    "$draft_blocked_body" \
    '> **gator-agent**

## Blocked

Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`' \
    20 \
    true

run_review_case "allows first batched inline review as one disposition" \
    '' \
    0

run_review_case "blocks a later batched inline review for the same SHA" \
    "$same_sha_body" \
    20

run_case "rejects an unversioned review disposition" \
    '' \
    '> **gator-agent**

## PR Review Status

Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`' \
    22

run_case "fails closed when comment history lookup fails" \
    '' \
    '> **gator-agent**

## PR Review Status

Head SHA: `0e4d7af7722fbedce2307d571b0c937a1eb3250f`
Gator payload: `2`' \
    21 \
    false \
    comments

printf 'PASS: gh same-SHA guard tests\n'
