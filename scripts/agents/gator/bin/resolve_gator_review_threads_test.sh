#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESOLVER="$SCRIPT_DIR/resolve-gator-review-threads"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

cat > "$tmp/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

thread_id=""
previous=""
for arg in "$@"; do
    if [[ "$previous" == "-f" && "$arg" == threadId=* ]]; then
        thread_id="${arg#threadId=}"
    fi
    previous="$arg"
done

printf '%s\n' "$*" >> "${MOCK_GH_LOG:?}"
if [[ "$thread_id" == "${MOCK_FAIL_THREAD:-}" ]]; then
    jq -n --arg id "$thread_id" '{data: {resolveReviewThread: {thread: {id: $id, isResolved: false}}}}'
else
    jq -n --arg id "$thread_id" '{data: {resolveReviewThread: {thread: {id: $id, isResolved: true}}}}'
fi
SH
chmod +x "$tmp/bin/gh"

cat > "$tmp/ledger.json" <<'JSON'
{
  "schema_version": 4,
  "threads": [
    {
      "thread_id": "thread-open",
      "finding_id": "GATOR-11111111-01",
      "is_resolved": false,
      "comments": [{"body": "> **gator-agent**\n\nOpen finding"}]
    },
    {
      "thread_id": "thread-resolved",
      "finding_id": "GATOR-11111111-02",
      "is_resolved": true,
      "comments": [{"body": "> **gator-agent**\n\nResolved finding"}]
    },
    {
      "thread_id": "thread-legacy",
      "finding_id": "gator-inline-1234",
      "is_resolved": false,
      "comments": [{"body": "> **gator-agent**\n\nLegacy finding"}]
    },
    {
      "thread_id": "thread-human",
      "finding_id": "GATOR-22222222-01",
      "is_resolved": false,
      "comments": [{"body": "Human review thread"}]
    }
  ]
}
JSON

export MOCK_GH_LOG="$tmp/gh.log"
PATH="$tmp/bin:$PATH" "$RESOLVER" "$tmp/ledger.json" \
    GATOR-11111111-01 GATOR-11111111-02 gator-inline-1234 \
    > "$tmp/success.out"

[[ "$(grep -c 'threadId=thread-' "$tmp/gh.log")" -eq 2 ]]
grep -q 'ResolveGatorReviewThread' "$tmp/gh.log"
grep -q 'threadId=thread-open' "$tmp/gh.log"
grep -q 'threadId=thread-legacy' "$tmp/gh.log"
grep -q 'already resolved: GATOR-11111111-02' "$tmp/success.out"

if PATH="$tmp/bin:$PATH" "$RESOLVER" "$tmp/ledger.json" GATOR-33333333-01 >/dev/null 2>&1; then
    echo "expected unknown finding ID to fail" >&2
    exit 1
fi

if PATH="$tmp/bin:$PATH" "$RESOLVER" "$tmp/ledger.json" GATOR-22222222-01 >/dev/null 2>&1; then
    echo "expected human-owned thread resolution to fail" >&2
    exit 1
fi

if MOCK_FAIL_THREAD=thread-open PATH="$tmp/bin:$PATH" \
    "$RESOLVER" "$tmp/ledger.json" GATOR-11111111-01 >/dev/null 2>&1; then
    echo "expected unconfirmed GitHub resolution to fail" >&2
    exit 1
fi

ruby -ryaml -e '
  profile = YAML.load_file(ARGV.fetch(0))
  endpoint = profile.fetch("endpoints").find {
    |entry| entry["path"] == "/graphql"
  }
  abort unless endpoint.fetch("rules").any? {
    |rule|
    allow = rule["allow"]
    allow &&
      allow["operation_type"] == "mutation" &&
      allow["operation_name"] == "ResolveGatorReviewThread" &&
      allow["fields"] == ["resolveReviewThread"]
  }
' "$GATOR_DIR/providers/github-gator.yaml"

echo "resolve-gator-review-threads tests passed"
