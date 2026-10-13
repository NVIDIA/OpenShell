#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LEDGER="$SCRIPT_DIR/review-feedback-ledger"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/review-threads.json" <<'JSON'
{
  "data": {
    "repository": {
      "pullRequest": {
        "author": {
          "login": "drew"
        },
        "headRefOid": "2222222222222222222222222222222222222222",
        "baseRefOid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "reviewThreads": {
          "nodes": [
            {
              "id": "resolved-gator-thread",
              "isResolved": true,
              "isOutdated": false,
              "path": "tasks/scripts/package-deb.sh",
              "line": 170,
              "resolvedBy": {
                "login": "drew"
              },
              "comments": {
                "nodes": [
                  {
                    "databaseId": 3668742319,
                    "author": {
                      "login": "drew"
                    },
                    "authorAssociation": "MEMBER",
                    "body": "> **gator-agent**\n\n**Warning:** Keep the package smoke test.",
                    "createdAt": "2026-07-28T19:53:23Z",
                    "updatedAt": "2026-07-28T19:53:23Z",
                    "url": "https://example.test/discussion/3668742319",
                    "commit": {
                      "oid": "old-head"
                    },
                    "pullRequestReview": {
                      "id": "review-node-1"
                    },
                    "replyTo": null
                  },
                  {
                    "databaseId": 3668793967,
                    "author": {
                      "login": "drew"
                    },
                    "authorAssociation": "MEMBER",
                    "body": "This is fine, already have release canaries.",
                    "createdAt": "2026-07-28T20:02:11Z",
                    "updatedAt": "2026-07-28T20:02:12Z",
                    "url": "https://example.test/discussion/3668793967",
                    "commit": {
                      "oid": "old-head"
                    },
                    "pullRequestReview": {
                      "id": "review-node-1"
                    },
                    "replyTo": {
                      "databaseId": 3668742319
                    }
                  }
                ]
              }
            },
            {
              "id": "open-gator-thread",
              "isResolved": false,
              "isOutdated": false,
              "path": "nix/test-guest/README.md",
              "line": 66,
              "resolvedBy": null,
              "comments": {
                "nodes": [
                  {
                    "databaseId": 3669570338,
                    "author": {
                      "login": "drew"
                    },
                    "authorAssociation": "MEMBER",
                    "body": "> **gator-agent**\n\n**Warning — GATOR-11111111-03:** Document only paths present in this PR.",
                    "createdAt": "2026-07-28T22:18:17Z",
                    "updatedAt": "2026-07-28T22:18:17Z",
                    "url": "https://example.test/discussion/3669570338",
                    "commit": {
                      "oid": "new-head"
                    },
                    "pullRequestReview": {
                      "id": "review-node-1"
                    },
                    "replyTo": null
                  }
                ]
              }
            },
            {
              "id": "human-only-thread",
              "isResolved": true,
              "isOutdated": false,
              "path": "README.md",
              "line": 1,
              "resolvedBy": {
                "login": "drew"
              },
              "comments": {
                "nodes": [
                  {
                    "databaseId": 1,
                    "author": {
                      "login": "reviewer"
                    },
                    "authorAssociation": "MEMBER",
                    "body": "This is an ordinary human review thread.",
                    "createdAt": "2026-07-28T18:00:00Z",
                    "updatedAt": "2026-07-28T18:00:00Z",
                    "url": "https://example.test/discussion/1",
                    "commit": {
                      "oid": "old-head"
                    },
                    "pullRequestReview": null,
                    "replyTo": null
                  }
                ]
              }
            }
          ],
          "pageInfo": {
            "hasNextPage": false,
            "endCursor": null
          }
        }
      }
    }
  }
}
JSON

cat > "$tmp/reviews.json" <<'JSON'
[
  {
    "id": 4801295794,
    "user": {
      "login": "drew"
    },
    "author_association": "MEMBER",
    "body": "> **gator-agent**\n\n## PR Review Status\n\nGeneral findings:\n- Finding ID: GATOR-11111111-01 — Keep package verification.\n\n<details>\n<summary>Gator metadata</summary>\n\n- Head SHA: `1111111111111111111111111111111111111111`\n- Base SHA: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`\n- Merge base SHA: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`\n- Patch ID: `cccccccccccccccccccccccccccccccccccccccc`\n- Gator payload: `2`\n\n</details>",
    "state": "COMMENTED",
    "submitted_at": "2026-07-28T19:53:23Z",
    "commit_id": "1111111111111111111111111111111111111111"
  },
  {
    "id": 4801295795,
    "user": {
      "login": "reviewer"
    },
    "author_association": "MEMBER",
    "body": "Ordinary human review",
    "state": "COMMENTED",
    "submitted_at": "2026-07-28T19:54:23Z",
    "commit_id": "1111111111111111111111111111111111111111"
  }
]
JSON

cat > "$tmp/issue-comments.json" <<'JSON'
[
  {
    "id": 9001,
    "user": {
      "login": "drew"
    },
    "author_association": "MEMBER",
    "body": "> **gator-agent**\n\n## Re-check After Maintainer Update\n\nHead SHA: `1111111111111111111111111111111111111111`\nBase SHA: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`\nMerge base SHA: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`\nPatch ID: `cccccccccccccccccccccccccccccccccccccccc`\nGator payload: `2`\n\nCarried finding: GATOR-11111111-02",
    "created_at": "2026-07-28T20:00:00Z",
    "updated_at": "2026-07-28T20:00:00Z",
    "html_url": "https://example.test/comment/9001"
  },
  {
    "id": 9002,
    "user": {
      "login": "reviewer"
    },
    "author_association": "MEMBER",
    "body": "Ordinary human issue comment",
    "created_at": "2026-07-28T20:01:00Z",
    "updated_at": "2026-07-28T20:01:00Z",
    "html_url": "https://example.test/comment/9002"
  }
]
JSON

jq -n \
  --slurpfile thread_pages "$tmp/review-threads.json" \
  --slurpfile review_pages "$tmp/reviews.json" \
  --slurpfile issue_comment_pages "$tmp/issue-comments.json" \
  '{
    thread_pages: $thread_pages,
    review_pages: $review_pages,
    issue_comment_pages: $issue_comment_pages,
    current_tree: {
      head_sha: "2222222222222222222222222222222222222222",
      base_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      merge_base_sha: "dddddddddddddddddddddddddddddddddddddddd",
      patch_id: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    }
  }' > "$tmp/raw-ledger-input.json"

"$LEDGER" --input "$tmp/raw-ledger-input.json" > "$tmp/ledger.json"

jq -e '
    .schema_version == 4 and
    .pr_author == "drew" and
    .current_head_sha == "2222222222222222222222222222222222222222" and
    .current_base_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
    .current_merge_base_sha == "dddddddddddddddddddddddddddddddddddddddd" and
    .current_patch_id == "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" and
    .last_reviewed_sha == "1111111111111111111111111111111111111111" and
    .last_reviewed_patch_id == "cccccccccccccccccccccccccccccccccccccccc" and
    .review_scope.mode == "follow_up" and
    .review_scope.previous_reviewed_sha == "1111111111111111111111111111111111111111" and
    (.reviews | length) == 1 and
    (.issue_comments | length) == 1 and
    (.dispositions | length) == 2 and
    .reviews[0].finding_ids == ["GATOR-11111111-01"] and
    .reviews[0].payload_version == 2 and
    .issue_comments[0].finding_ids == ["GATOR-11111111-02"] and
    (.reviews[0].summary_body | contains("Keep package verification")) and
    (.threads | length) == 2 and
    (
        .threads[]
        | select(.thread_id == "resolved-gator-thread")
        | .is_resolved == true and
          .resolved_by == "drew" and
          .finding_id == "gator-inline-3668742319" and
          .comments[1].body == "This is fine, already have release canaries." and
          .comments[1].reply_to == 3668742319
    ) and
    (
        .threads[]
        | select(.thread_id == "open-gator-thread")
        | .is_resolved == false and
          .finding_id == "GATOR-11111111-03"
    ) and
    (all(.threads[]; .thread_id != "human-only-thread"))
    and .review_telemetry.review_rounds == 1
    and .review_telemetry.finding_bearing_rounds == 1
    and .review_telemetry.review_budget_exhausted == false
    and (
      .finding_history[]
      | select(.finding_id == "GATOR-11111111-01")
      | .first_seen_head_sha ==
        "1111111111111111111111111111111111111111"
    )
' "$tmp/ledger.json" >/dev/null

jq '
  .review_pages = [] |
  .issue_comment_pages = []
' "$tmp/raw-ledger-input.json" > "$tmp/initial-input.json"
"$LEDGER" --input "$tmp/initial-input.json" > "$tmp/initial-ledger.json"
jq -e '
  .review_scope.mode == "initial" and
  .last_reviewed_sha == null and
  (.dispositions | length) == 0
' "$tmp/initial-ledger.json" >/dev/null

jq '
  .thread_pages[0].data.repository.pullRequest.headRefOid =
    "3333333333333333333333333333333333333333" |
  .current_tree.head_sha = "3333333333333333333333333333333333333333" |
  .current_tree.patch_id = "cccccccccccccccccccccccccccccccccccccccc"
' "$tmp/raw-ledger-input.json" > "$tmp/rebase-equivalent-input.json"
"$LEDGER" --input "$tmp/rebase-equivalent-input.json" \
  > "$tmp/rebase-equivalent-ledger.json"
jq -e '
  .review_scope.mode == "already_reviewed" and
  .review_scope.rebase_equivalent == true and
  .review_telemetry.current_patch_matches_last_review == true
' "$tmp/rebase-equivalent-ledger.json" >/dev/null

jq '
  .review_pages[0] += [
    {
      "id": 4801295796,
      "user": {"login": "drew"},
      "author_association": "MEMBER",
      "body": "> **gator-agent**\n\n## PR Review Status\n\nHead SHA: `1211111111111111111111111111111111111111`\n\nGATOR-12111111-01",
      "state": "COMMENTED",
      "submitted_at": "2026-07-28T20:53:23Z",
      "commit_id": "1211111111111111111111111111111111111111"
    },
    {
      "id": 4801295797,
      "user": {"login": "drew"},
      "author_association": "MEMBER",
      "body": "> **gator-agent**\n\n## PR Review Status\n\nHead SHA: `1311111111111111111111111111111111111111`\n\nGATOR-13111111-01",
      "state": "COMMENTED",
      "submitted_at": "2026-07-28T21:53:23Z",
      "commit_id": "1311111111111111111111111111111111111111"
    }
  ]
' "$tmp/raw-ledger-input.json" > "$tmp/budget-exhausted-input.json"
"$LEDGER" --input "$tmp/budget-exhausted-input.json" \
  > "$tmp/budget-exhausted-ledger.json"
jq -e '
  .review_scope.mode == "critical_only" and
  .review_scope.review_budget_exhausted == true and
  .review_telemetry.finding_bearing_rounds == 3
' "$tmp/budget-exhausted-ledger.json" >/dev/null

jq '
  .thread_pages[0].data.repository.pullRequest.headRefOid =
    "1111111111111111111111111111111111111111"
' "$tmp/raw-ledger-input.json" > "$tmp/already-reviewed-input.json"
"$LEDGER" --input "$tmp/already-reviewed-input.json" \
  > "$tmp/already-reviewed-ledger.json"
jq -e '
  .review_scope.mode == "already_reviewed" and
  .review_scope.current_head_sha ==
    "1111111111111111111111111111111111111111" and
  .review_scope.previous_reviewed_sha ==
    "1111111111111111111111111111111111111111"
' "$tmp/already-reviewed-ledger.json" >/dev/null

printf '{"data":{"repository":{"pullRequest":null}}}\n' > "$tmp/missing-pr.json"
if "$LEDGER" --input "$tmp/missing-pr.json" >/dev/null 2>&1; then
    echo "FAIL: missing PR response produced a valid ledger" >&2
    exit 1
fi

# Exercise live collection against real local Git trees, including a diff
# larger than GitHub's full-diff limit. No PR code is checked out by the helper.
mkdir -p "$tmp/mock-bin" "$tmp/source"
git -C "$tmp/source" init --quiet
git -C "$tmp/source" -c user.name=Test -c user.email=test@example.test \
    commit --quiet --allow-empty -m base
base="$(git -C "$tmp/source" rev-parse HEAD)"
seq 1 30000 > "$tmp/source/schema.json"
git -C "$tmp/source" add schema.json
git -C "$tmp/source" -c user.name=Test -c user.email=test@example.test \
    commit --quiet -m schema
head="$(git -C "$tmp/source" rev-parse HEAD)"
expected_patch="$(git -C "$tmp/source" diff "$base" "$head" | git patch-id --stable | awk '{print $1}')"
jq --arg head "$head" --arg base "$base" '
  .data.repository.pullRequest.headRefOid = $head |
  .data.repository.pullRequest.baseRefOid = $base
' "$tmp/review-threads.json" > "$tmp/live-threads.json"
export LEDGER_TEST_TMP="$tmp" LEDGER_TEST_BASE="$base"
export LEDGER_TEST_REAL_GIT="$(command -v git)"
cat > "$tmp/mock-bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *graphql*) cat "$LEDGER_TEST_TMP/live-threads.json" ;;
  *compare/*) echo "$LEDGER_TEST_BASE" ;;
  *reviews\?*) cat "$LEDGER_TEST_TMP/reviews.json" ;;
  *comments\?*) cat "$LEDGER_TEST_TMP/issue-comments.json" ;;
  *) echo 'unexpected GitHub request (full diffs unavailable)' >&2; exit 1 ;;
esac
SH
cat > "$tmp/mock-bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
args=()
for arg in "$@"; do
  if [[ "$arg" == https://github.com/* ]]; then
    [[ "${LEDGER_TEST_FETCH_FAIL:-0}" != 1 ]] || exit 1
    arg="$LEDGER_TEST_TMP/source"
  fi
  args+=("$arg")
done
exec "$LEDGER_TEST_REAL_GIT" "${args[@]}"
SH
chmod +x "$tmp/mock-bin/gh" "$tmp/mock-bin/git"
PATH="$tmp/mock-bin:$PATH" "$LEDGER" NVIDIA OpenShell 4288 > "$tmp/live-ledger.json"
jq -e --arg patch "$expected_patch" --arg head "$head" '
  .current_patch_id == $patch and .review_scope.current_head_sha == $head
' "$tmp/live-ledger.json" >/dev/null
PATH="$tmp/mock-bin:$PATH" LEDGER_TEST_FETCH_FAIL=1 \
    "$LEDGER" NVIDIA OpenShell 4288 > "$tmp/no-patch-ledger.json"
jq -e '
  .current_patch_id == null and
  .review_scope.rebase_equivalent == false and
  .review_scope.mode != "already_reviewed" and
  (.threads | length) > 0
' "$tmp/no-patch-ledger.json" >/dev/null

rg -q 'COPY bin/review-feedback-ledger /usr/local/bin/review-feedback-ledger' \
  "$GATOR_DIR/Dockerfile"
rg -q 'COPY bin/resolve-gator-review-threads /usr/local/bin/resolve-gator-review-threads' \
  "$GATOR_DIR/Dockerfile"
rg -q 'COPY bin/validate-review-findings /usr/local/bin/validate-review-findings' \
  "$GATOR_DIR/Dockerfile"
ruby -ryaml -e '
  manifest = YAML.load_file(ARGV.fetch(0))
   abort unless manifest.fetch("payload_version") == 12
  resource = manifest.fetch("resources").find {
    |entry| entry.fetch("id") == "gator-review-findings-schema"
  }
  abort unless resource.fetch("destination") ==
    "skills/gator-gate/references/review-findings-schema.md"
' "$GATOR_DIR/agent.yaml"
rg -Fq 'manifest.fetch("resources", [])' "$GATOR_DIR/../run.sh"
rg -Fq 'Gator payload version: {{PAYLOAD_VERSION}}' \
    "$GATOR_DIR/prompts/gator.md"
rg -q 'review-feedback-ledger NVIDIA OpenShell <pr-number>' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'Every prior Gator finding is a durable review disposition' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'review feedback ledger' "$GATOR_DIR/prompts/gator.md"
# Keep security routing consistent across the gate, top-level prompt, and
# independent reviewer; PR-owned regressions must remain actionable reviews.
rg -Fq 'PR in that PR' "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -Fq 'private_security_review_required' "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -Fq 'Do not initiate external disclosure' "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -Fq 'not a generic private-security blocker' "$GATOR_DIR/prompts/gator.md"
rg -Fq 'Security classification alone is not a private-triage gate' \
    "$GATOR_DIR/../../../.claude/agents/principal-engineer-reviewer.md"
rg -q '### Pragmatic review calibration' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'A new commit permits a delta review' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'Suggestions alone do not require' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'available evidence demonstrates a Critical' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'Keep reviews pragmatic and convergent' \
    "$GATOR_DIR/prompts/gator.md"
rg -q '### Pragmatic review calibration' \
    "$GATOR_DIR/../../../.claude/agents/principal-engineer-reviewer.md"
rg -q 'Do not mine unchanged code for new findings' \
    "$GATOR_DIR/../../../.claude/agents/principal-engineer-reviewer.md"
rg -q 'three finding-bearing rounds' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'alone is not a process blocker' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q '`test_dispatch_required`' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'Apply `test:windows` whenever a PR affects Windows support' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'require the `test:windows` label' \
    "$GATOR_DIR/../../../.claude/agents/principal-engineer-reviewer.md"
rg -q 'attacker_or_operator_prerequisite' \
    "$GATOR_DIR/skills/gator-gate/references/review-findings-schema.md"
rg -Fq 'Write `Summary` as natural prose that can be read aloud' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -Fq '<summary>Agent context</summary>' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -Fq '<summary>Gator metadata</summary>' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -Fq 'Those fields validate the finding;' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"

printf 'PASS: gator review feedback ledger tests\n'
