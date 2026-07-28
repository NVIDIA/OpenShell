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
                    "body": "> **gator-agent**\n\n**Warning:** Document only paths present in this PR.",
                    "createdAt": "2026-07-28T22:18:17Z",
                    "updatedAt": "2026-07-28T22:18:17Z",
                    "url": "https://example.test/discussion/3669570338",
                    "commit": {
                      "oid": "new-head"
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

"$LEDGER" --input "$tmp/review-threads.json" > "$tmp/ledger.json"

jq -e '
    .schema_version == 1 and
    .pr_author == "drew" and
    (.threads | length) == 2 and
    (
        .threads[]
        | select(.thread_id == "resolved-gator-thread")
        | .is_resolved == true and
          .resolved_by == "drew" and
          .comments[1].body == "This is fine, already have release canaries." and
          .comments[1].reply_to == 3668742319
    ) and
    (
        .threads[]
        | select(.thread_id == "open-gator-thread")
        | .is_resolved == false
    ) and
    (all(.threads[]; .thread_id != "human-only-thread"))
' "$tmp/ledger.json" >/dev/null

printf '{"data":{"repository":{"pullRequest":null}}}\n' > "$tmp/missing-pr.json"
if "$LEDGER" --input "$tmp/missing-pr.json" >/dev/null 2>&1; then
    echo "FAIL: missing PR response produced a valid ledger" >&2
    exit 1
fi

rg -q 'COPY bin/review-feedback-ledger /usr/local/bin/review-feedback-ledger' \
    "$GATOR_DIR/Dockerfile"
rg -q 'review-feedback-ledger NVIDIA OpenShell <pr-number>' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'resolved or explicitly waived finding is a durable review disposition' \
    "$GATOR_DIR/skills/gator-gate/SKILL.md"
rg -q 'review feedback ledger' "$GATOR_DIR/prompts/gator.md"

printf 'PASS: gator review feedback ledger tests\n'
