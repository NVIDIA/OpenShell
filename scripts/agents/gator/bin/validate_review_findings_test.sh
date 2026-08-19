#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATOR="$SCRIPT_DIR/validate-review-findings"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/findings.json" <<'JSON'
{
  "schema_version": 1,
  "reviewed_head_sha": "2222222222222222222222222222222222222222",
  "review_mode": "follow_up",
  "findings": [
    {
      "id": "GATOR-22222222-01",
      "severity": "Warning",
      "invariant": "Workspace authorization is checked before lookup.",
      "attacker_or_operator_prerequisite": "A user can name another workspace.",
      "supported_entry_point": "GET /workspaces/{name}",
      "sink": "workspace record lookup",
      "changed_location": {"path": "server.rs", "line": 42},
      "base_behavior": "The route rejected cross-workspace names.",
      "head_behavior": "The route performs the lookup first.",
      "observable_impact": "Workspace existence is disclosed.",
      "reproducer": "Request another workspace and assert 404 without lookup.",
      "pr_ownership": "The changed handler reordered the authorization check.",
      "requested_change": "Restore authorization before lookup.",
      "scope": "latest_delta"
    },
    {
      "id": "GATOR-22222222-02",
      "severity": "Critical",
      "invariant": "Credentials remain endpoint-bound.",
      "attacker_or_operator_prerequisite": "A sandbox controls the destination.",
      "supported_entry_point": "CONNECT",
      "sink": "credential injection",
      "changed_location": {"path": "proxy.rs", "line": 90},
      "base_behavior": "Credentials were endpoint-bound.",
      "head_behavior": "Credentials can reach a mismatched authority.",
      "observable_impact": "Credential disclosure.",
      "pr_ownership": "The latest delta changed authority selection.",
      "requested_change": "Bind injection to the canonical authority.",
      "scope": "latest_delta"
    },
    {
      "id": "GATOR-22222222-03",
      "severity": "Suggestion",
      "invariant": "Names remain concise.",
      "scope": "latest_delta"
    },
    {
      "id": "GATOR-22222222-04",
      "severity": "Warning",
      "invariant": "Workspace authorization is checked before lookup.",
      "attacker_or_operator_prerequisite": "A user can name another workspace.",
      "supported_entry_point": "GET /workspaces/{name}",
      "sink": "workspace record lookup",
      "changed_location": {"path": "other.rs", "line": 7},
      "base_behavior": "The route rejected cross-workspace names.",
      "head_behavior": "The route performs the lookup first.",
      "observable_impact": "Workspace existence is disclosed.",
      "reproducer": "Request another workspace and assert 404 without lookup.",
      "pr_ownership": "The changed handler reordered the authorization check.",
      "requested_change": "Restore authorization before lookup.",
      "scope": "latest_delta"
    }
  ]
}
JSON

"$VALIDATOR" "$tmp/findings.json" > "$tmp/normalized.json"

jq -e '
  .findings[0].blocking == true and
  .findings[0].classification == "blocker" and
  .findings[1].blocking == false and
  .findings[1].classification == "hypothesis" and
  (.findings[1].validation_errors | index("reproducer")) != null and
  .findings[2].blocking == false and
  .findings[2].classification == "suggestion" and
  .findings[3].blocking == false and
  .findings[3].classification == "hypothesis" and
  (.findings[3].validation_errors | index("duplicate_invariant")) != null and
  .telemetry.blockers == 1 and
  .telemetry.hypotheses == 2 and
  .telemetry.suggestions == 1 and
  .telemetry.duplicate_invariant_proposals == 1 and
  .telemetry.blockers_lacking_reproducer == 1
' "$tmp/normalized.json" >/dev/null

jq '.reviewed_head_sha = "short"' "$tmp/findings.json" > "$tmp/invalid.json"
if "$VALIDATOR" "$tmp/invalid.json" >/dev/null 2>&1; then
    echo "FAIL: malformed envelope passed validation" >&2
    exit 1
fi

printf 'PASS: gator review finding schema tests\n'
