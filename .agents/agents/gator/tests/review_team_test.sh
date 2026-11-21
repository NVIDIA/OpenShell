#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEAM="$GATOR_DIR/bin/review-team"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/review-team-test.XXXXXX")"
trap '[[ -n "${KEEP_TMP:-}" ]] || rm -rf "$tmp"' EXIT

payload="$tmp/payload"
mkdir -p "$payload/skills/gator-gate"
cp -R "$GATOR_DIR/skills/gator-gate/references" "$payload/skills/gator-gate/references"
export OPENSHELL_AGENT_PAYLOAD_DIR="$payload"

head=0123456789abcdef0123456789abcdef01234567
ledger() {
    jq -n --arg mode "$1" --arg head "$head" \
        '{review_scope: {mode: $mode, current_head_sha: $head}, all_finding_ids: []}' > "$tmp/ledger.json"
}
printf '# task\n' > "$tmp/task.md"
cat > "$tmp/plain.diff" <<'EOF'
diff --git a/crates/openshell-server/src/grpc/sandbox.rs b/crates/openshell-server/src/grpc/sandbox.rs
+++ b/crates/openshell-server/src/grpc/sandbox.rs
+    let x = 1;
EOF
cat > "$tmp/net-path.diff" <<'EOF'
diff --git a/crates/openshell-supervisor-network/src/l7/rest.rs b/crates/openshell-supervisor-network/src/l7/rest.rs
+    let x = 1;
EOF
cat > "$tmp/net-content.diff" <<'EOF'
diff --git a/crates/openshell-server/src/lib.rs b/crates/openshell-server/src/lib.rs
+    let s = TcpStream::connect(addr);
EOF

# Fake sub-agent: writes a canned envelope to the path named in its prompt.
# FAKE_FINDINGS lists members that report one finding; FAKE_FAIL lists members
# that always fail; FAKE_MERGE=drop omits one input from the merge report.
cat > "$tmp/fake-subagent" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
id="$1"
prompt="$(cat)"
echo "$id" >> "$FAKE_CALLS"
echo "$id ${OPENSHELL_SUBAGENT_REASONING:-default}" >> "$FAKE_CALLS.reasoning"
[[ " ${FAKE_FAIL:-} " != *" $id "* ]] || exit 1
out="$(sed -nE 's/^Write (your JSON|the merged) envelope to `([^`]*)`.*/\2/p' <<<"$prompt" | head -n 1)"
head="$FAKE_HEAD"
mode="$FAKE_MODE"
if [[ "$id" == review-merge ]]; then
    sources="$(printf '%s\n' "$prompt" |
        awk '/^## Member `/ { gsub(/[#`]/, ""); member = $2 } /"id": "/ && member != "" { match($0, /"id": "[^"]*"/); print member ":" substr($0, RSTART + 7, RLENGTH - 8) }')"
    [[ "${FAKE_MERGE:-}" != drop ]] || sources="$(head -n 1 <<<"$sources")"
    jq -n --arg h "$head" --arg m "$mode" --arg s "$sources" '{
        schema_version: 1, reviewed_head_sha: $h, review_mode: $m,
        findings: [{id: "GATOR-01234567-01", severity: "Warning"}],
        merge_report: {merged: [{id: "GATOR-01234567-01", sources: ($s | split("\n") | map(select(. != "")))}], dropped: []}
    }' > "$out"
    exit 0
fi
if [[ " ${FAKE_FINDINGS:-} " == *" $id "* ]]; then
    findings="[{\"id\": \"$id-01\", \"severity\": \"Warning\"}]"
else
    findings='[]'
fi
extra='{}'
if [[ "$id" != principal-engineer-reviewer && " ${FAKE_NO_ANALYSIS:-} " != *" $id "* ]]; then
    extra='{"analysis": [{"target": "f", "scenarios": [{"scenario": "s", "checked_at": ["a.rs:1"], "verdict": "ok"}]}]}'
fi
if [[ "$id" == review-networking && " ${FAKE_NO_ANALYSIS:-} " != *" $id "* ]]; then
    extra="$(jq -c --argjson n "$FAKE_RULES" '. + {checklist: [range(1; $n + 1) | {rule: ., applies: false, verdict: "not_applicable"}]}' <<<"$extra")"
fi
jq -n --arg h "$head" --arg m "$mode" --argjson f "$findings" --argjson x "$extra" \
    '{schema_version: 1, reviewed_head_sha: $h, review_mode: $m, findings: $f} + $x' > "$out"
echo "tokens used"
echo "100"
EOF
chmod +x "$tmp/fake-subagent"
export FAKE_RULES="$(grep -cE '^[0-9]+\. ' "$GATOR_DIR/skills/gator-gate/references/networking-checklist.md")"
export REVIEW_TEAM_SUBAGENT="$tmp/fake-subagent" FAKE_HEAD="$head" FAKE_CALLS="$tmp/calls"

run_team() {
    : > "$FAKE_CALLS"
    : > "$FAKE_CALLS.reasoning"
    rm -f "$tmp/out.json"
    FAKE_MODE="$1" "$TEAM" --task "$tmp/task.md" --ledger "$tmp/ledger.json" \
        --diff "$tmp/$2" --out "$tmp/out.json" 2> "$tmp/stderr"
}
calls() { sort "$FAKE_CALLS" | tr '\n' ' '; }

# Initial review without networking changes: no networking member; no findings
# from focused members skips the merge and returns the generalist output.
ledger initial
FAKE_FINDINGS="principal-engineer-reviewer" run_team initial plain.diff
[[ "$(calls)" == "principal-engineer-reviewer review-contracts " ]]
jq -e '.findings[0].id == "principal-engineer-reviewer-01"' "$tmp/out.json" >/dev/null
grep -q 'tokens used' "$tmp/stderr"

# Networking paths and networking code in added lines both add the networking member.
run_team initial net-path.diff
[[ "$(calls)" == *"review-networking"* ]]
run_team initial net-content.diff
[[ "$(calls)" == *"review-networking"* ]]

# The networking member's prompt includes the checklist.
REVIEW_TEAM_WORKDIR="$tmp/work" run_team initial net-path.diff
grep -q '# Networking review checklist' "$tmp/work/review-networking.prompt.md"
grep -q 'provisional finding ID prefix `NET`' "$tmp/work/review-networking.prompt.md"
if grep -q 'Networking review checklist' "$tmp/work/review-contracts.prompt.md"; then exit 1; fi

# critical_only drops the contracts member.
ledger critical_only
run_team critical_only plain.diff
[[ "$(calls)" == "principal-engineer-reviewer " ]]

# Focused findings go through the merge, which must account for every input.
ledger initial
FAKE_FINDINGS="principal-engineer-reviewer review-contracts" run_team initial plain.diff
[[ "$(calls)" == *"review-merge"* ]]
jq -e '.merge_report.merged[0].sources | length == 2' "$tmp/out.json" >/dev/null

if FAKE_MERGE=drop FAKE_FINDINGS="principal-engineer-reviewer review-contracts" run_team initial plain.diff; then
    echo "expected merge accounting failure" >&2
    exit 1
fi
[[ ! -e "$tmp/out.json" ]]
[[ "$(grep -c review-merge "$FAKE_CALLS")" == 2 ]]

# A member that keeps failing fails the team after one retry, without output.
if FAKE_FAIL="review-contracts" run_team initial plain.diff; then
    echo "expected member failure" >&2
    exit 1
fi
[[ ! -e "$tmp/out.json" ]]
[[ "$(grep -c review-contracts "$FAKE_CALLS")" == 2 ]]
grep -q 'members failed: review-contracts' "$tmp/stderr"

# A focused member that omits its analysis, or a networking member that skips
# checklist rules, is retried and then fails the team.
if FAKE_NO_ANALYSIS="review-contracts" run_team initial plain.diff; then
    echo "expected missing analysis failure" >&2
    exit 1
fi
[[ "$(grep -c review-contracts "$FAKE_CALLS")" == 2 ]]
if FAKE_RULES=3 run_team initial net-path.diff; then
    echo "expected incomplete checklist failure" >&2
    exit 1
fi

# Member reasoning applies to focused members only.
REVIEW_TEAM_MEMBER_REASONING=high run_team initial plain.diff
grep -qx 'principal-engineer-reviewer default' "$FAKE_CALLS.reasoning"
grep -qx 'review-contracts high' "$FAKE_CALLS.reasoning"

# Driver changes outside networking files do not add the networking member.
printf 'diff --git a/crates/openshell-driver-kubernetes/src/driver.rs b/crates/openshell-driver-kubernetes/src/driver.rs\n+ let x = 1;\n' > "$tmp/driver.diff"
run_team initial driver.diff
[[ "$(calls)" != *"review-networking"* ]]

# The config's member_reasoning applies without an override.
run_team initial plain.diff
grep -qx 'review-contracts high' "$FAKE_CALLS.reasoning"

# REVIEW_TEAM_MEMBERS replaces the default members, and can opt in members the
# config leaves out by default; mode and change triggers still apply.
REVIEW_TEAM_MEMBERS="review-networking" run_team initial net-path.diff
[[ "$(calls)" == "principal-engineer-reviewer review-networking " ]]
REVIEW_TEAM_MEMBERS="review-security review-correctness review-networking" run_team initial plain.diff
[[ "$(calls)" == "principal-engineer-reviewer review-correctness review-security " ]]

# Modes that do not need a review are rejected.
ledger already_reviewed
if run_team already_reviewed plain.diff; then
    echo "expected already_reviewed rejection" >&2
    exit 1
fi

echo "review_team_test: ok"
