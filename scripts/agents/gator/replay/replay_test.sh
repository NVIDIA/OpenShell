#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Offline test for the replay harness: a fixture repository, a fake reviewer,
# and a fake judge. No model or network calls.

set -euo pipefail

REPLAY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/gator-replay-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/codex-home"
printf '{}\n' > "$tmp/codex-home/auth.json"
export CODEX_HOME="$tmp/codex-home"

git init -q "$tmp/src"
git -C "$tmp/src" config user.email replay@example.invalid
git -C "$tmp/src" config user.name replay
printf 'fn main() {}\n' > "$tmp/src/main.rs"
git -C "$tmp/src" add main.rs
git -C "$tmp/src" commit -qm base
base="$(git -C "$tmp/src" rev-parse HEAD)"
printf 'fn main() { let _ = std::net::TcpStream::connect("10.0.0.1:80"); }\n' > "$tmp/src/main.rs"
git -C "$tmp/src" commit -qam head
head="$(git -C "$tmp/src" rev-parse HEAD)"
printf 'fn main() {}\n// fixed\n' > "$tmp/src/main.rs"
git -C "$tmp/src" commit -qam fix
git clone -q --bare "$tmp/src" "$tmp/cache.git"

jq -cn --arg b "$base" --arg h "$head" '
    {id: "ok-case", kind: "test", pr: 1, base_sha: $b, head_sha: $h, title: "Add a dial",
     body: "Dials a private address.", tags: ["small"],
     expected: [{summary: "Raw TcpStream::connect skips nodelay"}, {summary: "Unrelated defect"}]},
    {id: "fail-case", kind: "test", pr: 2, base_sha: $b, head_sha: $h, title: "Reviewer fails",
     body: "", tags: ["other"], expected: [{summary: "x"}]}
' > "$tmp/cases.jsonl"

cat > "$tmp/reviewer.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
task="$(cat)"
grep -q 'Head SHA: ' <<<"$task"
grep -q '### Pragmatic review calibration' <<<"$task"
grep -q '"mode": "initial"' <<<"$task"
grep -q 'TcpStream::connect' <<<"$task"
# The checkout must not expose history past the PR head.
[[ "$(git -C repo rev-list --all | wc -l | tr -d ' ')" == 2 ]]
if gh api user 2>/dev/null; then exit 9; fi
[[ "$(jq -r .id case.json)" != fail-case ]] || exit 3
head="$(jq -r .head_sha case.json)"
jq -n --arg h "$head" '{schema_version: 1, reviewed_head_sha: $h, review_mode: "initial", findings: [
    {id: "GATOR-\($h[0:8])-01", severity: "Warning", invariant: "Dial TCP with nodelay.",
     attacker_or_operator_prerequisite: "none", supported_entry_point: "main", sink: "connect",
     changed_location: {path: "main.rs", line: 1}, base_behavior: "no dial", head_behavior: "raw dial",
     observable_impact: "latency", reproducer: "run main", pr_ownership: "added here",
     requested_change: "use helper", scope: "latest_delta", sibling_sites: []},
    {id: "GATOR-\($h[0:8])-02", severity: "Warning", invariant: "Something else.",
     attacker_or_operator_prerequisite: "none", supported_entry_point: "main", sink: "x",
     changed_location: {path: "main.rs", line: 1}, base_behavior: "a", head_behavior: "b",
     observable_impact: "c", reproducer: "d", pr_ownership: "e",
     requested_change: "f", scope: "latest_delta", sibling_sites: []}
]}' > review-findings.raw.json
echo "tokens used"
echo "1,234"
EOF
chmod +x "$tmp/reviewer.sh"

cat > "$tmp/judge.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
grep -q '"blocking": true' "$1"
jq -n '{expected: [
    {index: 0, match: "blocking", finding_ids: ["x-01"], rationale: "same"},
    {index: 1, match: "none", finding_ids: [], rationale: "absent"}
], extra_blocking: [{finding_id: "x-02", assessment: "dubious", rationale: "style"}]}' > "$2"
EOF
chmod +x "$tmp/judge.sh"

GATOR_REPLAY_CACHE="$tmp/cache.git" "$REPLAY_DIR/run-replay" \
    --cases "$tmp/cases.jsonl" \
    --reviewer-command "bash $tmp/reviewer.sh < task.md" \
    --judge-command "bash $tmp/judge.sh \"\$1\" \"\$2\"" \
    --label test --out "$tmp/run" --jobs 2 --timeout 60 > "$tmp/report.txt"

jq -e '
    .totals.cases == 2 and .totals.ok == 1 and .totals.failed == 1 and
    .totals.expected == 2 and .totals.caught_blocking == 1 and .totals.missed == 1 and
    .totals.extra_dubious == 1 and .totals.recall_blocking_pct == 50 and
    .totals.reviewer_tokens == 1234 and
    (.cases[] | select(.id == "fail-case") | .status == "reviewer_failed" and .reviewer_exit == 3)
' "$tmp/run/summary.json" >/dev/null || {
    cat "$tmp/report.txt" "$tmp/run/summary.json" >&2
    exit 1
}
grep -q 'All: 1/2 blocking (50%)' "$tmp/report.txt"

# Re-judging keeps the reviewer metrics and replaces the judgment.
cat > "$tmp/judge2.sh" <<'EOF2'
#!/usr/bin/env bash
jq -n '{expected: [{index: 0, match: "blocking", finding_ids: [], rationale: ""}, {index: 1, match: "blocking", finding_ids: [], rationale: ""}], extra_blocking: []}' > "$2"
EOF2
GATOR_REPLAY_CACHE="$tmp/cache.git" "$REPLAY_DIR/run-replay" \
    --cases "$tmp/cases.jsonl" --rejudge "$tmp/run" \
    --judge-command "bash $tmp/judge2.sh \"\$1\" \"\$2\"" > /dev/null
jq -e '.totals.caught_blocking == 2 and .totals.reviewer_tokens == 1234 and .totals.failed == 1' \
    "$tmp/run/summary.json" >/dev/null

# Tag selection and listing.
GATOR_REPLAY_CACHE="$tmp/cache.git" "$REPLAY_DIR/run-replay" \
    --cases "$tmp/cases.jsonl" --tag other --list > "$tmp/list.txt"
[[ "$(wc -l < "$tmp/list.txt" | tr -d ' ')" == 1 ]] && grep -q '^fail-case' "$tmp/list.txt"

# Comparing a run with itself reports every case.
"$REPLAY_DIR/score" "$tmp/run" "$tmp/run" | grep -q $'^ok-case\t2/2 +0p0d\t2/2 +0p0d$'

# Timeout kills the reviewer and records a failure.
GATOR_REPLAY_CACHE="$tmp/cache.git" "$REPLAY_DIR/run-replay" \
    --cases "$tmp/cases.jsonl" --case ok-case \
    --reviewer-command 'sleep 30' --judge-command 'false' \
    --label slow --out "$tmp/slow" --timeout 2 > /dev/null
jq -e '.cases[0].status == "reviewer_failed"' "$tmp/slow/summary.json" >/dev/null
grep -q 'timed out' "$tmp/slow/cases/ok-case/reviewer.stderr"

echo "replay_test: ok"
