#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
dir="$(cd "$(dirname "$0")/../bin" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export CALLS="$tmp/calls" HEAD="$(printf 'a%.0s' {1..40})"
cat > "$tmp/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "$CALLS"
case "$*" in
  'api user --jq .login') echo operator ;;
  *'/permission --jq .permission') echo "${PERMISSION:-write}" ;;
  *'/pulls/42 --jq .head.sha') echo "${CURRENT_HEAD:-$HEAD}" ;;
  *'/pulls/42') jq -n --arg head "$HEAD" --arg repo "${PR_REPO:-ai-openshell/openshell}" --argjson count "${CHANGED_FILES:-1}" '{state:"open",draft:false,changed_files:$count,head:{sha:$head},base:{repo:{full_name:$repo}}}' ;;
  *'/files?'*) jq -n --arg file "${FILE:-src/main.rs}" --arg previous "${PREVIOUS_FILE:-}" '[{filename:$file,previous_filename:$previous}]' ;;
  *'--method POST'*) exit 0 ;;
  *'/actions/runs/123') jq -n --arg head "${RUN_HEAD:-$HEAD}" --arg repo "${RUN_REPO:-ai-openshell/openshell}" --arg path "${WORKFLOW:-.github/workflows/branch-e2e.yml}" --arg event "${EVENT:-pull_request}" --arg conclusion "${CONCLUSION:-action_required}" --argjson pr "${RUN_PR:-42}" '{repository:{full_name:$repo},head_sha:$head,path:$path,event:$event,conclusion:$conclusion,pull_requests:[{number:$pr}]}' ;;
  *) exit 90 ;;
esac
SH
chmod +x "$tmp/gh"
export PATH="$tmp:$PATH"
check() { bash "$dir/approve-gator-workflow" "$@"; }
reject() {
    : > "$CALLS"
    if check "$@" > "$tmp/out" 2>&1; then echo 'expected rejection' >&2; exit 1; fi
    if grep -q -- '--method POST' "$CALLS"; then echo 'unexpected approval' >&2; exit 1; fi
}
check --operator-authorized 42 123
grep -Fq 'api --method POST repos/ai-openshell/openshell/actions/runs/123/approve' "$CALLS"
WORKFLOW=.github/workflows/trivy-changes.yml check --operator-authorized 42 123
PR_REPO=ai-openshell/OpenShell RUN_REPO=ai-openshell/OpenShell check --operator-authorized 42 123
reject 42 123
PERMISSION=read reject --operator-authorized 42 123
PR_REPO=other/openshell reject --operator-authorized 42 123
RUN_REPO=other/openshell reject --operator-authorized 42 123
RUN_HEAD=stale reject --operator-authorized 42 123
CURRENT_HEAD=changed reject --operator-authorized 42 123
RUN_PR=43 reject --operator-authorized 42 123
EVENT=push reject --operator-authorized 42 123
CONCLUSION=success reject --operator-authorized 42 123
WORKFLOW=.github/workflows/release.yml reject --operator-authorized 42 123
FILE=.github/workflows/branch-checks.yml reject --operator-authorized 42 123
PREVIOUS_FILE=.github/workflows/branch-checks.yml reject --operator-authorized 42 123
CHANGED_FILES=2 reject --operator-authorized 42 123
echo 'PASS: workflow approval scope and fail-closed guards'
