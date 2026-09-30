---
name: fix-security-issue
description: Implement an authorized fix for a reviewed security issue and open a PR that closes its issue.
metadata:
  internal: true
---

# Fix Security Issue

Use this skill after an authorized `review-security-issue` review identifies an actionable concern. Follow `SECURITY.md`; do not disclose vulnerability details in a public issue. A direct user request to fix a specific reviewed issue authorizes implementation. For unattended work, inspect current `state:*` label descriptions, maintainer assignments, and comments to verify that remediation is authorized. Do not infer approval from a state that only records technical validation.

1. Fetch the issue and its comments with `gh issue view <id> --json number,title,body,state,labels,comments`. Inspect current repository labels and confirm this is a security issue. Find the review marked `> **🔒 security-review-agent**` and its remediation plan. If the review is missing or found the issue not actionable, stop and report that result.
2. Verify the review against current code. Adapt the plan when code has changed, and record material deviations. Check for an existing owner, branch, or PR.
3. Create an issue-specific branch or worktree, preserving unrelated changes. Implement the smallest safe fix and add regression tests for the security boundary. Avoid logging secrets or adding public exploit detail.
4. Run the relevant checks from `CONTRIBUTING.md`, including `mise run test` after code changes, `mise run e2e` for sandbox or policy changes, `mise run ci` before opening a PR, and `mise run pre-commit` before a signed-off Conventional Commit.
5. Follow `create-github-pr` and use `Closes #<id>` for the reviewed issue. Every PR must close its own issue; split multi-PR remediations into separate issues in the authorized security workflow. Keep the PR description appropriately scoped to its disclosure venue.

Begin any fix comments with `> **🔧 security-fix-agent**`. Do not change human disposition or introduce `agent:*` workflow labels.
