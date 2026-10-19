---
name: fix-security-issue
description: Implement an authorized fix for a reviewed security issue and open a PR that closes its issue.
metadata:
  internal: true
---

# Fix Security Issue

Use this skill after an authorized `review-security-issue` review identifies an actionable concern. Follow `SECURITY.md`; do not disclose vulnerability details in a public issue. A direct user request to fix a specific reviewed issue authorizes implementation. For unattended work, inspect current `state:*` label descriptions, maintainer assignments, and comments to verify that remediation is authorized. Do not infer approval from a state that only records technical validation.

1. Fetch the issue and its comments with `gh issue view <id> --json number,title,body,state,labels,comments`. Follow Label Discovery in `CONTRIBUTING.md` and confirm this is a security issue; resolve unclear meanings before interpreting authorization. Find the review marked `> **🔒 security-review-agent**` and its remediation plan. If the review is missing or found the issue not actionable, stop and report that result.
2. Verify the review against current code. Adapt the plan when code has changed, and record material deviations. Check for an existing owner, branch, or PR.
3. Create a `fix` branch or worktree following Branch Names in `CONTRIBUTING.md`, preserving unrelated changes and disclosure boundaries. Implement the smallest safe fix and add regression tests for the security boundary. Avoid logging secrets or adding public exploit detail.
4. Follow the verification guidance in `CONTRIBUTING.md`. Run format, lint, compile or type checks, and regression tests for the affected security boundary and dependent components, plus the relevant E2E lane for sandbox or policy changes. Broaden verification when the fix spans components or a concrete risk remains; do not require unaffected Rust or SDK suites solely to create a signed-off commit or PR.
5. Follow `create-github-pr` and use `Closes #<id>` for the reviewed issue. Every PR from this issue-backed remediation workflow must close its own issue; split multi-PR remediations into separate issues in the authorized security workflow. Keep the PR description appropriately scoped to its disclosure venue.

Begin any fix comments with `> **🔧 security-fix-agent**`. Do not change human disposition or introduce `agent:*` workflow labels.
