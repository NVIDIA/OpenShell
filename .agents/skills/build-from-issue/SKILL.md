---
name: build-from-issue
description: Plan and implement work described in a GitHub issue, including verification, documentation, and a PR that closes the issue.
metadata:
  internal: true
---

# Build From Issue

Use a specific GitHub issue to plan and implement a scoped change. Direct user instructions authorize the phase requested. Planning alone does not authorize implementation. For unattended work, inspect the current `state:*` label descriptions, maintainer assignments, and issue comments to infer the authorized phase. Proceed only when those records authorize the phase; do not assume every state permits implementation.

## Inspect the issue

1. Run `gh issue view <id> --json number,title,body,state,labels,comments,assignees` and inspect the repository's current `state:*` labels and descriptions with `gh label list`. Infer whether triage, validation, and human acceptance have happened. Do not hard-code label names or change disposition as part of building.
2. Read the issue, comments, linked PRs, and current code. Check for an active owner or implementation. If the issue concerns a vulnerability, use `review-security-issue` and `fix-security-issue` instead.
3. Confirm that the User Story attests to the human operator's first-hand OpenShell use and gives a specific use case. If the issue lacks this, ask the operator before proceeding with planning or implementation. For a bug, require reproduction using only an OpenShell deployment; do not install third-party tools solely to demonstrate the problem.
4. If the user's direct request starts before the normal issue disposition, briefly report the discrepancy and continue with the authorized phase. Stop only when information needed to do the work is actually unavailable or a conflicting owner needs resolution.

## Plan

Identify the user-visible outcome, affected code, alternatives, tests, and documentation. For configuration, CLI, SDK, or other UX changes, include notional commands, configuration, or API examples so a human can review the proposed interaction. Consider existing extensibility points such as middleware, interceptors, and providers. Prefer an applicable extension when it satisfies the use case; the need to run another service alone does not disqualify it.

Use a single issue comment beginning with `> **🏗️ build-plan**` when a plan should be recorded on GitHub. On later invocations, read that comment and any newer human feedback before taking action. Respond to unanswered feedback with a comment beginning `> **🏗️ build-from-issue-agent**`; update the existing plan comment in place when the design changes. Do not repeat a completed plan or open a second PR. Distinguish technical findings from product decisions. If the user requested only a plan, stop after the plan is available for review.

## Implement

1. Check the current branch and working tree. Preserve unrelated work. Create a branch or worktree as needed, with the branch named `<type>/<issue-id>-<short-description>/<github-username>`. Use a Conventional Commits type for `<type>`.
2. Implement the smallest coherent change that fulfills the acceptance criteria. Update relevant skills when behavior or commands change. Keep published documentation minimal: explain exactly what users need, avoid duplication across pages, and omit internal details with no user impact.
3. Add meaningful tests for changed behavior and follow the verification guidance in `CONTRIBUTING.md`. Select format, lint, compile or type checks, and tests for affected components and their dependencies. Run the relevant E2E lane for infrastructure, sandbox, or policy changes. Guidance and template edits need applicable Markdown, YAML, link, and consistency checks. Do not require full Rust, SDK, or repository CI solely because a commit or PR is being created; broaden checks only for a concrete remaining risk or failed check.
4. Review the diff, use a signed-off Conventional Commit, and prepare a PR following `create-github-pr`.

Every PR must have its own existing issue and use `Closes #<id>` in its Related Issue section. For work needing multiple PRs, split the scope into a closable issue per PR. A high-level issue may track those issues but should not be closed by an incomplete PR. Report the implementation, verification, and any remaining limitation in the PR description, rather than copying earlier issue diagnostics.

Do not apply acceptance or roadmap decisions on behalf of a maintainer. Do not introduce `agent:*` workflow labels.
