---
name: build-from-issue
description: Given a GitHub issue number, plan and implement the work described in the issue. Operates iteratively - creates an implementation plan, responds to feedback, and only builds when the 'state:agent-ready' label is applied. Includes tests, documentation updates, and PR creation. Trigger keywords - build from issue, implement issue, work on issue, build issue, start issue.
---

# Build From Issue

Plan, iterate on feedback, and implement work described in a GitHub issue.

This skill operates as a stateful workflow — it can be run repeatedly against the same issue. Each invocation inspects the issue's labels, plan comment, and conversation history to determine the correct next action.

## Prerequisites

- The `gh` CLI must be authenticated (`gh auth status`)
- You must be in a git repository with a GitHub remote

## Critical: `state:agent-ready` Label Is Human-Only

The `state:agent-ready` label is a **human gate**. It signals that a human has reviewed the plan and authorized the agent to build. Under **no circumstances** should this skill or any agent:

- Apply the `state:agent-ready` label
- Ask the user to let the agent apply it
- Suggest automating its application
- Bypass the check by proceeding without it

If the label is not present, the agent **must stop and wait**. This is a non-negotiable safety control — it ensures a human explicitly authorizes every build.

## Agent Comment Markers

This skill uses two distinct markers to identify its comments:

### Plan marker

The implementation plan lives in a **single comment** that is edited in place as the plan evolves. It is identified by this marker on its first line:

```
> **🏗️ build-plan**
```

### Conversation marker

All other comments (responses to human feedback, status updates, PR announcements) use this marker:

```
> **🏗️ build-from-issue-agent**
```

These markers distinguish agent comments from human comments and from other skills (e.g., `🔒 security-review-agent`, `🔧 security-fix-agent`).

## State Machine Overview

Each invocation follows this decision tree:

```
Fetch issue + comments
  │
  ├─ No plan comment (🏗️ build-plan) found?
  │   → Generate plan via principal-engineer-reviewer
  │   → Post plan comment
  │   → Add 'state:review-ready' label
  │   → STOP
  │
  ├─ Plan exists + new human comments since last agent response?
  │   → Respond to each comment (quote context, address feedback)
  │   → Update the plan comment if feedback requires plan changes
  │   → STOP
  │
  ├─ Plan exists + 'state:agent-ready' label + no 'state:in-progress' or 'state:pr-opened' label?
  │   → Run scope check (warn if high complexity)
  │   → Check for conflicting branches/PRs
  │   → BUILD (Steps 6–14)
  │
  ├─ 'state:in-progress' label present?
  │   → Detect existing branch and resume if possible
  │   → Otherwise report current state
  │
  ├─ 'state:pr-opened' label present?
  │   → Report that PR already exists, link to it
  │   → STOP
  │
  └─ Plan exists + no new comments + no 'state:agent-ready'?
      → Report: "Plan is posted and awaiting review. No new comments to address."
      → STOP
```

## Step 1: Fetch the Issue

The user provides an issue ID (e.g., `#42` or `42`). Strip any leading `#` and fetch:

```bash
gh issue view <id> --json number,title,body,state,labels,author
```

If the issue is closed, report that and stop.

If the issue has the `state:triage-needed` label, report that the issue has not been triaged yet. Suggest using the `triage-issue` skill first to assess and classify the issue before planning implementation. Stop.

## Step 2: Fetch and Classify Comments

Fetch all comments:

```bash
gh issue view <id> --json comments --jq '.comments[] | {id: .id, body: .body, author: .author.login, createdAt: .createdAt, updatedAt: .updatedAt}'
```

Classify each comment into one of:

- **Plan comment**: body starts with `> **🏗️ build-plan**`
- **Agent comment**: body starts with `> **🏗️ build-from-issue-agent**`
- **Human comment**: everything else (not agent-marked)

Record the plan comment's `id` (needed for editing via API) and its `updatedAt` timestamp.

## Step 3: Determine Action

Using the state machine above, determine what to do based on:

1. Whether a plan comment exists
2. Whether there are human comments newer than the last agent comment (plan or conversation)
3. Which labels are present (`state:review-ready`, `state:agent-ready`, `state:in-progress`, `state:pr-opened`)

Follow the appropriate branch below.

---

## Branch A: Generate the Plan

If no plan comment exists, generate one.

### A1: Analyze the Issue with Principal Engineer Reviewer

Pass the issue title, description, labels, and any relevant code references to the `principal-engineer-reviewer` sub-agent. Use the Task tool:

```
Task tool with subagent_type="principal-engineer-reviewer"
```

In the prompt, instruct the reviewer to:

1. Read the issue description thoroughly and identify what needs to change in the codebase.
2. Map the requirements to existing code — read the relevant source files.
3. Determine the **issue type** — one of: `feat` (new feature), `fix` (bug fix), `refactor`, `chore`, `perf`, `docs`.
4. Propose the minimal set of changes that satisfies the requirements.
5. Sequence the work so each step is independently testable.
6. Identify what tests are needed (unit, integration, e2e) and where they should live.
7. Assess **complexity** on a scale:
   - **Low**: Isolated change, < 3 files, clear path forward
   - **Medium**: Multiple files/components, some design decisions, but well-scoped
   - **High**: Cross-cutting changes, architectural decisions needed, significant unknowns
8. Call out risks, unknowns, and decisions that need stakeholder input.

### A2: Post the Plan Comment

Post the plan as a comment on the issue. This is the **canonical plan comment** that will be edited in place as the plan evolves.

```bash
gh issue comment <id> --body "$(cat <<'EOF'
> **🏗️ build-plan**

## Implementation Plan

**Issue type:** `<feat|fix|refactor|chore|perf|docs>`
**Complexity:** <Low|Medium|High>
**Confidence:** <High — clear path | Medium — some unknowns | Low — needs discussion>

### Summary
<2-3 sentences describing what will be built/changed and the approach>

### Scope
- `<file1>`: <what changes and why>
- `<file2>`: <what changes and why>
- ...

### Implementation Steps
1. <step 1 — independently testable>
2. <step 2>
3. ...

### Test Plan
- **Unit tests:** <what will be tested and where the tests live>
- **Integration tests:** <what will be tested, or "N/A" with rationale>
- **E2E tests:** <what will be tested, or "N/A" with rationale>

### Risks & Open Questions
- <risk or unknown that may need human input>

### Documentation Impact
- <which architecture/ docs will need updating, or "None expected">

---
*Revision 1 — initial plan*
EOF
)"
```

### A3: Add the `state:review-ready` Label

```bash
gh issue edit <id> --add-label "state:review-ready"
```

Report to the user that the plan has been posted and is awaiting review. Stop.

---

## Branch B: Respond to Feedback

If a plan exists and there are human comments newer than the last agent response, address them.

### B1: Process Each Unanswered Human Comment

For each human comment that is newer than the most recent agent comment (plan `updatedAt` or conversation comment `createdAt`):

1. Read the comment.
2. Quote the relevant portion using `>` blockquote syntax.
3. Formulate a response based on the codebase and the current plan.
4. Post a response with the conversation marker.

```bash
gh issue comment <id> --body "$(cat <<'EOF'
> **🏗️ build-from-issue-agent**

> <quoted portion of human's comment>

<response addressing the feedback>
EOF
)"
```

### B2: Update the Plan if Needed

If any feedback requires changes to the plan, **edit the existing plan comment** rather than posting a new one. Use the GitHub API with the comment's node ID:

```bash
gh api graphql -f query='
  mutation {
    updateIssueComment(input: {id: "<comment-node-id>", body: "<updated body>"}) {
      issueComment { id }
    }
  }
'
```

Or use the REST API:

```bash
gh api repos/{owner}/{repo}/issues/comments/<comment-id> -X PATCH -f body="$(cat <<'EOF'
> **🏗️ build-plan**

## Implementation Plan

<... updated plan content ...>

---
*Revision <N> — <brief description of what changed>*
*Revision <N-1> — <previous change>*
*Revision 1 — initial plan*
EOF
)"
```

Preserve the full revision history at the bottom so readers can track how the plan evolved.

Report to the user what feedback was addressed and whether the plan was updated. Stop.

---

## Branch C: Build

If the plan exists and the `state:agent-ready` label is present (and neither `state:in-progress` nor `state:pr-opened` is set), proceed with implementation.

### Step 4: Scope Check

Read the plan comment and check the **Complexity** and **Confidence** fields.

- **If Complexity is High or Confidence is Low**, warn the user:

  > "This issue is rated High complexity / Low confidence. The plan includes open questions that may need human decisions during implementation. Proceeding, but flagging this for your awareness."

  Continue — do not hard-stop. The human chose to apply `state:agent-ready`.

### Step 5: Conflict Detection

Before creating a branch, check for conflicts:

#### Check for existing branches

```bash
git fetch origin
git branch -r | grep -i "<issue-id>"
```

If a remote branch referencing this issue ID exists, report it and ask the user whether to continue on that branch or abort.

#### Check for existing PRs

```bash
gh pr list --state open --search "Closes #<issue-id>" --json number,title,url
```

If an open PR already references this issue, report it and stop. Do not create a competing PR.

### Step 6: Create Branch

Determine the branch prefix from the issue type in the plan:

| Issue type | Branch prefix |
| --- | --- |
| `feat` | `feat/` |
| `fix` | `fix/` |
| `refactor` | `refactor/` |
| `chore` | `chore/` |
| `perf` | `perf/` |
| `docs` | `docs/` |

Get the current username and create the branch:

```bash
USERNAME=$(gh api user --jq '.login')
git checkout main
git pull origin main
git checkout -b <prefix><issue-id>-<short-description>/$USERNAME
```

### Step 7: Add `state:in-progress` Label

```bash
gh issue edit <id> --add-label "state:in-progress"
```

### Step 8: Implement the Changes

Follow the implementation steps from the plan. Principles:

- **Follow the plan**: The plan was reviewed and approved. Stick to it unless you discover something that requires deviation.
- **Minimal scope**: Only change what the plan calls for. No unrelated refactors.
- **If you must deviate**: Note the deviation — it will be included in the PR description.

Read the relevant source files before making changes. Implement step by step per the plan's sequence.

### Step 9: Write Tests

Write tests as specified in the plan's Test Plan section. Follow the project's existing test conventions.

#### Unit tests

- Place alongside existing tests for the module (e.g., `#[cfg(test)]` blocks in Rust, `test_*.py` for Python)
- Cover the new/changed behavior, edge cases, and error paths
- Ensure pre-existing behavior still works

#### Integration tests

- Place in the project's existing integration test directories
- Cover interactions between the changed components
- Test realistic scenarios including error conditions

#### E2E tests

- Only if the plan calls for them
- Cover the full user-facing workflow affected by the change

#### Test naming

Use descriptive names that document intent:
- `test_pagination_returns_correct_page_count`
- `test_rejects_negative_offset_parameter`
- `test_retry_succeeds_after_transient_failure`

### Step 10: Verify — Tests, Lint, Pre-commit (Retry Loop)

Verification has two phases: unit tests + pre-commit, then E2E tests (if applicable). Run with up to **3 attempts per phase**.

#### Phase 1: Unit Tests and Pre-commit

On each attempt:

```bash
# Run pre-commit checks (includes unit tests, linting, formatting)
mise run pre-commit
```

**If verification fails:**

1. Read the error output carefully.
2. Fix the issues (test failures, lint errors, formatting).
3. Decrement the retry counter and try again.

**If all 3 attempts fail**, stop and report to the user:
- What passed and what failed
- The specific errors from the last attempt
- That manual intervention is needed

Do not proceed to Phase 2 or PR creation if Phase 1 is not green.

#### Phase 2: E2E Tests (Conditional)

**Trigger**: Run this phase if any files under `e2e/` were added or modified in this build. Check with:

```bash
git diff --name-only main -- e2e/
```

If there are no changes under `e2e/`, skip this phase entirely.

If E2E files were modified, deploy to the local cluster and run the E2E test suite:

```bash
# Deploy all changes to the local k3s cluster
mise run cluster:deploy

# Run the E2E sandbox tests
mise run test:e2e:sandbox
```

`mise run test:e2e:sandbox` depends on `cluster:deploy` and `python:proto`, then runs `uv run pytest -o python_files='test_*.py' e2e/python`. However, since the cluster may need explicit deploy for code changes beyond just E2E test files, always run `mise run cluster:deploy` first as a separate step to ensure all sandbox/proxy/policy changes are live on the cluster before running E2E tests.

**E2E retry loop** (up to 3 attempts):

1. Run `mise run cluster:deploy` (only on the first attempt, or if code was changed between attempts).
2. Run `mise run test:e2e:sandbox`.
3. If tests fail:
   - Read the pytest output carefully — identify which tests failed and why.
   - Distinguish between **test bugs** (the test itself is wrong) and **implementation bugs** (the code under test is wrong).
   - Fix the failing code or tests.
   - If code changes were made (not just test fixes), re-run `mise run cluster:deploy` before retrying.
   - Decrement the retry counter and try again.
4. If tests pass, Phase 2 is green.

**If all 3 E2E attempts fail**, stop and report to the user:
- Which E2E tests are failing
- The pytest output from the last attempt
- Whether the failures appear to be test issues or implementation issues
- That manual intervention is needed

Do not proceed to PR creation if E2E verification is not green.

### Step 11: Update Documentation

Use the `arch-doc-writer` sub-agent to update architecture documentation. Use the Task tool:

```
Task tool with subagent_type="arch-doc-writer"
```

In the prompt, provide:
- Which files were changed and why (from the plan + any deviations)
- The issue context (what was built/fixed)
- Which architecture docs in `architecture/` are likely affected

Launch one `arch-doc-writer` instance per documentation file that needs updating. If no documentation changes are needed, the `arch-doc-writer` will make that determination.

### Step 12: Commit and Push

Commit all changes using conventional commit format. The `<type>` comes from the issue type in the plan:

```bash
git add <files>
git commit -m "$(cat <<'EOF'
<type>(<scope>): <short description>

Closes #<issue-id>

<brief explanation of what was implemented>
EOF
)"
```

Push:

```bash
git push -u origin HEAD
```

### Step 13: Open PR

Create the PR:

```bash
gh pr create \
  --title "<type>(<scope>): <short description>" \
  --body "$(cat <<'EOF'
> **🏗️ build-from-issue-agent**

## Summary
<1-3 sentences describing what was built and the approach taken>

## Related Issue
Closes #<issue-id>

## Changes
- `<file1>`: <what changed and why>
- `<file2>`: <what changed and why>

### Deviations from Plan
<any deviations from the approved plan, or "None — implemented as planned">

## Testing
- [x] `mise run pre-commit` passes
- [x] Unit tests added/updated
- [x] E2E tests added/updated (if applicable)

**Tests added:**
- **Unit:** <test file(s) and what they cover>
- **Integration:** <test file(s) and what they cover, or "N/A">
- **E2E:** <test file(s) and what they cover, or "N/A">

## Checklist
- [x] Follows Conventional Commits
- [x] Commits are signed off (DCO)
- [x] Architecture docs updated (if applicable)

**Documentation updated:**
- `<architecture/doc.md>`: <what was updated>
EOF
)"
```

**Display the PR URL** so it's easily clickable:

```
Created PR [#<number>](https://github.com/OWNER/REPO/pull/<number>)
```

### Step 14: Post-Build Cleanup

#### Post summary comment on the issue

```bash
gh issue comment <id> --body "$(cat <<'EOF'
> **🏗️ build-from-issue-agent**

## Implementation Complete

PR: [#<pr-number>](https://github.com/OWNER/REPO/pull/<pr-number>)

### What was built
<1-2 sentence summary>

### Tests
- Unit: <count> tests added
- Integration: <count or N/A>
- E2E: <count or N/A>

### Docs updated
- <list of updated architecture docs, or "None needed">

The issue will auto-close when the PR is merged.
EOF
)"
```

#### Post E2E attestation comment on the PR

If E2E tests were run in Phase 2 of Step 10, post an attestation comment on the **PR** documenting that local E2E tests passed. This is necessary because E2E tests are not yet running in CI — this comment serves as the verification record for reviewers.

Collect the metadata before posting:

```bash
# Get the commit SHA that was tested
COMMIT_SHA=$(git rev-parse HEAD)

# Get the test output summary (last few lines of pytest output)
# This was captured during the Phase 2 run — include the pass/fail/skip counts
```

Post the attestation:

```bash
gh pr comment <pr-number> --body "$(cat <<'EOF'
> **🏗️ build-from-issue-agent**

## E2E Test Attestation

Local E2E tests passed. CI does not currently run E2E tests, so this comment serves as the verification record.

| Field | Value |
|-------|-------|
| **Commit** | `<commit-sha>` |
| **Command** | `mise run test:e2e:sandbox` |
| **Cluster deploy** | `mise run cluster:deploy` (completed before test run) |
| **Result** | ✅ All passed |

### Test Summary

```
<paste the pytest summary line, e.g.: "12 passed, 1 skipped in 45.32s">
```

### Tests Executed
- `<test_file.py>::<test_name>` — PASSED
- `<test_file.py>::<test_name>` — PASSED
- ...
EOF
)"
```

Include **every test** that ran (not just the new ones) so the reviewer can see full coverage. If any tests were skipped, note them and explain why.

#### Update labels

Remove `state:in-progress` and `state:review-ready`, add `state:pr-opened`:

```bash
gh issue edit <id> --remove-label "state:in-progress" --remove-label "state:review-ready" --add-label "state:pr-opened"
```

#### Report workflow run URL

Get the workflow run URL from the PR so the user can monitor CI:

```bash
BRANCH=$(gh pr view <pr-number> --json headRefName --jq '.headRefName')
gh run list --branch "$BRANCH" --limit 1 --json databaseId,status,url
```

Report the workflow run URL and suggest the user can use the `watch-github-actions` skill to monitor it.

---

## Branch D: Resume In-Progress Build

If the `state:in-progress` label is present, the skill was previously started but may not have completed.

1. Check for an existing branch matching the issue ID:
   ```bash
   git branch -r | grep -i "<issue-id>"
   ```
2. If found, check it out and inspect the state (are there uncommitted changes? committed but not pushed? pushed but no PR?).
3. Resume from the appropriate step (9, 10, 12, or 13).
4. If the state is unrecoverable, report to the user and suggest starting fresh (remove `state:in-progress` label and re-run).

---

## Useful Commands Reference

| Command | Description |
| --- | --- |
| `gh issue view <id> --json number,title,body,state,labels,author` | Fetch full issue metadata |
| `gh issue view <id> --json comments` | Fetch all comments on an issue |
| `gh issue comment <id> --body "..."` | Post a comment on an issue |
| `gh api repos/{owner}/{repo}/issues/comments/<id> -X PATCH -f body="..."` | Edit an existing comment |
| `gh issue edit <id> --add-label "..."` | Add labels |
| `gh issue edit <id> --remove-label "..."` | Remove labels |
| `gh pr list --state open --search "..."` | Search for open PRs |
| `gh pr create --title "..." --body "..."` | Create a pull request |
| `gh api user --jq '.login'` | Get current GitHub username |
| `mise run pre-commit` | Run pre-commit checks (includes unit tests, lint, format) |
| `mise run cluster:deploy` | Deploy all changes to local k3s cluster |
| `mise run test:e2e:sandbox` | Run E2E sandbox tests (depends on cluster:deploy) |

## Example Usage

### First run — no plan exists

User says: "Build from issue #42"

1. Fetch issue #42 — title: "Add pagination to dataset list endpoint"
2. Fetch comments — no `🏗️ build-plan` marker found
3. Pass issue to `principal-engineer-reviewer` for analysis
4. Reviewer produces a plan: feat type, Medium complexity, 3 implementation steps, unit + integration tests needed
5. Post the plan comment with the `🏗️ build-plan` marker
6. Add `state:review-ready` label
7. Report to user: "Plan posted on issue #42. Awaiting review."

### Second run — human left feedback

User says: "Check on issue #42"

1. Fetch issue #42 and comments
2. Find existing plan comment (Revision 1)
3. Find new human comment: "Should we also paginate the search endpoint?"
4. Post response quoting the question, explaining that search pagination is out of scope for this issue but could be a follow-up
5. Report to user: "Responded to feedback on #42. Plan unchanged."

### Third run — human revised scope, plan needs update

User says: "Check issue #42"

1. Fetch issue #42 and comments
2. Find plan + new human comment: "Actually, let's include search pagination. Updated the issue description."
3. Post response acknowledging the scope change
4. Edit the plan comment to include search endpoint pagination — Revision 2
5. Report to user: "Updated plan to include search pagination (Revision 2)."

### Fourth run — state:agent-ready applied

User says: "Build issue #42"

1. Fetch issue #42 — labels include `state:agent-ready`
2. Plan exists (Revision 2), complexity: Medium, confidence: High
3. No conflicting branches or PRs
4. Create branch `feat/42-add-pagination/jmyers`
5. Add `state:in-progress` label
6. Implement pagination for both endpoints per the plan
7. Add unit tests for pagination logic, integration tests for both endpoints
8. `mise run pre-commit` passes on first attempt
9. E2E tests skipped (no changes under `e2e/`)
10. `arch-doc-writer` updates `architecture/gateway.md` with pagination details
10. Commit, push, create PR with `Closes #42`
11. Post summary comment on issue with PR link
12. Update labels: remove `state:in-progress` + `state:review-ready`, add `state:pr-opened`
13. Report PR URL and workflow run status to user

### Run on issue with existing PR

User says: "Build issue #42"

1. Fetch issue #42 — `state:pr-opened` label present
2. Find existing PR #789 linked to the issue
3. Report: "PR [#789](...) already exists for issue #42. Nothing to build."

### Run on high-complexity issue

User says: "Build issue #99"

1. Fetch issue #99 — `state:agent-ready` label present
2. Plan exists: complexity High, confidence Low, has open questions
3. Warn user: "Issue #99 is rated High complexity / Low confidence. Proceeding but flagging for your awareness."
4. Continue with build
