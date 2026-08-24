---
name: build-from-issue
description: Given a GitHub issue number, plan and implement the work described in the issue. Supports direct user requests and unattended queue processing through the `agent:*` workflow labels. Includes tests, documentation updates, and PR creation. Trigger keywords - build from issue, implement issue, work on issue, build issue, start issue.
---

# Build From Issue

Plan, iterate on feedback, and implement work described in a GitHub issue.

This skill operates as a stateful workflow — it can be run repeatedly against the same issue. Each invocation inspects the issue's labels, plan comment, and conversation history to determine the correct next action.

## Prerequisites

- The `gh` CLI must be authenticated (`gh auth status`)
- You must be in a git repository with a GitHub remote

## Invocation and Authorization

This skill supports two invocation modes:

- **Direct mode:** A user explicitly asks the agent to plan or implement a specific issue. The request itself authorizes the requested phase; the corresponding `agent:*` request label is not required.
- **Queue mode:** An always-on or unattended agent scans for work without a live user directing it to a specific issue. In this mode, `agent:plan-requested` authorizes planning and `agent:implementation-requested` authorizes implementation.

A direct request authorizes only what it says. A request to review or plan does not authorize implementation. A request to build, implement, or work on an issue authorizes both the planning needed to perform the work and implementation unless the user asks to stop after planning.

The two request labels remain human-only queue controls. Under **no circumstances** should this skill or any agent apply them, ask to apply them, or suggest automating their application.

In direct mode, issue lifecycle and `agent:*` workflow labels are advisory rather than gates. Inspect the labels and warn the user about each expected label that is missing or any lifecycle label that indicates the normal workflow is incomplete, then continue with the requested phase. Do not ask the user to fix the labels first. A direct request does not change the issue's disposition or make the labels accurate; it only authorizes the requested work.

If direct work begins on an issue that was not already in the label-driven workflow, do not introduce `agent:in-progress` or `agent:pr-opened` solely for that invocation. If a matching request label is present, preserve the existing label transitions so unattended agents can track the workflow.

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
  ├─ topic:security present?
  │   → Route to review-security-issue or fix-security-issue; STOP
  │
  ├─ Direct mode + expected lifecycle or agent-workflow labels missing/incomplete?
  │   → Warn which labels are missing or incomplete; continue with the requested phase
  │
  ├─ Queue mode + triage incomplete, awaiting information, or awaiting human disposition?
  │   → Report the blocking state and STOP
  │
  ├─ No plan comment and no direct planning request and agent:plan-requested absent?
  │   → No request for agent planning; STOP
  │
  ├─ No plan comment + direct planning request or agent:plan-requested present?
  │   → Generate plan via principal-engineer-reviewer
  │   → Post plan comment
  │   → Advance labels only for a label-driven invocation
  │   → Continue if the direct request also authorized implementation; otherwise STOP
  │
  ├─ Plan exists + new human comments since last agent response?
  │   → Respond to each comment (quote context, address feedback)
  │   → Update the plan comment if feedback requires plan changes
  │   → STOP
  │
  ├─ Plan exists + direct implementation request or 'agent:implementation-requested' label?
  │   → Run scope check (warn if high complexity)
  │   → Check for conflicting branches/PRs
  │   → BUILD (Steps 6–14)
  │
  ├─ 'agent:in-progress' label present?
  │   → Detect existing branch and resume if possible
  │   → Otherwise report current state
  │
  ├─ 'agent:pr-opened' label present?
  │   → Report that PR already exists, link to it
  │   → STOP
  │
  └─ Plan exists + no new comments + neither a direct implementation request nor 'agent:implementation-requested'?
      → Report: "Plan is posted and awaiting review. No new comments to address."
      → STOP
```

## Step 1: Fetch the Issue

The user provides an issue ID (e.g., `#42` or `42`). Strip any leading `#` and fetch:

```bash
gh issue view <id> --json number,title,body,state,labels,author
```

If the issue is closed, report that and stop.

If `topic:security` is present, stop. General build agents must not plan or implement security issues. Route planning/review to `review-security-issue` and authorized remediation to `fix-security-issue`.

In queue mode, stop before planning on `state:triage-needed` or `state:needs-info`, and stop on `state:validated` without roadmap placement. Require `state:accepted` or roadmap placement before queue work proceeds. If no plan exists, require `agent:plan-requested`; require `agent:implementation-requested` before queue-mode implementation.

In direct mode, inspect the same expected workflow state but do not stop because a lifecycle or agent-workflow label is absent or incomplete. Before continuing, warn the user with the specific discrepancy, for example:

> "Issue #42 is missing `state:accepted` or roadmap placement and `agent:implementation-requested`. Those labels are expected in the queued workflow, but your direct request authorizes implementation, so I am continuing without changing them."

If `state:triage-needed`, `state:needs-info`, or `state:validated` is present, name that state in the warning and explain what it normally means. Continue unless the issue lacks information that is actually necessary to perform the requested work; in that case, report the concrete missing information rather than treating the label itself as the blocker.

Never add or remove `state:accepted`, either human request label, or the `roadmap` label.

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
3. Whether this is direct mode and which phase the user requested
4. Which lifecycle and agent-workflow labels are present (`state:*`, `agent:plan-requested`, `agent:plan-ready`, `agent:implementation-requested`, `agent:in-progress`, and `agent:pr-opened`) and which discrepancies require a direct-mode warning

Follow the appropriate branch below.

---

## Branch A: Generate the Plan

If no plan comment exists, generate one when the user directly requested planning or implementation, or when `agent:plan-requested` is present. Otherwise report that no one has requested agent planning and stop.

### A1: Analyze the Issue with Principal Engineer Reviewer

Pass the issue title, description, labels, and any relevant code references to the `principal-engineer-reviewer` sub-agent. Use the Task tool:

```
Task tool with subagent_type="principal-engineer-reviewer"
```

In the prompt, instruct the reviewer to:

1. Read the issue's user story and identify what needs to change in the codebase. Treat reporter diagnostics or solution ideas as optional context, not as authoritative or current analysis.
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
9. Assess **gateway config documentation impact** — if the change adds, removes, renames, or changes defaults for gateway TOML keys or driver-specific config options, the plan must include an update to `docs/reference/gateway-config.mdx`. If the change is surfaced through Helm or a compute-driver overview, also include `docs/reference/sandbox-compute-drivers.mdx` or the relevant deployment docs.
10. Assess **LSM compatibility** — if the change touches process identity, `/proc` filesystem access, binary execution, or inter-process visibility, flag whether it will behave differently on hosts running SELinux (enforcing) or AppArmor. In particular, tests that fork+exec into system binaries will fail on SELinux-enforcing hosts due to cross-label `/proc/<pid>/exe` access restrictions.

Perform this investigation against the current branch and current product behavior. If the issue contains earlier diagnostics, verify them rather than relying on them.

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
- <docs expected per AGENTS.md, or "None expected">

---
*Revision 1 — initial plan*
EOF
)"
```

### A3: Mark the Plan Ready in Queue Mode

If `agent:plan-requested` was present, replace it with `agent:plan-ready`. Do not add `agent:plan-ready` for a direct invocation that was not already using the label workflow.

```bash
gh issue edit <id> --remove-label "agent:plan-requested" --add-label "agent:plan-ready"
```

If the direct request authorized implementation, continue to Branch C. Otherwise report that the plan has been posted and stop. In queue mode, a human reviews the plan and applies `agent:implementation-requested` before an unattended agent can build.

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

Proceed with implementation when the plan exists and either the user directly requested implementation or `agent:implementation-requested` is present. An existing `agent:in-progress` or `agent:pr-opened` label still triggers the resume or existing-PR checks below.

### Step 4: Scope Check

Read the plan comment and check the **Complexity** and **Confidence** fields.

- **If Complexity is High or Confidence is Low**, warn the user:

  > "This issue is rated High complexity / Low confidence. The plan includes open questions that may need human decisions during implementation. Proceeding, but flagging this for your awareness."

  Continue — do not hard-stop. The user directly requested implementation or chose to apply `agent:implementation-requested`.

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

### Step 7: Mark Queue Work In Progress

If `agent:implementation-requested` is present, replace it and `agent:plan-ready` with `agent:in-progress`. In direct mode without a request label, do not add an agent-workflow label.

```bash
gh issue edit <id> --remove-label "agent:implementation-requested" --remove-label "agent:plan-ready" --add-label "agent:in-progress"
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
# Run pre-commit checks (linting, formatting, license headers)
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

If E2E files were modified, run the relevant E2E lane for the driver touched by the change:

```bash
# Docker-backed gateway smoke E2E
mise run e2e:docker
```

Use `mise run e2e:podman`, `mise run e2e:vm`, or a Helm-backed Kubernetes E2E lane when the change targets those drivers.

**E2E retry loop** (up to 3 attempts):

1. Run the selected E2E lane.
2. If tests fail:
   - Read the pytest output carefully — identify which tests failed and why.
   - Distinguish between **test bugs** (the test itself is wrong) and **implementation bugs** (the code under test is wrong).
   - Fix the failing code or tests.
   - Decrement the retry counter and try again.
3. If tests pass, Phase 2 is green.

**If all 3 E2E attempts fail**, stop and report to the user:
- Which E2E tests are failing
- The pytest output from the last attempt
- Whether the failures appear to be test issues or implementation issues
- That manual intervention is needed

Do not proceed to PR creation if E2E verification is not green.

### Step 11: Update Documentation

Review the documentation requirements in `AGENTS.md` and update any affected
docs as part of the implementation. Keep documentation changes scoped to the
behavior or subsystem that changed.

If the implementation changes gateway TOML parsing, `[openshell.gateway]`
fields, `[openshell.drivers.<name>]` fields, driver config defaults, or Helm
rendering of `gateway.toml`, update `docs/reference/gateway-config.mdx` in the
same branch. If the change affects user-facing compute-driver setup, also
update `docs/reference/sandbox-compute-drivers.mdx` or the relevant deployment
page.

Use the `sync-agent-infra` skill's maintenance map to identify related skill updates when the implementation changes behavior, commands, or development workflows. Run its full consistency check when the implementation adds, removes, or renames skills or crates; changes workflow relationships or skill coverage; modifies issue or PR templates; or changes agent cross-references. Fix any drift before committing.

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

**Documentation updated:**
- `<doc path>`: <what was updated, or "None needed">
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
- <list of updated docs, or "None needed">

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
| **Command** | `<selected e2e command>` |
| **Gateway mode** | `<docker / podman / vm / helm>` |
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

If `agent:in-progress` is present, replace it with `agent:pr-opened`. Do not add `agent:pr-opened` for an unlabeled direct invocation:

```bash
gh issue edit <id> --remove-label "agent:in-progress" --add-label "agent:pr-opened"
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

If the `agent:in-progress` label is present, the skill was previously started but may not have completed.

1. Check for an existing branch matching the issue ID:
   ```bash
   git branch -r | grep -i "<issue-id>"
   ```
2. If found, check it out and inspect the state (are there uncommitted changes? committed but not pushed? pushed but no PR?).
3. Resume from the appropriate step (9, 10, 12, or 13).
4. If the state is unrecoverable, report to the user and suggest starting fresh. Queue mode requires a human to reapply `agent:implementation-requested`; a new direct implementation request can resume without it.

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
| `mise run pre-commit` | Run pre-commit checks (lint, format, license headers) |
| `mise run e2e:docker` | Run smoke E2E against a standalone Docker-backed gateway |
| `mise run e2e:podman` | Run smoke E2E against a Podman-backed gateway |
| `mise run e2e:vm` | Run smoke E2E against the VM compute driver |

## Example Usage

### First run — no plan exists

User says: "Plan issue #42"

1. Fetch issue #42 — title: "Add pagination to dataset list endpoint"
2. Notice that `state:accepted` and `agent:plan-requested` are absent; warn that the issue does not match the queued workflow, then continue because the user directly requested planning
3. Fetch comments — no `🏗️ build-plan` marker found
4. Pass issue to `principal-engineer-reviewer` for analysis
5. Reviewer produces a plan: feat type, Medium complexity, 3 implementation steps, unit + integration tests needed
6. Post the plan comment with the `🏗️ build-plan` marker
7. Because this direct invocation was unlabeled, leave the `agent:*` workflow labels unchanged
8. Report to user: "Plan posted on issue #42. Awaiting review."

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

### Fourth run — implementation requested

User says: "Build issue #42"

1. Fetch issue #42 — `state:accepted` is present but `agent:implementation-requested` is absent; warn about the missing queue label and continue because the user directly requested implementation
2. Plan exists (Revision 2), complexity: Medium, confidence: High
3. No conflicting branches or PRs
4. Create branch `feat/42-add-pagination/jmyers`
5. Leave `agent:*` labels unchanged because this direct invocation was not picked up from the queue
6. Implement pagination for both endpoints per the plan
7. Add unit tests for pagination logic, integration tests for both endpoints
8. `mise run pre-commit` passes on first attempt
9. E2E tests skipped (no changes under `e2e/`)
10. Commit, push, create PR with `Closes #42`
11. Post summary comment on issue with PR link
12. No agent-workflow label transition is needed
13. Report PR URL and workflow run status to user

### Run directly on an issue outside the workflow state machine

User says: "Build issue #42"

1. Fetch issue #42 — it has `state:triage-needed`; neither `state:accepted` nor `agent:implementation-requested` is present
2. Warn that triage and acceptance are incomplete and name the missing implementation request label
3. Continue through planning and implementation because the user directly requested the work
4. Do not add, remove, or reinterpret lifecycle or agent-workflow labels

### Run on issue with existing PR

User says: "Build issue #42"

1. Fetch issue #42 — `agent:pr-opened` label present
2. Find existing PR #789 linked to the issue
3. Report: "PR [#789](...) already exists for issue #42. Nothing to build."

### Run on high-complexity issue

User says: "Build issue #99"

1. Fetch issue #99 — warn about any missing expected workflow labels, then continue because the user directly requested implementation
2. Plan exists: complexity High, confidence Low, has open questions
3. Warn user: "Issue #99 is rated High complexity / Low confidence. Proceeding but flagging for your awareness."
4. Continue with build
