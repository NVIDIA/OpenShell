---
name: fix-security-issue
description: Implement a fix for a reviewed security issue. Takes a directly requested issue number or scans for issues labeled `topic:security` and `agent:implementation-requested`. Reads the security review from the issue comments and implements the remediation plan. Trigger keywords - fix security issue, remediate security, implement security fix, patch vulnerability.
---

# Fix Security Issue

Implement a code fix for a security issue that has already been reviewed by the `review-security-issue` skill.

## Prerequisites

- The `gh` CLI must be authenticated (`gh auth status`)
- You must be in a git repository with a GitHub remote
- The issue must have `topic:security`. In unattended scan mode it must also have `agent:implementation-requested`; for a direct user request, warn if that workflow label is missing and continue without changing it.
- The issue must have a prior security review comment (posted by `review-security-issue`) with a **Legitimate concern** determination and a remediation plan

## Agent Comment Marker

All PR descriptions and comments posted by this skill **must** begin with the following marker line:

```
> **🔧 security-fix-agent**
```

This distinguishes fix-agent content from review-agent comments (`🔒 security-review-agent`) and human comments.

## Step 1: Identify the Issue

The user may provide an issue number directly, or ask the agent to find issues to fix.

### If an issue number is provided

Strip any leading `#` and proceed to Step 2 with that issue ID. The user's explicit fix request authorizes implementation. If `agent:implementation-requested` is absent, warn that the expected workflow label is missing and continue without changing it.

### If no issue number is provided

Scan for open issues labeled `topic:security` and `agent:implementation-requested`:

```bash
gh issue list --label "topic:security" --label "agent:implementation-requested" --state open --json number,title,labels,updatedAt
```

- **If no issues are found**, report to the user that there are no security issues ready for fixing and stop.
- **If one issue is found**, proceed to Step 2 with that issue.
- **If multiple issues are found**, list them for the user and ask which one to work on. If the user said to handle all of them, process them sequentially (one full fix cycle per issue).

## Step 2: Fetch the Issue and Validate Labels

Fetch the issue details:

```bash
gh issue view <id> --json number,title,body,state,labels,author
```

### Validate the Security Label and Invocation Mode

Check the issue's `labels` array from the response above:

- `topic:security` is required because this specialized skill handles security issues.
- `agent:implementation-requested` is required only when an unattended agent discovered the issue by scanning the queue.

If `topic:security` is missing, report that this skill only handles security issues and stop. If queue mode selected an issue without `agent:implementation-requested`, report that it is not ready for unattended pickup and stop.

Never apply `agent:implementation-requested` yourself. In direct mode, warn about its absence and continue; the missing label does not block the user's request to fix the specific issue.

### Validate the security review

Once labels are confirmed, fetch the comments to find the security review:

```bash
gh issue view <id> --json comments --jq '[.comments[] | select(.body | contains("security-review-agent"))]'
```

- **If no `security-review-agent` comment is found**, report to the user that this issue has not been reviewed yet. Suggest running the `review-security-issue` skill first. Stop.
- **If the review determination is "Not actionable"**, report to the user that the review found no actionable concern. There is nothing to fix. Stop.
- **If the review determination is "Legitimate concern"**, extract the **Remediation Plan** and **Severity Assessment** sections from the review comment. Proceed to Step 3.

## Step 3: Plan the Implementation

Before writing code, analyze the remediation plan from the review comment:

1. Identify all files and components mentioned in the remediation plan.
2. Read those files to understand the current code.
3. Determine if the remediation plan is still accurate given the current state of the code (the codebase may have changed since the review).
4. Break the fix into discrete, testable changes.

If the remediation plan references files or components that no longer exist or have changed significantly, adapt the plan accordingly and note the deviations.

## Step 4: Create a Branch

Create a working branch for the fix:

```bash
git checkout -b fix/security-<issue-id>-<short-description>
```

Follow the project's branch naming conventions. The branch name should reference the issue ID.

In queue mode, replace the human request and ready-plan labels with the agent execution state. For an unlabeled direct invocation, do not add an agent-workflow label:

```bash
gh issue edit <id> --remove-label "agent:implementation-requested" --remove-label "agent:plan-ready" --add-label "agent:in-progress"
```

## Step 5: Implement the Fix

Implement the changes described in the remediation plan. Follow these principles:

- **Minimal scope**: Only change what is necessary to address the security concern. Avoid unrelated refactors.
- **Defense in depth**: Where appropriate, add multiple layers of protection (input validation, output encoding, access checks, etc.).
- **No regressions**: Ensure existing tests still pass after the fix.

After implementing, run the project's pre-commit checks:

```bash
mise run pre-commit
```

Fix any issues that arise before proceeding.

## Step 6: Write Tests

Every security fix **must** include tests that verify the vulnerability is resolved. Choose the appropriate test level(s) based on the nature of the fix:

### Unit tests

Add unit tests when the fix changes a specific function, method, or module in isolation. Place them alongside the existing tests for that module (e.g., same `tests/` directory or `#[cfg(test)]` block for Rust, `test_*.py` for Python).

Unit tests should cover:
- The previously-vulnerable code path now rejects malicious input or behaves correctly
- Edge cases around the security boundary (empty input, oversized input, special characters, etc.)
- That legitimate inputs continue to work as before

### Integration / E2E tests

Add integration or end-to-end tests when the vulnerability spans multiple components or is triggered via an API endpoint, CLI command, or network boundary. Place them in the project's existing integration or e2e test directories.

Integration tests should cover:
- The full attack scenario described in the security review is no longer exploitable
- The fix holds under realistic conditions (authenticated vs. unauthenticated, different roles, etc.)

### Test naming

Name tests descriptively to document the security concern:
- `test_rejects_sql_injection_in_search_query`
- `test_blocks_path_traversal_in_file_upload`
- `test_enforces_auth_on_admin_endpoint`

### Verify

Run the full relevant test suite to confirm both the new tests pass and no existing tests regress:

```bash
# Run tests relevant to the changed components
# The specific command depends on the project area affected
```

If the review identified a specific exploit scenario, verify that it is no longer possible with the fix in place.

## Step 7: Update Documentation

Review the documentation requirements in `AGENTS.md` and update any affected
docs as part of the security fix. If the fix is purely internal, such as
switching to parameterized queries with no external behavior change,
documentation updates may not be needed.

## Step 8: Commit, Push, and Open PR

### Commit

Commit all changes (implementation, tests, and documentation) using conventional commit format:

```bash
git add <files>
git commit -m "$(cat <<'EOF'
fix(security): <short description of the fix>

Closes #<issue-id>

<brief explanation of what was vulnerable and how it's fixed>
EOF
)"
```

### Push

```bash
git push -u origin HEAD
```

### Create the PR

Create a PR that closes the security issue. Put the full fix summary in the PR description rather than commenting on the issue -- the `Closes #<id>` directive will auto-close the issue when merged.

```bash
gh pr create \
  --title "fix(security): <short description>" \
  --label "topic:security" \
  --body "$(cat <<'EOF'
> **🔧 security-fix-agent**

Closes #<issue-id>

## Security Fix

### Summary
<1-3 sentences describing the security issue and how it was fixed>

### Severity Assessment
- **Impact:** <high / medium / low>
- **Exploitability:** <description of attack vector and prerequisites>
- **Affected components:** <list of affected code paths or services>

### Changes Made
- `<file1>`: <what changed and why>
- `<file2>`: <what changed and why>

### Tests Added
- **Unit:** <test file and what it covers>
- **Integration/E2E:** <test file and what it covers, or "N/A" if not applicable>

### Documentation Updated
- `<doc path>`: <what was updated, or "None needed">

### Verification
<how the fix was verified -- tests passed, exploit scenario tested, etc.>
EOF
)"
```

**Display the PR URL** so it's easily clickable:

```
Created PR [#<number>](https://github.com/OWNER/REPO/pull/<number>)
```

In queue mode, replace `agent:in-progress` with `agent:pr-opened` after the PR is created. For an unlabeled direct invocation, do not add an agent-workflow label:

```bash
gh issue edit <id> --remove-label "agent:in-progress" --add-label "agent:pr-opened"
```

## Step 9: Report to User

Summarize what was done:

1. Which issue was addressed and link to it
2. What the vulnerability was
3. What changes were made (files, approach)
4. What tests were added and at which level (unit, integration, e2e)
5. What documentation was updated
6. Link to the PR

## Useful Commands Reference

| Command | Description |
| --- | --- |
| `gh issue list --label "topic:security" --label "agent:implementation-requested" --state open` | Find security issues whose fixes a human requested |
| `gh issue view <id> --json number,title,body,state,labels,author` | Fetch full issue metadata |
| `gh issue view <id> --json comments` | Fetch all comments on an issue |
| `gh pr create --title "..." --body "..."` | Create a pull request |
| `gh api user --jq '.login'` | Get current GitHub username |
| `gh issue view <id>` | View issue details |
| `mise run pre-commit` | Run pre-commit checks |

## Example Usage

### Fix a specific issue

User says: "Fix security issue #42"

1. Fetch issue #42 and its comments
2. Find the `security-review-agent` review with determination "Legitimate concern"
3. Extract the remediation plan (e.g., add input sanitization to API handler)
4. Create branch `fix/security-42-input-sanitization`
5. Implement the fix
6. Add unit tests for the sanitization function and an integration test for the endpoint
7. Update affected documentation per `AGENTS.md`, if needed
8. Commit, push, and open PR with `Closes #42`
9. Report the PR link and changes to the user

### Scan and fix requested security issues

User says: "Fix any ready security issues"

1. Query for open issues with labels `topic:security` + `agent:implementation-requested`
2. Find issue #78: "SQL injection in search endpoint"
3. Fetch the review comment -- determination is "Legitimate concern"
4. Implement parameterized queries
5. Add `test_rejects_sql_injection_in_search_query` unit test and e2e test for the search endpoint
6. Update affected documentation per `AGENTS.md`, if needed
7. Commit, push, open PR with `Closes #78`, report to user

### Issue with non-actionable review

User says: "Fix security issue #99"

1. Fetch issue #99 and its comments
2. Find the `security-review-agent` review with determination "Not actionable"
3. Report to the user: "Issue #99 was reviewed and determined to be not actionable. No fix is needed."
4. Stop

### Directly requested issue without `agent:implementation-requested`

User says: "Fix security issue #55"

1. Fetch issue #55 metadata
2. Labels are `["topic:security"]` -- missing `agent:implementation-requested`
3. Confirm that a legitimate security review and remediation plan exist
4. Warn that `agent:implementation-requested` is missing from the expected workflow state
5. Proceed because the user's direct request authorizes implementation; leave the labels unchanged

### Issue without a review

User says: "Fix security issue #60"

1. Fetch issue #60 metadata -- `topic:security` is present and the user directly requested the fix
2. Fetch comments -- no `security-review-agent` comment found
3. Report to the user: "Issue #60 has not been reviewed yet. Run the review-security-issue skill first."
4. Stop
