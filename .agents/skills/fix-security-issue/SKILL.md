---
name: fix-security-issue
description: Implement a fix for a reviewed security issue. Takes an issue number or scans for issues labeled "security" and "agent-ready". Reads the security review from the issue comments and implements the remediation plan. Trigger keywords - fix security issue, remediate security, implement security fix, patch vulnerability.
---

# Fix Security Issue

Implement a code fix for a security issue that has already been reviewed by the `review-security-issue` skill.

## Prerequisites

- The `glab` CLI must be configured for `gitlab-master.nvidia.com`
- You must be in a git repository with a GitLab remote
- The issue **must** have both the `security` and `agent-ready` labels. If either is missing, do not proceed.
- The issue must have a prior security review comment (posted by `review-security-issue`) with a **Legitimate concern** determination and a remediation plan

## Shell Permissions

When running `glab` commands, always use `required_permissions: ["all"]` to avoid TLS certificate verification issues with the corporate GitLab instance.

**Troubleshooting:** If glab commands fail with TLS errors, try prefixing with:

```bash
SSL_CERT_FILE=/etc/ssl/cert.pem glab ...
```

## Agent Comment Marker

All MR descriptions and comments posted by this skill **must** begin with the following marker line:

```
> **🔧 security-fix-agent**
```

This distinguishes fix-agent content from review-agent comments (`🔒 security-review-agent`) and human comments.

## Step 1: Identify the Issue

The user may provide an issue number directly, or ask the agent to find issues to fix.

### If an issue number is provided

Strip any leading `#` and proceed to Step 2 with that issue ID.

### If no issue number is provided

Scan for open issues labeled `security` and `agent-ready`:

```bash
glab api "projects/:id/issues?labels=security,agent-ready&state=opened" --paginate | jq '[.[] | {
  iid: .iid,
  title: .title,
  labels: .labels,
  updated_at: .updated_at
}]'
```

- **If no issues are found**, report to the user that there are no security issues ready for fixing and stop.
- **If one issue is found**, proceed to Step 2 with that issue.
- **If multiple issues are found**, list them for the user and ask which one to work on. If the user said to handle all of them, process them sequentially (one full fix cycle per issue).

## Step 2: Fetch the Issue and Validate Labels

Fetch the issue details:

```bash
glab api "projects/:id/issues/<id>" | jq '{
  iid: .iid,
  title: .title,
  description: .description,
  state: .state,
  labels: .labels,
  author: .author.username
}'
```

### Require both `security` and `agent-ready` labels

**This is a hard gate.** Check the issue's `labels` array from the response above. Both of the following labels **must** be present:

- `security`
- `agent-ready`

If **either label is missing**, do **not** proceed. Report to the user which label(s) are missing and stop. For example:

- Missing `agent-ready`: "Issue #42 has the `security` label but is not marked `agent-ready`. It may still need review or human triage before a fix can be implemented."
- Missing `security`: "Issue #42 is marked `agent-ready` but does not have the `security` label. This skill only handles security issues."
- Missing both: "Issue #42 is missing both the `security` and `agent-ready` labels. Cannot proceed."

**Do not offer to add the labels or bypass this check.** The labels are a deliberate human-controlled gate.

### Validate the security review

Once labels are confirmed, fetch the comments to find the security review:

```bash
glab api "projects/:id/issues/<id>/notes" --paginate | jq '[.[] | select(.body | contains("security-review-agent")) | {id: .id, body: .body, created_at: .created_at}]'
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

Use the `arch-doc-writer` sub-agent to update any architecture documentation affected by the fix. Use the Task tool:

```
Task tool with subagent_type="arch-doc-writer"
```

In the prompt, provide:
- Which files were changed and why
- The security context (what vulnerability was fixed)
- Which architecture docs in `architecture/` are likely affected

The `arch-doc-writer` will determine which docs need updating and make the changes. Common cases include:
- A new validation layer or middleware was added
- An API contract changed (new required headers, changed error responses, etc.)
- Access control or authentication flow was modified
- Network or infrastructure security boundaries changed

If the fix is purely internal (e.g., switching to parameterized queries with no external behavior change), documentation updates may not be needed -- let the `arch-doc-writer` make that determination.

## Step 8: Commit, Push, and Open MR

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

### Get the current GitLab username

```bash
USERNAME=$(glab api user | jq -r '.username')
```

### Create the MR

Create an MR that closes the security issue. Put the full fix summary in the MR description rather than commenting on the issue -- the `Closes #<id>` directive will auto-close the issue when merged.

```bash
glab mr create \
  --title "fix(security): <short description>" \
  --assignee "$USERNAME" \
  --label "security" \
  --remove-source-branch \
  --squash-before-merge \
  --yes \
  --description "$(cat <<'EOF'
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
- `<architecture/doc.md>`: <what was updated>

### Verification
<how the fix was verified — tests passed, exploit scenario tested, etc.>
EOF
)"
```

**Display the MR URL** so it's easily clickable:

```
Created MR [!<iid>](https://gitlab-master.nvidia.com/navigator/navigator/-/merge_requests/<iid>)
```

## Step 9: Report to User

Summarize what was done:

1. Which issue was addressed and link to it
2. What the vulnerability was
3. What changes were made (files, approach)
4. What tests were added and at which level (unit, integration, e2e)
5. What documentation was updated
6. Link to the MR

## Useful Commands Reference

| Command | Description |
| --- | --- |
| `glab api "projects/:id/issues?labels=security,agent-ready&state=opened"` | Find open security issues ready for fixing |
| `glab api "projects/:id/issues/<id>"` | Fetch full issue metadata |
| `glab api "projects/:id/issues/<id>/notes" --paginate` | Fetch all comments on an issue |
| `glab mr create --title "..." --description "..."` | Create a merge request |
| `glab api user \| jq -r '.username'` | Get current GitLab username |
| `glab issue view <id>` | View issue details |
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
7. Run `arch-doc-writer` to update `architecture/sandbox.md` with the new input validation layer
8. Commit, push, and open MR with `Closes #42`
9. Report the MR link and changes to the user

### Scan and fix agent-ready issues

User says: "Fix any ready security issues"

1. Query for open issues with labels `security` + `agent-ready`
2. Find issue #78: "SQL injection in search endpoint"
3. Fetch the review comment -- determination is "Legitimate concern"
4. Implement parameterized queries
5. Add `test_rejects_sql_injection_in_search_query` unit test and e2e test for the search endpoint
6. `arch-doc-writer` updates API docs to note the query parameter validation
7. Commit, push, open MR with `Closes #78`, report to user

### Issue with non-actionable review

User says: "Fix security issue #99"

1. Fetch issue #99 and its comments
2. Find the `security-review-agent` review with determination "Not actionable"
3. Report to the user: "Issue #99 was reviewed and determined to be not actionable. No fix is needed."
4. Stop

### Issue missing `agent-ready` label

User says: "Fix security issue #55"

1. Fetch issue #55 metadata
2. Labels are `["security"]` -- missing `agent-ready`
3. Report to the user: "Issue #55 has the `security` label but is not marked `agent-ready`. It may still need review or human triage before a fix can be implemented."
4. Stop

### Issue without a review

User says: "Fix security issue #60"

1. Fetch issue #60 metadata -- labels include both `security` and `agent-ready`
2. Fetch comments -- no `security-review-agent` comment found
3. Report to the user: "Issue #60 has not been reviewed yet. Run the review-security-issue skill first."
4. Stop
