---
name: review-security-issue
description: Given a GitHub issue, review the issue for security implications. You'll make a determination if the claim in the issue is legitimate and should be addressed or will be a "won't fix." Trigger keywords - security issue, review security ticket, review security issue.
---

# Review Security Issue

Review an issue that outlines a security, vulnerability, or privacy concern.

## Prerequisites

- The `gh` CLI must be authenticated (`gh auth status`)
- You must be in a git repository with a GitHub remote

## Agent Comment Marker

All comments posted by this skill **must** begin with the following marker line so that prior reviews can be detected and human comments can be distinguished from agent comments:

```
> **🔒 security-review-agent**
```

This marker is used in Step 2 to detect prior reviews and in Step 5 to distinguish agent comments from human comments.

## Step 1: Fetch the Issue

The user will provide an issue ID (e.g., `#42` or `42`). Strip any leading `#` and fetch the issue contents.

```bash
gh issue view <id>
```

To also retrieve the full issue body as JSON (useful for parsing):

```bash
gh issue view <id> --json title,body,state,labels,author
```

## Step 2: Check if Review is Needed

First, check the issue's labels from the metadata fetched in Step 1.

- **If the issue has the `state:agent-ready` label**, the issue has already been reviewed and is ready for implementation. There is no review to perform. Report to the user that this issue is already reviewed and marked as `state:agent-ready`, and suggest using the `fix-security-issue` skill instead. Stop.

Next, fetch existing comments on the issue:

```bash
gh issue view <id> --json comments --jq '.comments[].body'
```

Search the comments for the agent marker (`> **🔒 security-review-agent**`).

- **If the marker is found** and no subsequent human comments exist that ask follow-up questions or challenge the review, you are done. Report to the user that a review already exists.
- **If the marker is found** but there are newer human comments with questions or objections, proceed to Step 5 to address them.
- **If the marker is not found**, proceed to Step 3.

## Step 3: Analyze the Issue

Pass the issue title, description, and any relevant code references to the `principal-engineer-reviewer` sub-agent for analysis. Use the Task tool:

```
Task tool with subagent_type="principal-engineer-reviewer"
```

In the prompt, instruct the reviewer to approach the issue with a security-focused lens, specifically evaluating:

- **Validity**: Is this a real security, vulnerability, or privacy concern?
- **Severity**: What is the potential impact (data exposure, privilege escalation, denial of service, etc.)?
- **Exploitability**: How easy is it to exploit? Does it require authentication, specific conditions, or access?
- **Attack scenario**: What are the concrete steps an attacker would take to exploit this, from their perspective?
- **Affected surface**: Which components, endpoints, or code paths are affected?
- **Recommendation**: Should this be fixed, mitigated, accepted as risk, or closed as not actionable?

## Step 4: Post the Review

Based on the analysis from Step 3, post a comment on the issue.

### If the concern is legitimate

Post a comment with a remediation plan:

```bash
gh issue comment <id> --body "$(cat <<'EOF'
> **🔒 security-review-agent**

## Security Review

**Determination:** Legitimate concern

### Summary
<1-3 sentences describing the security issue and its impact>

### Severity Assessment
- **Impact:** <high / medium / low>
- **Exploitability:** <description of attack vector and prerequisites>
- **Affected components:** <list of affected code paths or services>

### Attack Scenario
Step-by-step from the attacker's perspective:
1. <attacker's first action — e.g., crafts a malicious payload>
2. <attacker's second action — e.g., sends request to endpoint>
3. <resulting impact — e.g., gains access to sensitive data>

### Remediation Plan
1. <step 1 with file/component references>
2. <step 2>
3. ...

### Additional Notes
<any caveats, trade-offs, or related concerns>
EOF
)"
```

### If the concern is not actionable

Post a comment with a rationale:

```bash
gh issue comment <id> --body "$(cat <<'EOF'
> **🔒 security-review-agent**

## Security Review

**Determination:** Not actionable

### Rationale
<clear explanation of why this is not a security concern, including any mitigating factors already in place>

### References
<links to documentation, code, or standards that support the determination>
EOF
)"
```

## Step 5: Add `state:review-ready` Label

After posting the review comment (whether legitimate or not actionable), add the `state:review-ready` label to the issue:

```bash
gh issue edit <id> --add-label "state:review-ready"
```

This signals to humans and downstream skills (e.g., `fix-security-issue`) that the review is complete.

## Step 6: Address Follow-up Comments

After posting (or if a prior review exists with new human comments), review all comments that do **not** contain the `> **🔒 security-review-agent**` marker. These are human comments.

For each unanswered human comment:

1. Read the question or objection.
2. Formulate a response based on the codebase and the prior security analysis.
3. Post a reply that begins with the agent marker.

**Important:** The authenticated user posting these comments may be a real person's account. Humans may reply to your comments directly. Always use the agent marker to distinguish your comments from theirs.

## Useful Commands Reference

| Command | Description |
| --- | --- |
| `gh issue view <id>` | View issue details |
| `gh issue view <id> --json title,body,state,labels,author` | Fetch full issue metadata as JSON |
| `gh issue view <id> --json comments --jq '.comments[].body'` | Fetch all comments on an issue |
| `gh issue comment <id> --body "..."` | Post a comment on an issue |
| `gh issue edit <id> --add-label "state:review-ready"` | Add a label to an issue |

## Example Usage

### Review a security issue

User says: "Review security issue #42"

1. Fetch issue #42 via `gh issue view 42`
2. Fetch comments and check for the `security-review-agent` marker
3. No prior review found -- pass issue to `principal-engineer-reviewer` with security lens
4. Reviewer determines it's a legitimate XSS vulnerability in the API response handler
5. Post a comment with severity assessment and remediation plan
6. Add the `state:review-ready` label to the issue
7. Report the finding and posted comment to the user

### Re-review with new comments

User says: "Check on security issue #42 again"

1. Fetch issue #42 and its comments
2. Find existing `security-review-agent` review from a prior run
3. Detect two new human comments asking about scope of the vulnerability
4. Post responses to each, prefixed with the agent marker
5. Report to the user what was addressed
