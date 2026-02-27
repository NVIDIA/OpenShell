---
name: review-gitlab-mr
description: Review a GitLab merge request by summarizing its diff and key design decisions. Use when the user wants to review an MR, understand changes in a branch, or get a code review summary. Trigger keywords - review MR, review merge request, summarize MR, summarize diff, code review, review branch, MR summary, diff summary.
---

# Review GitLab Merge Request

Summarize a GitLab merge request diff, highlighting key design decisions and notable code snippets.

## Prerequisites

- The `glab` CLI must be configured for `gitlab-master.nvidia.com`
- You must be in a git repository with a GitLab remote

## Shell Permissions

When running `glab` commands, always use `required_permissions: ["all"]` to avoid TLS certificate verification issues with the corporate GitLab instance.

**Troubleshooting:** If glab commands fail with TLS errors, try prefixing with:

```bash
SSL_CERT_FILE=/etc/ssl/cert.pem glab ...
```

## Step 1: Resolve the MR

The user will provide either an **MR ID** (e.g., `!123` or `123`) or a **branch name**. Determine which input was given and resolve it to an MR.

### If an MR ID is provided

Strip any leading `!` and use the numeric ID directly. Proceed to Step 2.

### If a branch name is provided

Look up the open MR whose source branch matches:

```bash
glab mr list --source-branch="<branch>" --state=opened
```

- If exactly one MR is found, extract its IID and proceed to Step 2.
- If multiple MRs are found, list them and ask the user which one to review.
- If no MR is found, skip Step 2 (no MR description to fetch) and go directly to Step 3 using the local git diff fallback.

## Step 2: Fetch MR Description

Retrieve the MR metadata using the GitLab API:

```bash
glab api "projects/:id/merge_requests/<mr-iid>" | jq '{
  title: .title,
  description: .description,
  state: .state,
  source_branch: .source_branch,
  target_branch: .target_branch,
  labels: .labels,
  author: .author.username
}'
```

Record the **title**, **description**, **source_branch**, and **target_branch** for use in later steps.

## Step 3: Generate the Diff

### Primary: glab API diff

Fetch the diff via the GitLab API:

```bash
glab mr diff <mr-iid>
```

If this succeeds, use this diff and proceed to Step 4.

### Fallback: local git diff

If no MR exists (branch-only case) or the glab diff command fails, fall back to a local diff:

```bash
# Ensure both branches are available locally
git fetch origin <target-branch> <source-branch>

# Generate the diff
git diff origin/<target-branch>...origin/<source-branch>
```

If the user provided a branch name and no MR was found, diff against `main`:

```bash
git fetch origin main <branch>
git diff origin/main...origin/<branch>
```

### Handling large diffs

If the diff output is very large (thousands of lines), use the Task tool to process it in chunks. Summarize each chunk independently, then merge the summaries. Do not skip or truncate parts of the diff — accuracy depends on reading all of it.

## Step 4: Analyze and Summarize

Read through the full diff (and the MR description if available). Produce a summary with the following sections. Keep every section as concise as possible — brevity is a priority.

### Summary format

```
## MR Review: <title>

**MR:** [!<iid>](<url>)  ← only if an MR exists
**Author:** <author>
**Branch:** `<source>` → `<target>`

### Overview
<1-3 sentences describing what this MR does and why>

### Key Design Decisions
- <decision 1 with file:line reference>
- <decision 2 with file:line reference>
- ...

### Notable Code
<short fenced code snippets that illustrate the most important changes — max 3 snippets>

### Potential Concerns  ← omit if none
- <risk or issue worth discussing>
```

**Guidelines for the summary:**

- **Overview**: State what changed and why. Pull context from the MR description if available.
- **Key Design Decisions**: Focus on _why_ something was done a particular way, not _what_ changed. Include `file_path:line_number` references. Examples: choice of algorithm, new abstraction introduced, API contract change, migration strategy.
- **Notable Code**: Include only the most instructive or surprising snippets. Keep each snippet under 15 lines. Always include the file path above the code block.
- **Potential Concerns**: Only include if there are genuine risks — missing error handling, breaking changes, performance implications, security issues. Do not fabricate concerns.

## Step 5: Output

Print the summary directly in the chat as formatted markdown.

If the user requests it, also save the summary to a file:

```bash
# Default path
reviews/<mr-iid>-review.md

# Or for branch-only reviews
reviews/<branch-name>-review.md
```

## Useful Commands Reference

| Command | Description |
| --- | --- |
| `glab mr list --source-branch=<branch>` | Find MR by source branch |
| `glab mr diff <iid>` | Get MR diff via GitLab API |
| `glab api "projects/:id/merge_requests/<iid>"` | Get full MR metadata |
| `git diff origin/<target>...origin/<source>` | Local diff between branches |

## Example Usage

### Review by MR ID

User says: "Review MR !456"

1. Fetch MR metadata for IID 456
2. Fetch diff via `glab mr diff 456`
3. Produce summary

### Review by branch name

User says: "Review branch `feature/add-pagination`"

1. Look up MR with `glab mr list --source-branch="feature/add-pagination"`
2. If found, fetch MR metadata and diff
3. If not found, diff against main locally
4. Produce summary
