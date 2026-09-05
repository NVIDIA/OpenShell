---
name: review-github-pr
description: Review a GitHub pull request by summarizing its diff and key design decisions. Use when the user wants to review a PR, understand changes in a branch, or get a code review summary. Trigger keywords - review PR, review pull request, summarize PR, summarize diff, code review, review branch, PR summary, diff summary.
metadata:
  internal: true
---

# Review GitHub Pull Request

Summarize a GitHub pull request diff, highlighting key design decisions and notable code snippets.

## Prerequisites

- The `gh` CLI must be authenticated (`gh auth status`)
- You must be in a git repository with a GitHub remote

## Step 1: Resolve the PR

The user will provide either a **PR number** (e.g., `#123` or `123`) or a **branch name**. Determine which input was given and resolve it to a PR.

### If a PR number is provided

Strip any leading `#` and use the numeric ID directly. Proceed to Step 2.

### If a branch name is provided

Look up the open PR whose head branch matches:

```bash
gh pr list --head "<branch>" --state open
```

- If exactly one PR is found, extract its number and proceed to Step 2.
- If multiple PRs are found, list them and ask the user which one to review.
- If no PR is found, skip Step 2 (no PR description to fetch) and go directly to Step 3 using the local git diff fallback.

## Step 2: Fetch PR Description

Retrieve the PR metadata:

```bash
gh pr view <number> --json title,body,state,headRefName,baseRefName,labels,author
```

Record the **title**, **body**, **headRefName**, and **baseRefName** for use in later steps.

## Step 3: Generate the Diff

### Primary: gh pr diff

Fetch the diff via the GitHub CLI:

```bash
gh pr diff <number>
```

If this succeeds, use this diff and proceed to Step 4.

### Fallback: local git diff

If no PR exists (branch-only case) or the gh diff command fails, fall back to a local diff:

```bash
# Ensure both branches are available locally
git fetch origin <target-branch> <source-branch>

# Generate the diff
git diff origin/<target-branch>...origin/<source-branch>
```

If the user provided a branch name and no PR was found, diff against `main`:

```bash
git fetch origin main <branch>
git diff origin/main...origin/<branch>
```

### Handling large diffs

If the diff output is very large (thousands of lines), use the Task tool to process it in chunks. Summarize each chunk independently, then merge the summaries. Do not skip or truncate parts of the diff — accuracy depends on reading all of it.

## Step 4: Analyze and Summarize

Read through the full diff (and the PR description if available). Produce a summary with the following sections. Keep every section as concise as possible — brevity is a priority.

### Summary format

```
## PR Review: <title>

**PR:** [#<number>](<url>)  <- only if a PR exists
**Author:** <author>
**Branch:** `<source>` -> `<target>`

### Overview
<1-3 sentences describing what this PR does and why>

### Key Design Decisions
- <decision 1 with file:line reference>
- <decision 2 with file:line reference>
- ...

### Notable Code
<short fenced code snippets that illustrate the most important changes -- max 3 snippets>

### Potential Concerns  <- omit if none
- **<concise user-visible behavior>** — Before this PR, <affected persona>
  experienced <previous behavior>. With this PR, <new concerning behavior>, so
  <user-visible impact>. Details: `<file>:<line>`.
```

**Guidelines for the summary:**

- **Overview**: State what changed and why. Pull context from the PR description if available.
- **Key Design Decisions**: Focus on _why_ something was done a particular way, not _what_ changed. Include `file_path:line_number` references. Examples: choice of algorithm, new abstraction introduced, API contract change, migration strategy.
- **Notable Code**: Include only the most instructive or surprising snippets. Keep each snippet under 15 lines. Always include the file path above the code block.
- **Potential Concerns**: Only include genuine risks that warrant a change or a
  deliberate accept/reject decision. Describe each concern in terms of observable
  behavior for the affected persona, such as a sandbox creator, sandbox user,
  operator, administrator, SDK consumer, or developer maintaining the system.
  Always compare the previous behavior with the new concerning behavior and state
  the resulting user-visible impact. Prefer the compact form: "Before this PR,
  `<persona>` experienced `<old behavior>`. With this PR, `<new behavior>`, so
  `<impact>`." Add only the minimum file and line references needed to substantiate
  the finding.
  - Use the PR base as the normal previous-behavior baseline. Review older history
    only when the change is fixing or extending an earlier feature and that history
    is necessary to explain the behavioral contract. In that case, describe the
    relevant transitions explicitly: "Before `<commit>`, ... After `<commit>`, ...
    With this PR, ...".
  - Translate internal failure modes and race conditions into what the affected
    person would observe. Internal implementation details belong in the trailing
    file and line references, not in place of the behavior description.
  - Do not assign P0/P1/P2 or similar priority labels. The behavioral comparison
    and impact should give maintainers enough context to accept or reject the
    suggested change.
  - Do not fabricate concerns or claim a behavioral regression without evidence
    for both the prior and proposed behavior.
- **Agent infrastructure**: When the PR changes behavior, commands, or development workflows, use the `sync-agent-infra` maintenance map to check that related skills were updated. When it adds, removes, or renames skills or crates; changes workflow relationships or skill coverage; modifies issue or PR templates; or changes agent cross-references, apply the full consistency checklist. Report missing companion updates or drift under **Potential Concerns**.

## Step 5: Output

Print the summary directly in the chat as formatted markdown.

If the user requests it, also save the summary to a file:

```bash
# Default path
reviews/<number>-review.md

# Or for branch-only reviews
reviews/<branch-name>-review.md
```

## Useful Commands Reference

| Command | Description |
| --- | --- |
| `gh pr list --head <branch>` | Find PR by head branch |
| `gh pr diff <number>` | Get PR diff |
| `gh pr view <number> --json ...` | Get full PR metadata |
| `git diff origin/<target>...origin/<source>` | Local diff between branches |

## Example Usage

### Review by PR number

User says: "Review PR #456"

1. Fetch PR metadata for number 456
2. Fetch diff via `gh pr diff 456`
3. Produce summary

### Review by branch name

User says: "Review branch `feature/add-pagination`"

1. Look up PR with `gh pr list --head "feature/add-pagination"`
2. If found, fetch PR metadata and diff
3. If not found, diff against main locally
4. Produce summary
