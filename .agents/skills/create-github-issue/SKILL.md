---
name: create-github-issue
description: Create GitHub issues using the gh CLI. Use when the user wants to create a new issue, report a bug, create a linked feature request discussion issue, or create a task in GitHub. Trigger keywords - create issue, new issue, file bug, report bug, feature request issue, github issue.
---

# Create GitHub Issue

Create issues on GitHub using the `gh` CLI. Issues must conform to the project's issue templates.

## Prerequisites

The `gh` CLI must be authenticated (`gh auth status`).

## Issue Templates

This project uses YAML form issue templates. When creating issues, match the template structure so the output aligns with what GitHub renders.

### Bug Reports

Do not add a type label automatically. The body must include an **Agent Diagnostic** section — this is required by the template and enforced by project convention. Apply area or topic labels only when they are clearly known.

```bash
gh issue create \
  --title "bug: <concise description>" \
  --body "$(cat <<'EOF'
## Agent Diagnostic

<Paste the output from the agent's investigation. What skills were loaded?
What was found? What was tried?>

## Description

**Actual behavior:** <what happened>

**Expected behavior:** <what should happen>

## Reproduction Steps

1. <step>
2. <step>

## Environment

- OS: <os>
- Docker: <version>
- OpenShell: <version>

## Logs

```
<relevant output>
```
EOF
)"
```

### Feature Requests

Feature request issues are discussion threads for completed feature request
documents. They are not the first artifact for substantial feature ideas.

If the user asks to create a feature issue but does not have a completed,
GitHub-visible feature request doc or PR, do not create the issue yet. Tell the
user to use `create-feature-request` first.

If the user already has a PR containing the completed feature request doc, use
that PR as the link target. Confirm the PR contains or links to a
`feature-requests/NNNN-*/README.md` document before creating the issue.

Useful PR lookup:

```bash
gh pr view <pr-number-or-url> --json title,url,body,files
```

Do not add a type label automatically. Apply area or topic labels only when
they are clearly known.

```bash
gh issue create \
  --title "feat: <concise feature title>" \
  --body "$(cat <<'EOF'
## Feature request document or PR

<Link the completed feature request document, or the PR containing it if the
document is not merged yet.>

## Summary

<Briefly summarize the feature and user-visible outcome.>

## Review focus

<What feedback do you want from maintainers?>

## Related work and prior art

<Link related issues, discussions, docs, examples, or similar features in other
projects.>

## Checklist

- [ ] The linked feature request doc or PR is complete and ready for discussion
- [ ] The linked feature request doc describes product requirements, not an implementation plan
EOF
)"
```

After creating a feature request discussion issue, report the issue URL and
suggest adding it back to the feature request doc front matter and PR
description. Do not update the PR or doc unless the user explicitly asks.

### Tasks

For internal tasks that don't fit bug/feature templates:

```bash
gh issue create \
  --title "<type>: <description>" \
  --body "$(cat <<'EOF'
## Description

<Clear description of the work>

## Context

<Any dependencies, related issues, or background>

## Definition of Done

- [ ] <criterion>
EOF
)"
```

GitHub built-in issue types (`Bug`, `Feature`, `Task`) should come from the matching issue template when possible, or be set manually afterward. Do not try to emulate them through labels.

## Useful Options

| Option              | Description                        |
| ------------------- | ---------------------------------- |
| `--title, -t`       | Issue title (required)             |
| `--body, -b`        | Issue description                  |
| `--label, -l`       | Add label (can use multiple times) |
| `--milestone, -m`   | Add to milestone                   |
| `--project, -p`     | Add to project                     |
| `--web`             | Open in browser after creation     |

## After Creating

The command outputs the issue URL and number.

**Display the URL using markdown link syntax** so it's easily clickable:

```
Created issue [#123](https://github.com/OWNER/REPO/issues/123)
```

Use the issue number to:

- Reference in commits: `git commit -m "Fix validation error (fixes #123)"`
- Create a branch following project convention: `<issue-number>-<description>/<username>`
