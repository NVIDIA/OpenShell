---
name: create-github-issue
description: Create GitHub issues using the gh CLI. Use when the user wants to create a new issue, report a bug, request a feature, or create a task in GitHub. Trigger keywords - create issue, new issue, file bug, report bug, feature request, github issue.
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

Do not add a type label automatically. The body must include a **Proposed Design** — not a "please build this" request. Apply area or topic labels only when they are clearly known.

```bash
gh issue create \
  --title "feat: <concise description>" \
  --body "$(cat <<'EOF'
## Problem Statement

<What problem does this solve? Why does it matter?>

## Proposed Design

<How should this work? Describe the system behavior, components involved,
and user-facing interface.>

## Alternatives Considered

<What other approaches were evaluated? Why is this design better?>

## Agent Investigation

<If the agent explored the codebase to assess feasibility, paste findings here.>
EOF
)"
```

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
