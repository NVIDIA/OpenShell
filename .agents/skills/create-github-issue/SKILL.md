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

Do not add a type label automatically. Write the issue as a user story. Capture the affected persona, desired user-facing workflow or capability, reason and current impact, the workflow that exposes the problem, and the relevant environment. Do not require a diagnosis, internal implementation design, or agent output. Apply area or topic labels only when they are clearly known.

```bash
gh issue create \
  --title "bug: <concise description>" \
  --body "$(cat <<'EOF'
## What persona does this impact?

<The affected role in the workflow, such as an operator, sandbox creator, or agent>

## What does this persona need to be able to do?

<The user-facing workflow, capability, or outcome the persona needs>

## Why does this matter to the persona?

<What happens today and how it affects the persona's work>

## What workflow exposes the problem?

1. <step>
2. <step>

## Environment

- OS: <os>
- OpenShell: <version>
- Platform, deployment, runtime, or integration: <relevant details>

## Relevant Logs

```
<optional minimal, redacted output>
```
EOF
)"
```

### Feature Requests

Do not add a type label automatically. Use the same core user-story structure as a bug report. Ask for the desired user-facing workflow, but do not require the reporter to decide whether the gap is a defect or missing capability, design the internal implementation, or include agent output. Apply area or topic labels only when they are clearly known.

```bash
gh issue create \
  --title "feat: <concise description>" \
  --body "$(cat <<'EOF'
## What persona does this impact?

<The affected role in the workflow, such as an operator, sandbox creator, or agent>

## What does this persona need to be able to do?

<The user-facing workflow, capability, or outcome the persona needs>

## Why does this matter to the persona?

<What happens today and how it affects the persona's work>

## What workflow exposes the need?

1. <step>
2. <step>

## Environment

- OpenShell: <version>
- Platform, deployment, runtime, or integration: <relevant details>
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

Creating an issue does not accept it or queue agent work. Agents never apply `state:accepted`, the `roadmap` label, add issues to the roadmap project, or apply `agent:plan-requested` or `agent:implementation-requested`. Community issues proceed through `triage-issue`; a human accepts technically validated work with `state:accepted` or roadmap placement. The request labels queue work for unattended agents; a user may instead direct an agent to a specific issue.

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
