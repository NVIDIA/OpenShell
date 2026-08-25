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

Do not add a type label automatically. The body must include a **User Story**, **Problem Statement**, **Impact / Why This Matters**, and **Acceptance Criteria**, followed by bug-specific reproduction steps and environment details. Logs are optional and must be concise and redacted. Apply area or topic labels only when they are clearly known.

```bash
gh issue create \
  --title "bug: <concise description>" \
  --body "$(cat <<'EOF'
## User Story

As a <persona>, I want <capability or outcome>, so that <benefit or impact>.

## Problem Statement

<Summarize what is broken or missing in OpenShell's current behavior and when the issue occurs>

## Impact / Why This Matters

<Explain the consequences for users, the current workaround, and why that workaround is insufficient>

## Acceptance Criteria

- [ ] <observable outcome that demonstrates the bug is fixed>

## Reproduction Steps

1. <step>
2. <step>

## Environment

- OpenShell: <version>
- OS: <os>
- Runtime, deployment, or integration: <relevant details>

## Logs

```
<optional minimal, redacted output>
```
EOF
)"
```

### Feature Requests

Do not add a type label automatically. The body must include a **User Story**, **Problem Statement**, **Impact / Why This Matters**, **Proposed Design**, **Acceptance Criteria**, and **Alternatives Considered**. The proposed design should define the user-facing workflow and externally observable behavior without prescribing internal implementation. Agent investigation is optional. Apply area or topic labels only when they are clearly known.

```bash
gh issue create \
  --title "feat: <concise description>" \
  --body "$(cat <<'EOF'
## User Story

As a <persona>, I want <capability or outcome>, so that <benefit or impact>.

## Problem Statement

<Summarize the capability or behavior missing from OpenShell today>

## Impact / Why This Matters

<Explain what users must do today, why it is insufficient, and the operational cost, risk, blocked workflow, or adoption barrier>

## Proposed Design

<The desired user-facing workflow and externally observable behavior, without prescribing internal implementation>

## Acceptance Criteria

- [ ] <specific, observable outcome>

## Alternatives Considered

<Other user-facing workflows or behaviors considered and why this approach best satisfies the user story>

## Agent Investigation

<Optional findings from codebase exploration>
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

Creating an issue does not accept it or queue agent work. Agents never apply `state:accepted`, the `roadmap` label, add issues to the roadmap project, or apply `agent:plan-requested` or `agent:implementation-requested`. Community issues proceed through `triage-issue`; a human accepts technically validated work with `state:accepted` or roadmap placement. The request labels queue work for unattended agents. A user may instead direct an agent to a specific issue; the agent warns about missing expected workflow labels and continues with the requested phase without changing them.

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
