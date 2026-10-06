---
name: create-github-issue
description: Create GitHub issues using the gh CLI. Use when the user wants to create a new issue, report a bug, request a feature, or create a task in GitHub. Trigger keywords - create issue, new issue, file bug, report bug, feature request, github issue.
metadata:
  internal: true
---

# Create GitHub Issue

Create issues on GitHub using the `gh` CLI. Issues must conform to the project's issue templates.

## Prerequisites

The `gh` CLI must be authenticated (`gh auth status`).

## Issue Templates

This project uses YAML form issue templates. When creating issues, match the template structure so the output aligns with what GitHub renders.

### Bug Reports

Do not add a type label automatically. Confirm that the human operator personally uses Ryno and directly encountered the problem or needs the feature for a specific use case. If that first-hand attestation or concrete use case is missing, ask for it before creating the issue. Frame the issue entirely in terms of Ryno. The body must include a **User Story**, **Problem Statement**, **Impact / Why This Matters**, and **Acceptance Criteria**, followed by bug-specific reproduction steps using only Ryno deployments and environment details. Do not install third-party tools to demonstrate reproducibility. Logs are optional and must be concise and redacted. If the issue suggests a change to configuration, CLI, SDK, or other user experience, include a notional example of the proposed interaction for human review. Inspect current repository labels before applying any; use only labels whose meaning is clear.

```bash
gh issue create \
  --title "bug: <concise description>" \
  --body "$(cat <<'EOF'
## User Story

I use Ryno for <specific use case>. I directly encountered or need <specific behavior> so that <outcome>.

## Problem Statement

<Summarize what is broken or missing in Ryno's current behavior and when the issue occurs>

## Impact / Why This Matters

<Explain the consequences for users, the current workaround, and why that workaround is insufficient>

## Acceptance Criteria

- [ ] <observable outcome that demonstrates the bug is fixed>

## Reproduction Steps

1. <step>
2. <step>

## Environment

- Ryno: <version>
- OS: <os>
- Runtime, deployment, or integration: <relevant details>

## Suggested UX (if applicable)

<Notional Ryno CLI, configuration, SDK, or other interaction>

## Logs

<Optional minimal, redacted output>
EOF
)"
```

### Feature Requests

Do not add a type label automatically. Confirm that the human operator personally uses Ryno and directly encountered the problem or needs the feature for a specific use case. If that first-hand attestation or concrete use case is missing, ask for it before creating the issue. Frame the issue entirely in terms of Ryno. The body must include a **User Story**, **Problem Statement**, **Impact / Why This Matters**, **Proposed Design**, **Acceptance Criteria**, and **Alternatives Considered**. The proposed design should define the user-facing workflow and externally observable behavior without prescribing internal implementation. Agent investigation is optional. If the issue suggests a change to configuration, CLI, SDK, or other user experience, include a notional example of the proposed interaction for human review. Inspect current repository labels before applying any; use only labels whose meaning is clear.

```bash
gh issue create \
  --title "feat: <concise description>" \
  --body "$(cat <<'EOF'
## User Story

I use Ryno for <specific use case>. I directly encountered or need <specific behavior> so that <outcome>.

## Problem Statement

<Summarize the capability or behavior missing from Ryno today>

## Impact / Why This Matters

<Explain what users must do today, why it is insufficient, and the operational cost, risk, blocked workflow, or adoption barrier>

## Proposed Design

<The desired user-facing workflow and externally observable behavior, without prescribing internal implementation>

## Suggested UX (if applicable)

<Notional Ryno CLI, configuration, SDK, or other interaction>

## Acceptance Criteria

- [ ] <specific, observable outcome>

## Alternatives Considered

<Other Ryno workflows considered, including relevant middleware, interceptors, providers, or other extension points, and why the proposal better serves the use case. Prefer an applicable extension when it satisfies the use case; running another service alone is not a reason to dismiss it.>

## Agent Investigation

<Optional findings from codebase exploration>
EOF
)"
```

### Tasks

For internal tasks that do not fit bug/feature templates, still obtain the operator's first-hand Ryno use case before creating the issue:

```bash
gh issue create \
  --title "<type>: <description>" \
  --body "$(cat <<'EOF'
## User Story

<I personally use Ryno for this specific case and directly need this work because...>

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

Creating an issue does not accept it. Inspect the repository’s current `state:*` labels and follow its triage → validation → human acceptance process. Agents may assess facts, but only humans decide whether to accept work or place it on the roadmap. A direct user request authorizes the requested planning or implementation phase without changing issue disposition.

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

- Reference in signed-off Conventional Commits: `git commit --signoff -m "fix(cli): validate empty requests (fixes #123)"`
- Create a branch following project convention: `<type>/<issue-id>-<short-description>/<github-username>`, where `<type>` is a Conventional Commits type.
