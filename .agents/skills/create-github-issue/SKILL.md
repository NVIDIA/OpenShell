---
name: create-github-issue
description: Create GitHub issues using the gh CLI. Use when the user wants to create a new issue, report a bug, request a feature, or create a task in GitHub. Trigger keywords - create issue, new issue, file bug, report bug, feature request, github issue.
---

# Create GitHub Issue

Create issues on GitHub using the `gh` CLI.

## Prerequisites

The `gh` CLI must be authenticated (`gh auth status`).

## Creating an Issue

Use `gh issue create` with title and body:

```bash
gh issue create --title "Issue title" --body "Issue description"
```

### With Labels

```bash
gh issue create --title "Title" --body "Description" --label "bug" --label "priority:high"
```

### Assign to Someone

```bash
gh issue create --title "Title" --body "Description" --assignee "username"
```

### Assign to Yourself

```bash
gh issue create --title "Title" --body "Description" --assignee "@me"
```

## Issue Formatting Guidelines

Format the description based on the issue type:

### Bug Reports

Include:

- What happened (actual behavior)
- What should happen (expected behavior)
- Steps to reproduce
- Environment details if relevant

### Feature Requests

Include:

- Problem or use case being addressed
- Proposed solution
- Acceptance criteria (what "done" looks like)

### Tasks

Include:

- Clear description of the work
- Any context or dependencies
- Definition of done

## Useful Options

| Option              | Description                        |
| ------------------- | ---------------------------------- |
| `--title, -t`       | Issue title (required)             |
| `--body, -b`        | Issue description                  |
| `--label, -l`       | Add label (can use multiple times) |
| `--assignee, -a`    | Assign to user                     |
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
