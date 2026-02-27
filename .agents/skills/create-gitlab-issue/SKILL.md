---
name: create-gitlab-issue
description: Create GitLab issues using the glab CLI. Use when the user wants to create a new issue, report a bug, request a feature, or create a task in GitLab. Trigger keywords - create issue, new issue, file bug, report bug, feature request, gitlab issue.
---

# Create GitLab Issue

Create issues in GitLab using the `glab` CLI.

## Prerequisites

The `glab` CLI must be configured for `gitlab-master.nvidia.com`. See the project's glab rule for setup instructions.

## Shell Permissions

When running `glab` commands, always use `required_permissions: ["all"]` to avoid TLS certificate verification issues with the corporate GitLab instance.

## Creating an Issue

Use `glab issue create` with title and description:

```bash
glab issue create --title "Issue title" --description "Issue description"
```

### With Labels

```bash
glab issue create --title "Title" --description "Description" --label "bug" --label "priority::high"
```

### Assign to Someone

```bash
glab issue create --title "Title" --description "Description" --assignee "username"
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

## Examples

TODO

## Useful Options

| Option              | Description                        |
| ------------------- | ---------------------------------- |
| `--title, -t`       | Issue title (required)             |
| `--description, -d` | Issue description                  |
| `--label, -l`       | Add label (can use multiple times) |
| `--assignee, -a`    | Assign to user                     |
| `--weight, -w`      | Story points (1, 2, 3, 5, or 8)    |
| `--milestone, -m`   | Add to milestone                   |
| `--confidential`    | Mark as confidential               |
| `--web`             | Open in browser after creation     |

## After Creating

The command outputs the issue URL and number.

**Display the URL using markdown link syntax** so it's easily clickable:

```
Created issue [#123](https://gitlab-master.nvidia.com/navigator/navigator/-/issues/123)
```

Use the issue number to:

- Reference in commits: `git commit -m "Fix validation error (fixes #123)"`
- Create a branch following project convention: `<issue-number>-<description>/<username>`
