---
name: create-gitlab-mr
description: Create GitLab merge requests using the glab CLI. Use when the user wants to create a new MR, submit code for review, or open a pull request. Trigger keywords - create MR, merge request, new MR, pull request, PR, submit for review, code review.
---

# Create GitLab Merge Request

Create merge requests in GitLab using the `glab` CLI.

## Prerequisites

- The `glab` CLI must be configured for `gitlab-master.nvidia.com`
- You must have commits on a branch that's pushed to the remote
- Branch should follow naming convention: `<issue-number>-<description>/<username>`

## Shell Permissions

When running `glab` commands, always use `required_permissions: ["all"]` to avoid TLS certificate verification issues with the corporate GitLab instance.

**Troubleshooting:** If glab commands fail with TLS errors inside Cursor, try prefixing with:

```bash
SSL_CERT_FILE=/etc/ssl/cert.pem glab ...
```

## Before Creating an MR

### Run Pre-commit Checks

Run the local pre-commit task before opening an MR:

```bash
mise run pre-commit
```

### Verify Branch State

Before creating an MR, verify:

1. **You're not on main** - Never create MRs directly from main:

   ```bash
   # Should NOT be "main"
   git branch --show-current
   ```

2. **Branch follows naming convention** - Format: `<issue-number>-<description>/<initials>`

   ```bash
   # Example: 1234-add-pagination/jd
   git branch --show-current
   ```

3. **Consider squashing commits** - For cleaner history, squash related commits before pushing:

   ```bash
   # Squash last N commits into one
   git reset --soft HEAD~N
   git commit -m "feat(component): description"
   ```

### Push Your Branch

Ensure your branch is pushed to the remote:

```bash
git push -u origin HEAD
```

## Creating an MR

Basic MR creation (opens editor for description):

```bash
glab mr create
```

With title and description:

```bash
glab mr create --title "MR title" --description "MR description"
```

## MR Title Format

**MR titles must follow the conventional commit format:**

```
<type>(<scope>): <description>
```

**Types:**

- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation only
- `refactor` - Code change that neither fixes a bug nor adds a feature
- `test` - Adding or updating tests
- `chore` - Maintenance tasks (CI, build, dependencies)
- `perf` - Performance improvement

**Scope** is typically the component name (e.g., `evaluator`, `cli`, `sdk`, `jobs`).

**Examples:**

- `feat(evaluator): add support for custom rubrics`
- `fix(jobs): handle timeout errors gracefully`
- `docs(sdk): update authentication examples`
- `refactor(models): simplify deployment logic`
- `chore(ci): update Python version in pipeline`

## Required MR Fields

Every MR **must** have:

1. **Assignee** - Always assign to yourself

## Assignee and Reviewer

### Always Assign to Yourself

**Every MR must be assigned to the user creating it.** Use the `--assignee` flag with your GitLab username:

```bash
glab mr create --title "Title" --assignee "your-username"
```

To get the current user's GitLab username:

```bash
glab api user | jq -r '.username'
```

### Link to an Issue

Use `Closes #<issue-number>` in the description to auto-close the issue when merged:

```bash
glab mr create \
  --title "Fix validation error for empty requests" \
  --assignee "your-username" \
  --description "Closes #123

## Summary
- Added validation for empty request bodies
- Returns 400 instead of 500"
```

### Create as Draft

For work-in-progress that's not ready for review:

```bash
glab mr create --draft --title "WIP: New feature" --assignee "your-username"
```

### With Labels

```bash
glab mr create --title "Title" --label "component::evaluator" --label "bug"
```

### Target a Different Branch

Default target is `main`. To target a different branch:

```bash
glab mr create --target-branch "release-1.0"
```

## MR Description Guidelines

A good MR description includes:

### Summary

Brief description of changes (2-3 bullet points).

### Test Plan

How the changes were tested:

- Unit tests added/updated
- Manual testing performed
- Integration tests

### Related Issues

Link to related issues using `Closes #123` or `Related to #456`.

## Example MR (Complete)

```bash
# Get current username
USERNAME=$(glab api user | jq -r '.username')

glab mr create \
  --title "feat(files): add pagination to dataset list endpoint" \
  --assignee "$USERNAME" \
  --milestone "Platform 26.02" \
  --description "Closes #456

## Summary
- Added \`offset\` and \`limit\` query parameters to GET /datasets
- Default limit is 20, max is 100
- Response includes \`total_count\` field
```

## Useful Options

| Option                   | Description                                  |
| ------------------------ | -------------------------------------------- |
| `--title, -t`            | MR title (use conventional commit format)    |
| `--description, -d`      | MR description                               |
| `--assignee, -a`         | Assign to user (always use your username)    |
| `--reviewer`             | Request review from user (use component PIC) |
| `--draft`                | Create as draft (WIP)                        |
| `--label, -l`            | Add label (can use multiple times)           |
| `--target-branch, -b`    | Target branch (default: main)                |
| `--source-branch, -s`    | Source branch (default: current)             |
| `--squash-before-merge`  | Enable squash on merge                       |
| `--remove-source-branch` | Delete branch after merge                    |
| `--web`                  | Open in browser after creation               |
| `--yes`                  | Skip confirmation prompts                    |

## After Creating

The command outputs the MR URL and number.

**Display the URL using markdown link syntax** so it's easily clickable:

```
Created MR [!123](https://gitlab-master.nvidia.com/navigator/navigator/-/merge_requests/123)
```

### Monitor Pipeline (Optional)

If the user asks to wait for a green pipeline before posting the RFR, use this snippet to monitor CI status:

```bash
PIPELINE_ID=<pipeline-id>  # Get from MR or glab ci list
while true; do
  ps=$(glab api "projects/:id/pipelines/$PIPELINE_ID" | jq -r '.status')
  echo "$(date '+%H:%M:%S') Pipeline: $ps"
  case "$ps" in success|failed|canceled) break ;; *) sleep 30 ;; esac
done
```

To get the pipeline ID for the MR:

```bash
glab api "projects/:id/merge_requests/<mr-id>/pipelines" | jq '.[0].id'
```

``
