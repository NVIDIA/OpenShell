---
name: create-github-pr
description: Create GitHub pull requests using the gh CLI. Use when the user wants to create a new PR, submit code for review, or open a pull request. Trigger keywords - create PR, pull request, new PR, submit for review, code review.
---

# Create GitHub Pull Request

Create pull requests on GitHub using the `gh` CLI.

## Prerequisites

- The `gh` CLI must be authenticated (`gh auth status`)
- You must have commits on a branch that's pushed to the remote
- Branch should follow naming convention: `<issue-number>-<description>/<username>`

## Before Creating a PR

### Run Pre-commit Checks

Run the local pre-commit task before opening a PR:

```bash
mise run pre-commit
```

### Verify Branch State

Before creating a PR, verify:

1. **You're not on main** - Never create PRs directly from main:

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

## Creating a PR

Basic PR creation (opens editor for description):

```bash
gh pr create
```

With title and body:

```bash
gh pr create --title "PR title" --body "PR description"
```

## PR Title Format

**PR titles must follow the conventional commit format:**

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

### Link to an Issue

Use `Closes #<issue-number>` in the body to auto-close the issue when merged:

```bash
gh pr create \
  --title "Fix validation error for empty requests" \
  --body "Closes #123

## Summary
- Added validation for empty request bodies
- Returns 400 instead of 500"
```

### Create as Draft

For work-in-progress that's not ready for review:

```bash
gh pr create --draft --title "WIP: New feature"
```

### With Labels

```bash
gh pr create --title "Title" --label "area:cli" --label "topic:security"
```

### Target a Different Branch

Default target is `main`. To target a different branch:

```bash
gh pr create --base "release-1.0"
```

## PR Description Format

PR descriptions must follow the project's [PR template](.github/PULL_REQUEST_TEMPLATE.md) structure:

```markdown
## Summary
<!-- 1-3 sentences: what this PR does and why -->

## Related Issue
<!-- Fixes #NNN or Closes #NNN -->

## Changes
<!-- Bullet list of key changes -->

## Testing
<!-- What testing was done? -->
- [ ] `mise run pre-commit` passes
- [ ] Unit tests added/updated
- [ ] E2E tests added/updated (if applicable)

## Checklist
- [ ] Follows Conventional Commits
- [ ] Commits are signed off (DCO)
```

Populate the testing checklist based on what was actually run. Check boxes for steps that were completed.

## Example PR (Complete)

```bash
gh pr create \
  --title "feat(cli): add pagination to sandbox list" \
  --body "$(cat <<'EOF'
## Summary

Add `--limit` and `--offset` flags to `openshell sandbox list` for pagination.

## Related Issue

Closes #456

## Changes

- Added `offset` and `limit` query parameters to the sandbox list API call
- Default limit is 20, max is 100
- Response includes `total_count` field

## Testing

- [x] `mise run pre-commit` passes
- [x] Unit tests added/updated
- [ ] E2E tests added/updated (if applicable)

## Checklist

- [x] Follows Conventional Commits
- [x] Commits are signed off (DCO)
EOF
)"
```

## Useful Options

| Option              | Description                                |
| ------------------- | ------------------------------------------ |
| `--title, -t`       | PR title (use conventional commit format)  |
| `--body, -b`        | PR description                             |
| `--reviewer, -r`    | Request review from user                   |
| `--draft`           | Create as draft (WIP)                      |
| `--label, -l`       | Add label (can use multiple times)         |
| `--base, -B`        | Target branch (default: main)              |
| `--head, -H`        | Source branch (default: current)           |
| `--web`             | Open in browser after creation             |

## After Creating

The command outputs the PR URL and number.

**Display the URL using markdown link syntax** so it's easily clickable:

```
Created PR [#123](https://github.com/OWNER/REPO/pull/123)
```

### Monitor Workflow Run (Optional)

If the user asks to wait for a green CI before posting the RFR, use this snippet to monitor the workflow run:

```bash
# Watch the latest workflow run for the current branch
gh run watch
```

Or poll manually:

```bash
RUN_ID=$(gh run list --branch "$(git branch --show-current)" --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$RUN_ID"
```
