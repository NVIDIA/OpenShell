---
name: github
description: Interact with GitHub using the gh CLI restricted to REST API only (no GraphQL). Use when the user wants to work with GitHub issues, pull requests, repos, releases, or Actions — especially in sandboxed environments where the GraphQL endpoint may be blocked. Trigger keywords - github, gh, pull request, PR, github issue, github actions, workflow, release, gh api.
---

Always prefer using the github cli. do not use git for any operations except cloning.

# GitHub via REST API

Work with GitHub using `gh api` and REST-only subcommands. Many `gh` subcommands (`gh pr list`, `gh issue list`, `gh issue view`, `gh pr view`, etc.) use GraphQL internally and **will fail** if the sandbox blocks `api.github.com/graphql`. Always prefer `gh api` hitting REST endpoints.

## Shell Permissions

Use `required_permissions: ["full_network"]` for all `gh` commands (they need to reach `api.github.com`).

## Key Constraint

| Endpoint                          | Status                 |
| --------------------------------- | ---------------------- |
| `api.github.com/graphql`          | **Blocked** in sandbox |
| `api.github.com/repos/...` (REST) | Allowed                |

**Rule:** Never use `gh` subcommands that call GraphQL. When in doubt, use `gh api` with an explicit REST path.

### Commands known to use GraphQL (avoid these)

- `gh pr list`, `gh pr view`, `gh pr status`, `gh pr checks`
- `gh issue list`, `gh issue view`, `gh issue status`
- `gh project` (all subcommands)
- `gh search` (all subcommands)
- `gh label list`

### Commands that are REST-safe

- `gh api <REST-path>` — always REST when given a path (not `graphql`)
- `gh pr create` — uses REST
- `gh pr merge` — uses REST
- `gh release *` — uses REST
- `gh run *` — uses REST
- `gh workflow *` — uses REST
- `gh auth status` — local/REST
- `gh repo clone` / `gh repo view --json` — may use GraphQL; prefer `gh api`

## Authentication Check

```bash
gh auth status
```

If not authenticated, instruct the user to run `gh auth login`.

## Repositories

### Get repo info

```bash
gh api repos/{owner}/{repo}
```

### List repos for a user or org

```bash
gh api "users/{username}/repos?per_page=30&sort=updated"
gh api "orgs/{org}/repos?per_page=30&sort=updated"
```

## Issues

### List issues

```bash
gh api "repos/{owner}/{repo}/issues?state=open&per_page=30" \
  | jq '.[] | {number, title, state, user: .user.login, labels: [.labels[].name]}'
```

Filter options (query params): `state` (open/closed/all), `labels` (comma-separated), `assignee`, `creator`, `milestone`, `sort` (created/updated/comments), `direction` (asc/desc), `since` (ISO 8601), `per_page`, `page`.

### Get a single issue

```bash
gh api repos/{owner}/{repo}/issues/{number}
```

### Create an issue

```bash
gh api repos/{owner}/{repo}/issues \
  -f title="Issue title" \
  -f body="Issue description" \
  -f "labels[]=bug" \
  -f "assignees[]={username}"
```

### Comment on an issue

```bash
gh api repos/{owner}/{repo}/issues/{number}/comments \
  -f body="Comment text"
```

### Close an issue

```bash
gh api repos/{owner}/{repo}/issues/{number} -X PATCH -f state=closed
```

### Reopen an issue

```bash
gh api repos/{owner}/{repo}/issues/{number} -X PATCH -f state=open
```

### Add labels

```bash
gh api repos/{owner}/{repo}/issues/{number}/labels \
  -f "labels[]=bug" -f "labels[]=priority-high"
```

## Pull Requests

### List PRs

```bash
gh api "repos/{owner}/{repo}/pulls?state=open&per_page=30" \
  | jq '.[] | {number, title, state, user: .user.login, head: .head.ref, base: .base.ref}'
```

Filter options: `state` (open/closed/all), `head` (filter by head user/org and branch: `user:ref-name`), `base` (filter by base branch), `sort` (created/updated/popularity/long-running), `direction`, `per_page`, `page`.

### Get a single PR

```bash
gh api repos/{owner}/{repo}/pulls/{number} \
  | jq '{number, title, state, body, user: .user.login, head: .head.ref, base: .base.ref, mergeable: .mergeable, merged: .merged}'
```

### Get PR diff

```bash
gh api repos/{owner}/{repo}/pulls/{number} \
  -H "Accept: application/vnd.github.diff"
```

### Get PR files changed

```bash
gh api "repos/{owner}/{repo}/pulls/{number}/files?per_page=100" \
  | jq '.[] | {filename, status, additions, deletions, changes}'
```

### Create a PR (REST-safe alternative)

`gh pr create` is REST-safe and the easiest way:

```bash
gh pr create --title "PR title" --body "PR description" --base main --head feature-branch
```

Or via `gh api`:

```bash
gh api repos/{owner}/{repo}/pulls \
  -f title="PR title" \
  -f body="PR description" \
  -f head="feature-branch" \
  -f base="main"
```

### Merge a PR

```bash
gh pr merge {number} --squash  # REST-safe
```

Or via `gh api`:

```bash
gh api repos/{owner}/{repo}/pulls/{number}/merge \
  -X PUT -f merge_method=squash
```

### Request reviewers

```bash
gh api repos/{owner}/{repo}/pulls/{number}/requested_reviewers \
  -f "reviewers[]={username}"
```

### List PR reviews

```bash
gh api "repos/{owner}/{repo}/pulls/{number}/reviews" \
  | jq '.[] | {user: .user.login, state, body}'
```

### List PR review comments

```bash
gh api "repos/{owner}/{repo}/pulls/{number}/comments" \
  | jq '.[] | {user: .user.login, path, body, line}'
```

### Comment on a PR

PRs use the issues comments endpoint:

```bash
gh api repos/{owner}/{repo}/issues/{number}/comments \
  -f body="Comment text"
```

## Commits & Branches

### List branches

```bash
gh api "repos/{owner}/{repo}/branches?per_page=30" \
  | jq '.[].name'
```

### Get a commit

```bash
gh api repos/{owner}/{repo}/commits/{sha} \
  | jq '{sha, message: .commit.message, author: .commit.author.name, date: .commit.author.date}'
```

### Compare two refs

```bash
gh api "repos/{owner}/{repo}/compare/{base}...{head}" \
  | jq '{ahead_by, behind_by, total_commits, files: [.files[] | {filename, status, additions, deletions}]}'
```

### List commits on a branch

```bash
gh api "repos/{owner}/{repo}/commits?sha={branch}&per_page=20" \
  | jq '.[] | {sha: .sha[:8], message: (.commit.message | split("\n")[0]), date: .commit.author.date}'
```

## GitHub Actions

### List workflow runs

```bash
gh run list --limit 10  # REST-safe
```

Or via `gh api`:

```bash
gh api "repos/{owner}/{repo}/actions/runs?per_page=10" \
  | jq '.workflow_runs[] | {id, name, status, conclusion, head_branch, created_at}'
```

### Get a specific run

```bash
gh api repos/{owner}/{repo}/actions/runs/{run_id} \
  | jq '{id, name, status, conclusion, head_branch, html_url}'
```

### List jobs for a run

```bash
gh api "repos/{owner}/{repo}/actions/runs/{run_id}/jobs" \
  | jq '.jobs[] | {id, name, status, conclusion, started_at, completed_at}'
```

### Download job logs

```bash
gh run view {run_id} --log  # REST-safe
```

### Re-run a workflow

```bash
gh api repos/{owner}/{repo}/actions/runs/{run_id}/rerun -X POST
```

### Re-run failed jobs only

```bash
gh api repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs -X POST
```

### List workflows

```bash
gh api "repos/{owner}/{repo}/actions/workflows" \
  | jq '.workflows[] | {id, name, state, path}'
```

### Trigger a workflow dispatch

```bash
gh api repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches \
  -f ref=main -f "inputs[key]=value"
```

## Releases

### List releases

```bash
gh api "repos/{owner}/{repo}/releases?per_page=10" \
  | jq '.[] | {tag_name, name, draft, prerelease, published_at}'
```

### Get latest release

```bash
gh api repos/{owner}/{repo}/releases/latest \
  | jq '{tag_name, name, body, published_at, assets: [.assets[] | {name, download_count, browser_download_url}]}'
```

### Create a release

```bash
gh api repos/{owner}/{repo}/releases \
  -f tag_name="v1.0.0" \
  -f name="Release v1.0.0" \
  -f body="Release notes here" \
  -F draft=false \
  -F prerelease=false
```

## Check Runs & Statuses (CI)

### List check runs for a ref

```bash
gh api "repos/{owner}/{repo}/commits/{ref}/check-runs" \
  | jq '.check_runs[] | {name, status, conclusion, html_url}'
```

### Get combined status for a ref

```bash
gh api "repos/{owner}/{repo}/commits/{ref}/status" \
  | jq '{state, total_count, statuses: [.statuses[] | {context, state, description}]}'
```

## Pagination

GitHub REST API returns at most 100 items per page. Use `per_page` and `page` query params:

```bash
gh api "repos/{owner}/{repo}/issues?state=all&per_page=100&page=1"
gh api "repos/{owner}/{repo}/issues?state=all&per_page=100&page=2"
```

Or use `--paginate` to auto-follow `Link` headers (returns all pages concatenated):

```bash
gh api "repos/{owner}/{repo}/issues?state=all&per_page=100" --paginate \
  | jq '.[] | {number, title}'
```

## Resolving Owner/Repo

If the user doesn't specify a repo, infer from the current git remote:

```bash
gh api repos/:owner/:repo
```

`gh api` resolves `:owner` and `:repo` from the current git remote automatically.

## Error Handling

- **401 Unauthorized** — run `gh auth status`; may need `gh auth login`
- **403 Forbidden** — rate limit or insufficient permissions; check `gh api rate_limit`
- **404 Not Found** — wrong owner/repo/number or private repo without access
- **422 Unprocessable** — invalid payload; check field names and types
- **Network error / timeout** — if you see connection refused on the graphql endpoint, you're hitting the sandbox restriction; switch to a REST endpoint
