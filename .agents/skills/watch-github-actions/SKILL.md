---
name: watch-github-actions
description: Watch and monitor GitHub Actions workflow runs using the gh CLI. Use when the user wants to check workflow status, watch a running workflow, view CI/CD jobs, or monitor build progress. Trigger keywords - watch pipeline, pipeline status, CI status, check build, monitor CI, view pipeline, pipeline progress, workflow status, actions status.
---

# Watch GitHub Actions

Monitor GitHub Actions workflow runs using the `gh` CLI.

## Prerequisites

- The `gh` CLI must be authenticated (`gh auth status`)
- You must be in a git repository with a GitHub remote

## Quick Status Check

List recent workflow runs for the current branch:

```bash
gh run list --branch "$(git branch --show-current)"
```

List all recent runs:

```bash
gh run list
```

## Watch a Run in Real Time

Watch a workflow run until it completes:

```bash
gh run watch
```

Watch a specific run:

```bash
gh run watch <run-id>
```

This will continuously update the status until the run finishes (success, failure, or cancelled).

## View Run Details

View a specific run with job details:

```bash
gh run view <run-id>
```

View with full log output:

```bash
gh run view <run-id> --log
```

View a failed job's log:

```bash
gh run view <run-id> --log-failed
```

## Check Runs for a Specific Branch

Current branch:

```bash
gh run list --branch "$(git branch --show-current)"
```

Specific branch:

```bash
gh run list --branch main
gh run list --branch feature-branch
```

## Check Runs for a PR

List workflow runs associated with a PR:

```bash
# Get the head branch of the PR, then list runs
BRANCH=$(gh pr view <pr-number> --json headRefName --jq '.headRefName')
gh run list --branch "$BRANCH"
```

Or view the checks directly on the PR:

```bash
gh pr checks <pr-number>
```

## List Recent Runs

List runs for the current project:

```bash
gh run list
```

Filter by status:

```bash
gh run list --status failure
gh run list --status success
gh run list --status in_progress
```

Filter by workflow:

```bash
gh run list --workflow "CI"
```

JSON output for scripting:

```bash
gh run list --json databaseId,status,headBranch,url --jq '.[] | {id: .databaseId, status: .status, branch: .headBranch, url: .url}'
```

## View Job Logs

View logs for a specific run:

```bash
gh run view <run-id> --log
```

View only failed job logs:

```bash
gh run view <run-id> --log-failed
```

## Wait for Run Completion (Scripting)

Watch and wait for a run to complete:

```bash
RUN_ID=$(gh run list --branch "$(git branch --show-current)" --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$RUN_ID" --exit-status
echo "Run finished with exit code: $?"
```

## Open Run in Browser

Open the latest run in your default browser:

```bash
gh run view --web
```

Open a specific run:

```bash
gh run view <run-id> --web
```

## Rerun Failed Jobs

Rerun all failed jobs in a run:

```bash
gh run rerun <run-id> --failed
```

Rerun an entire run:

```bash
gh run rerun <run-id>
```

## Useful Commands Reference

| Command                             | Description                             |
| ----------------------------------- | --------------------------------------- |
| `gh run list`                       | List recent workflow runs               |
| `gh run list --branch <branch>`     | List runs for a specific branch         |
| `gh run list --status failure`      | List failed runs                        |
| `gh run watch`                      | Watch latest run until completion       |
| `gh run watch <run-id>`             | Watch a specific run until completion   |
| `gh run view <run-id>`              | View run details and job list           |
| `gh run view <run-id> --log`        | View full run logs                      |
| `gh run view <run-id> --log-failed` | View only failed job logs               |
| `gh run view --web`                 | Open run in browser                     |
| `gh run rerun <run-id>`             | Rerun a workflow run                    |
| `gh run rerun <run-id> --failed`    | Rerun only failed jobs                  |
| `gh run cancel <run-id>`            | Cancel a running workflow               |
| `gh pr checks <pr-number>`          | View PR check statuses                  |

## Common Flags

| Flag               | Description                                    |
| ------------------- | ---------------------------------------------- |
| `-b, --branch`     | Specify branch (default: current branch)       |
| `--status`         | Filter by status (queued, in_progress, etc.)   |
| `--workflow`       | Filter by workflow name                        |
| `-L, --limit`      | Maximum number of runs to list                 |
| `-w, --web`        | Open in browser                                |
| `--json`           | Output as JSON with specified fields           |
| `--jq`             | Filter JSON output with jq expression          |

## Example Workflow

1. Push your changes and create/update a PR
2. Watch the workflow run:
   ```bash
   gh run watch
   ```
3. If a job fails, view the failed logs:
   ```bash
   gh run view <run-id> --log-failed
   ```
4. Rerun the failed jobs if needed:
   ```bash
   gh run rerun <run-id> --failed
   ```
