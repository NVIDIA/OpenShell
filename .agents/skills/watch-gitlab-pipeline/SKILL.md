---
name: watch-gitlab-pipeline
description: Watch and monitor GitLab CI/CD pipelines using the glab CLI. Use when the user wants to check pipeline status, watch a running pipeline, view CI/CD jobs, or monitor build progress. Trigger keywords - watch pipeline, pipeline status, CI status, check build, monitor CI, view pipeline, pipeline progress.
---

# Watch GitLab Pipeline

Monitor GitLab CI/CD pipelines using the `glab` CLI.

## Prerequisites

- The `glab` CLI must be configured for `gitlab-master.nvidia.com`
- You must be in a git repository with a GitLab remote

## Shell Permissions

When running `glab` commands, always use `required_permissions: ["all"]` to avoid TLS certificate verification issues with the corporate GitLab instance.

**Troubleshooting:** If glab commands fail with TLS errors, try prefixing with:

```bash
SSL_CERT_FILE=/etc/ssl/cert.pem glab ...
```

## Quick Status Check

Get the current pipeline status for the current branch:

```bash
glab ci status
```

Compact view:

```bash
glab ci status --compact
```

## Watch Pipeline in Real Time

Watch the pipeline until it completes (recommended for monitoring):

```bash
glab ci status --live
```

This will continuously update the status until the pipeline finishes (success, failed, or canceled).

## Interactive Pipeline View

For a full interactive TUI with job navigation and log viewing:

```bash
glab ci view
```

**Interactive controls:**

- Arrow keys to navigate jobs
- `Enter` to view job logs/traces
- `Ctrl+R` or `Ctrl+P` to retry/play a job
- `Ctrl+D` to cancel a job
- `Ctrl+Q` or `q` to quit
- `Esc` to close logs and return to job list

## Check Pipeline for a Specific Branch

Current branch:

```bash
glab ci status
```

Specific branch:

```bash
glab ci status --branch=main
glab ci status -b feature-branch
```

## Check Pipeline for an MR

Get the pipeline ID for a merge request:

```bash
MR_IID=123
glab api "projects/:id/merge_requests/$MR_IID/pipelines" | jq '.[0]'
```

Then view that specific pipeline:

```bash
PIPELINE_ID=456789
glab ci view --pipelineid=$PIPELINE_ID
```

## List Recent Pipelines

List pipelines for the current project:

```bash
glab ci list
```

Filter by status:

```bash
glab ci list --status=running
glab ci list --status=failed
glab ci list --status=success
```

Filter by branch/ref:

```bash
glab ci list --ref=main
glab ci list --ref=$(git branch --show-current)
```

JSON output for scripting:

```bash
glab ci list --output=json | jq '.[] | {id, status, ref, web_url}'
```

## View Job Logs

Trace a specific job's logs in real time:

```bash
glab ci trace <job-id>
```

To find the job ID, use `glab ci view` or:

```bash
# Get jobs for the latest pipeline on current branch
glab api "projects/:id/pipelines/latest/jobs?ref=$(git branch --show-current)" | jq '.[] | {id, name, status}'
```

## Wait for Pipeline Completion (Scripting)

Poll until pipeline completes:

```bash
PIPELINE_ID=$(glab ci list --ref=$(git branch --show-current) --output=json | jq -r '.[0].id')
while true; do
  STATUS=$(glab api "projects/:id/pipelines/$PIPELINE_ID" | jq -r '.status')
  echo "$(date '+%H:%M:%S') Pipeline $PIPELINE_ID: $STATUS"
  case "$STATUS" in
    success|failed|canceled) break ;;
    *) sleep 30 ;;
  esac
done
echo "Pipeline finished with status: $STATUS"
```

## Open Pipeline in Browser

Open the current branch's pipeline in your default browser:

```bash
glab ci view --web
```

## Useful Commands Reference

| Command                          | Description                              |
| -------------------------------- | ---------------------------------------- |
| `glab ci status`                 | Quick status of current branch pipeline  |
| `glab ci status --live`          | Watch pipeline until completion          |
| `glab ci status --compact`       | Compact status view                      |
| `glab ci view`                   | Interactive TUI for pipeline/jobs        |
| `glab ci view --web`             | Open pipeline in browser                 |
| `glab ci list`                   | List recent pipelines                    |
| `glab ci list --status=failed`   | List failed pipelines                    |
| `glab ci trace <job-id>`         | Stream job logs in real time             |
| `glab ci retry <job-id>`         | Retry a failed job                       |
| `glab ci cancel`                 | Cancel running pipeline                  |

## Common Flags

| Flag                | Description                                    |
| ------------------- | ---------------------------------------------- |
| `-b, --branch`      | Specify branch (default: current branch)       |
| `-p, --pipelineid`  | Specify pipeline ID                            |
| `-l, --live`        | Watch in real time until completion            |
| `-c, --compact`     | Compact output format                          |
| `-w, --web`         | Open in browser                                |
| `-R, --repo`        | Specify repository (OWNER/REPO format)         |
| `-F, --output`      | Output format: text or json                    |

## Example Workflow

1. Push your changes and create/update an MR
2. Watch the pipeline:
   ```bash
   glab ci status --live
   ```
3. If a job fails, view the logs:
   ```bash
   glab ci view
   # Navigate to failed job and press Enter
   ```
4. Retry the failed job if needed:
   ```bash
   glab ci retry <job-id>
   ```
