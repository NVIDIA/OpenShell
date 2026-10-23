---
name: watch-github-actions
description: Watch and monitor GitHub Actions workflow runs using the gh CLI. Use when the user wants to check workflow status, watch a running workflow, view CI/CD jobs, or monitor build progress. Trigger keywords - watch pipeline, pipeline status, CI status, check build, monitor CI, view pipeline, pipeline progress, workflow status, actions status.
metadata:
  internal: true
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

For tmachine Kubernetes conformance failures, inspect the `tmachine-diagnostics-*` artifact. The K3s report includes Agent Sandbox controller state, leader leases, events, and current and previous controller logs. The conformance playbook checks reconciliation after guest boot with a temporary scheduling-gated Sandbox probe before running tests. Distinguish a failed controller probe from a failed conformance scenario; gateway connectivity and controller Deployment availability do not prove reconciliation works.

For the `e2e-suites` lane (`.github/workflows/e2e-suites.yml`), the last lines of the job log give the runner's result: PASS, FAIL with the failed tests, or ERROR with the step that broke. Then inspect the `e2e-results-<family>-<package>-<environment>-<installer>` artifact, which holds `junit.xml`, `nextest.log` and, after a failure, the guest's `diagnostics/`.

`Pre-release` temporarily omits Codex Security from its `Security Scan` job.
`Release` uses the passing prerelease qualification result. Other scanners and
qualification gates still run. Use the standalone
`Codex Security Release Qualification` workflow for manual investigation.

For `Codex Security`, an exit code of 2 with partial coverage is an incomplete
scan, not a HIGH/CRITICAL threshold failure. Check the execution diagnostics in
the job summary and the `codex-security-diagnostics-<run>-<attempt>` artifact on
scan failure. It contains fixed status values, aggregate coverage counts, and
disk space before, after, and the minimum sampled every five seconds. Missing
coverage or manifest documents indicate no readable final report was available;
deferred items or surfaces needing follow-up can explain partial coverage.
Sampling cannot rule out a disk spike between samples.

Artifacts and logs in this public repository are public. Never upload the raw
scan directory, `report.md`, `coverage.json`, findings, agent state, or scanner
logs. Coverage reasons and notes are free text and may disclose vulnerabilities.
The public diagnostic intentionally omits them; detailed review needs an
approved private destination. Helpers must come from the workflow revision,
not from the candidate under scan.

`setup-nix` retries development-shell preparation once when `prepare-shell`
is enabled. Inspect both attempts in the job log; `setup-rust` assumes the
shell has already been prepared. Cargo, lint, and test commands are not retried.
Direct Nix builds and app dependency preparation also retry once; apps run
once after preparation succeeds. Skipped dependent E2E suites indicate blocked
coverage.

For `Trivy Changes`, inspect the `Resolve PR baseline` step for the base and head
SHAs. PR runs compare the tested merge commit with its
first parent; change detection and scans must use the same pair. On reruns, do
not substitute the current `main` tip or the event's older PR base SHA. Merge
groups and manual runs use their explicit baseline. Findings are reported by
`Reject new high or critical findings`; distinguish those from scanner failures.

For `Protobuf Compatibility`, check the logged train and comparison baseline.
Branch Checks compares the prospective merge tree with its target; release qualification
compares the tagged candidate with the previous stable release. Both use
the shared `check-protobuf-compatibility` action with `nix run .#check-protobuf-compatibility -- <ref>`.
During `0.x`, a minor train permits compatibility findings
as warnings; a patch train or no active train rejects them. Compare the current
train's version with the latest stable release; commit messages are irrelevant.
Compilation, baseline, and tool errors remain fatal. The `protobuf_compatibility` suite participates in
the `release-tag-v1` qualification profile. Pre-release calls the reusable
`release-qualification.yml` workflow after building, in parallel with publication. Release
selects the latest passing prerelease for the requested version and branch,
verifies its qualification evidence, creates the stable tag at its exact commit,
then rebuilds and publishes without rerunning qualification. The promotion job
summary and `stable-promotion-*` artifact record the candidate and evidence.
Failed, cancelled, or skipped required suites fail
qualification; stable publication is blocked, while published pre-release
artifacts remain available. The Pre-release failure notification includes the
run link. Both callers share `release-build.yml` and `release-publish.yml`.
Qualification evidence remains in Actions; publishing a copy to OCI storage is best effort.
Snap Store uploads happen only for stable releases after qualification passes.

For a release notes preview, dispatch `release.yml` with `notes-only=true` and
`tag=<stable-tag>`. The generator resolves the previous reachable stable tag;
only `release-notes.yml` exposes an optional `previous-stable-tag` override.
This runs the same
`release-notes.yml` generator as stable publication and retains the `release-notes`
artifact. Promotion, tag creation, builds, qualification, and publication are
skipped. Check the `Prepare release notes` step before diagnosing model or
GitHub API failures; it requires `LLM_INFERENCE_API_KEY`, `ANTHROPIC_BASE_URL`, and
`ANTHROPIC_MODEL` in the repository Actions settings.

Pre-release also runs `release-notes.yml` after building, alongside publication
and qualification, and keeps the notes only in the `release-notes` artifact.
This job is advisory: a notes failure emits a warning without failing the
prerelease run or blocking promotion. Stable publication reuses the promoted
prerelease's `release-notes` artifact, retagged, and generates notes only when
that preview is unavailable. The `Select Qualified Prerelease` summary says
which happened.

For `Codex Compatibility Review`, inspect its job summary and the
`compatibility-review-run-<run-id>-attempt-<attempt>` artifact. Confirm the
candidate and baseline SHAs before interpreting findings. `complete` describes
execution and coverage, not compatibility: also read the assessment and findings.
An `error`, incomplete coverage, or missing artifact means no clean review is
available. Findings are advisory. The review targets breaking changes with high
reasoning effort. Risk acceptance needs a linked author or verified-maintainer
comment or review, not a PR description, general approval, or bot report.
The full report keeps all findings and prior-comment links. `comment.md` includes
only new or materially changed findings; unchanged reviews post no comment. Check
the full artifact linked by qualification even when the bot is silent.
The review is scheduled independently of Security Scan. The two Codex workflows
share the `codex-release-review` concurrency group with `queue: max`, retaining
up to 100 pending reviews while preventing overlapping API usage across runs.
Either review can run first; other security scanners run in parallel.
The qualification caller waits for both reviews to finish. Do not
rerun Release or Pre-release to debug this reviewer. Use its dedicated manual workflow
with an existing candidate tag; that path does not publish release artifacts.

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
