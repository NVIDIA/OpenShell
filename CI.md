# CI

This document describes how OpenShell's continuous integration works for pull requests, with a focus on what contributors need to do to get their PR tested.

For local test commands see [TESTING.md](TESTING.md). For PR conventions see [CONTRIBUTING.md](CONTRIBUTING.md).

## Overview

PR CI that runs on NVIDIA self-hosted runners uses NVIDIA's copy-pr-bot. The bot mirrors trusted PR commits to internal `pull-request/<N>` branches in this repository. The gated workflows trigger on pushes to those branches, not on the original PR.

`Branch Checks` run automatically after copy-pr-bot mirrors the PR. `Required CI Gates` posts PR-head statuses that verify the mirror exists, is current, and ran the expected push-based workflows. E2E suites are opt-in because they are more expensive and publish temporary images.

Merge queue validation is a second integration gate for `main`. After a PR has passed the required PR-head statuses, a maintainer adds it to the merge queue. GitHub creates a temporary merge-group branch that combines the latest `main`, the queued PR, and any earlier queued PRs. The same required `OpenShell / ...` status contexts are then published against the merge-group SHA before GitHub merges it.

Three opt-in labels enable the long-running E2E suites:

- `test:e2e` runs the standard Docker, rootless Podman, Kubernetes, and VM E2E
  suites in `Branch E2E Checks`
- `test:e2e-gpu` runs GPU E2E in `Branch E2E Checks`
- `test:e2e-kubernetes` runs Kubernetes E2E with the HA Helm overlay
  (`replicaCount: 2` and bundled PostgreSQL) in `Branch E2E Checks`

When multiple labels are present, `Branch E2E Checks` builds the shared gateway and supervisor images once and fans out all enabled suites in parallel.
The `OpenShell / E2E` and `OpenShell / GPU E2E` required statuses are evaluated from separate suite result jobs inside that workflow. `test:e2e-kubernetes` is optional while HA behavior is under active iteration: failures are visible in the workflow run but do not publish a required CI gate status.

The GitHub ruleset should require the `OpenShell / ...` statuses published by `Required CI Gates`, not the push-triggered workflow jobs directly.

## Commit signing

copy-pr-bot decides whether to mirror a PR automatically based on whether the author is trusted. For org members and collaborators, "trusted" means **all commits in the PR are cryptographically signed**. Unsigned commits, even from an org member, force the bot to wait for a maintainer's `/ok to test <SHA>`.

DCO sign-off (`-s` / `Signed-off-by`) is a separate requirement and does not count as commit signing. Dependabot-authored dependency update PRs are allowlisted in DCO Assistant because the bot cannot sign commits.

### One-time setup with an SSH key

If you already use an SSH key for `git push`, you can reuse it as a signing key. (You can also generate a separate one - GitHub allows the same SSH key as both auth and signing.)

1. Generate a key (skip if reusing your existing SSH key):

   ```shell
   ssh-keygen -t ed25519 -C "you@example.com" -f ~/.ssh/id_ed25519_signing
   ```

2. Add the **public** key at <https://github.com/settings/keys> using **New SSH key**, and set **Key type: Signing Key** (not Authentication). Signing keys are managed separately from authentication keys, even when they reuse the same key material - you have to add the entry once for each role.

3. Configure git globally:

   ```shell
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
   git config --global commit.gpgsign true
   git config --global tag.gpgsign true
   ```

4. Verify on a test commit:

   ```shell
   git commit --allow-empty -s -m "test: signing"
   ```

   Push the branch and confirm GitHub shows the commit as **Verified**.

## Pull request flows

### Internal contributor PR

Prerequisites:

- Org member or collaborator on the repo.
- All commits cryptographically signed (see [Commit signing](#commit-signing)).
- All commits include a DCO sign-off (`git commit -s`).

Flow:

1. Open the PR. copy-pr-bot mirrors it to `pull-request/<N>` automatically.
2. The mirror push runs `Branch Checks` automatically. `Required CI Gates` keeps the PR blocked until the mirror exists, matches the PR head SHA, and the required push-based workflow succeeds. The first `Branch E2E Checks` run only resolves metadata and skips expensive jobs unless an E2E label is already set.
3. A maintainer applies `test:e2e`, `test:e2e-gpu`, and/or `test:e2e-kubernetes`. `E2E Label Help` posts a comment with a link to the existing gated workflow run.
4. The maintainer opens that link and clicks **Re-run all jobs**. This time `pr_metadata` sees the label and the build/E2E jobs run.
5. When the run finishes, the matching `OpenShell / ...` gate status flips to green automatically.
6. New commits push to the mirror automatically and re-trigger `Branch Checks` plus any labeled E2E jobs in `Branch E2E Checks`.
7. When the PR is ready to merge, use **Add to merge queue** instead of merging directly. The queue validates the final integration state before updating `main`.

### Forked PR

Prerequisites:

- DCO sign-off (`git commit -s`) on every commit. Commit signing is not required for forks - copy-pr-bot trusts forks based on maintainer review, not signing.
- A maintainer must vouch you. See the [Vouch System](AGENTS.md#vouch-system).

Flow:

1. Open the PR. The vouch check confirms you are vouched (otherwise the PR is auto-closed).
2. copy-pr-bot does not mirror forks automatically. A maintainer reviews the diff and comments `/ok to test <SHA>` with your latest commit SHA.
3. After `/ok to test`, copy-pr-bot mirrors to `pull-request/<N>`. From here the flow is identical to internal PRs: `Required CI Gates` verifies the mirror and required push workflows, and maintainers apply the E2E label when the extra suites are needed.
4. When the PR is ready to merge, maintainers add it to the merge queue so the queued integration state is tested before it reaches `main`.

Important: every new commit you push requires another `/ok to test <new-SHA>` from a maintainer before push-based CI will run on it. If a label is applied while the mirror is stale, `E2E Label Help` will post a comment explaining what's needed.

## Merge queue

GitHub merge queue is required for `main`. Repository administrators must enable **Require merge queue** in the branch ruleset for `main` and keep these required status contexts aligned with the PR gates:

- `OpenShell / Branch Checks`
- `OpenShell / E2E`
- `OpenShell / GPU E2E`
- `OpenShell / Helm Lint`

Do not require the underlying workflow job names directly. `Required CI Gates` publishes stable commit statuses for both PR-head mirror commits and merge-group commits.

Merge-group runs use the `merge_group` event. The event is distinct from `pull_request` and `push`, and GitHub will not report required checks for queued PRs unless the workflows include it. In this repository:

- `Branch Checks` runs the standard non-E2E gates on the merge-group SHA.
- `Branch E2E Checks` runs core E2E and GPU E2E for merge groups. Kubernetes HA E2E remains optional and label-driven on PRs.
- `Helm Lint` runs for merge groups without the PR diff optimization, because the merge-group branch is the final integration state.
- `Required CI Gates` posts the same `OpenShell / ...` statuses to the merge-group SHA and does not require a `pull-request/<N>` mirror for merge-group events.

Maintainers should add ready PRs to the queue rather than pressing a direct merge button. GitHub removes a PR from the queue if the merge-group checks fail or time out.

## copy-pr-bot

[copy-pr-bot](https://github.com/apps/copy-pr-bot) is a GitHub App maintained by NVIDIA that solves a specific GitHub Actions security problem: by default, `pull_request`-triggered workflows on a self-hosted runner can run an arbitrary contributor's code on hardware the project owns. For projects that need self-hosted runners (GPU access, ARM hardware, on-prem secrets), GitHub's recommended pattern is to never trigger workflows directly from external `pull_request` events.

copy-pr-bot enforces that pattern. When a PR is opened against this repository, the bot evaluates whether the change is trusted - by default, only commits authored by org members and signed with a verified key are trusted, and forks always need an explicit per-SHA approval. Once a change passes that check, the bot mirrors the PR head into a branch named `pull-request/<N>` inside this repository. Our self-hosted workflows then trigger on `push` to those mirror branches, never on the original `pull_request` event.

The user-visible consequences inside this repo:

- A PR cannot run E2E until copy-pr-bot has mirrored it. For trusted authors this happens within seconds of opening the PR; for forked PRs it requires a maintainer to comment `/ok to test <SHA>`.
- New commits to a fork need a fresh `/ok to test <new-SHA>` before the mirror updates.
- The `pull-request/<N>` branches are not for humans to push to - they are managed by the bot.

The bot's full administrator documentation is internal to NVIDIA. The only command contributors may see in PR comments is `/ok to test <SHA>`, used by maintainers to approve a specific commit on a forked PR for testing.

## Workflow files

| File | Role |
|---|---|
| `.github/workflows/branch-checks.yml` | Required non-E2E checks. Triggers on `push: pull-request/[0-9]+` for PR mirrors and `merge_group` for queued merges. |
| `.github/workflows/branch-e2e.yml` | Standard, GPU, and Kubernetes HA E2E. PR mirror pushes use `test:e2e`, `test:e2e-gpu`, and `test:e2e-kubernetes` labels; merge groups run core and GPU E2E. |
| `.github/workflows/helm-lint.yml` | Helm chart validation. PR mirror pushes skip lint jobs unless Helm inputs changed; merge groups always validate Helm because they represent the final integration state. |
| `.github/actions/pr-gate/action.yml` | Composite action that resolves PR metadata and verifies the required label is set for PR mirror pushes. Non-push events are allowed through. |
| `.github/actions/pr-merge-base/action.yml` | Composite action that resolves and fetches the merge-base commit for `pull-request/<N>` push workflows. |
| `.github/workflows/required-ci-gates.yml` | Posts required PR-head and merge-group statuses for gated CI workflows. This is what branch protection and merge queue should require. |
| `.github/workflows/e2e-label-help.yml` | When a `test:e2e*` label is applied, posts a PR comment telling the maintainer the next manual step (re-run an existing workflow run, or `/ok to test <SHA>` to refresh the mirror). |

## Release workflows

These workflows run after merge to publish dev/tagged artifacts and verify them. They are not PR-gated.

| File | Role |
|---|---|
| `.github/workflows/release-dev.yml` | Publishes the rolling `dev` build on every push to `main`. Builds gateway/supervisor images and binaries, packages, wheels, and pushes the Helm chart as `oci://ghcr.io/nvidia/openshell/helm-chart:0.0.0-dev` (plus an immutable `0.0.0-dev.<sha>` pin). Also dispatchable manually. |
| `.github/workflows/release-tag.yml` | Publishes a tagged public release. |
| `.github/workflows/release-canary.yml` | Smoke-tests published artifacts on `macos`, `ubuntu`, `fedora`, and `kubernetes` (kind + Helm) runners. Triggers automatically when `Release Dev` succeeds, and via `workflow_dispatch` on any branch (`gh workflow run release-canary.yml --ref <branch>`). The `kubernetes` job pins to `0.0.0-dev` artifacts; the other jobs install the latest tagged release via `install.sh`. See the `test-release-canary` skill for the manual-dispatch playbook and local kind reproduction. |

## Required status contexts

Require these statuses in the branch ruleset for PR and merge-queue CI:

- `OpenShell / Branch Checks`
- `OpenShell / E2E`
- `OpenShell / GPU E2E`
- `OpenShell / Helm Lint`

Do not require the underlying workflow jobs directly. PR workflow jobs only appear after copy-pr-bot mirrors trusted code, and merge-group workflow jobs run on temporary queue branches. The stable `OpenShell / ...` contexts prove the expected workflow completed for the commit that GitHub is about to merge.
