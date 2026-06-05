# CI

This document describes how OpenShell's continuous integration works for pull requests, with a focus on what contributors need to do to get their PR tested.

For local test commands see [TESTING.md](TESTING.md). For PR conventions see [CONTRIBUTING.md](CONTRIBUTING.md).

## Overview

PR CI that runs on NVIDIA self-hosted runners uses NVIDIA's copy-pr-bot. The bot mirrors trusted PR commits to internal `pull-request/<N>` branches in this repository. The gated workflows trigger on pushes to those branches, not on the original PR.

`Branch Checks` run automatically after copy-pr-bot mirrors the PR. `Required CI Gates` posts PR-head statuses that verify the mirror exists, is current, and ran the expected push-based workflows. E2E suites are opt-in because they are more expensive and publish temporary images.

Three opt-in labels enable the long-running E2E suites:

- `test:e2e` runs the standard E2E suite in `Branch E2E Checks`
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

### Forked PR

Prerequisites:

- DCO sign-off (`git commit -s`) on every commit. Commit signing is not required for forks - copy-pr-bot trusts forks based on maintainer review, not signing.
- A maintainer must vouch you. See the [Vouch System](AGENTS.md#vouch-system).

Flow:

1. Open the PR. The vouch check confirms you are vouched (otherwise the PR is auto-closed).
2. copy-pr-bot does not mirror forks automatically. A maintainer reviews the diff and comments `/ok to test <SHA>` with your latest commit SHA.
3. After `/ok to test`, copy-pr-bot mirrors to `pull-request/<N>`. From here the flow is identical to internal PRs: `Required CI Gates` verifies the mirror and required push workflows, and maintainers apply the E2E label when the extra suites are needed.

Important: every new commit you push requires another `/ok to test <new-SHA>` from a maintainer before push-based CI will run on it. If a label is applied while the mirror is stale, `E2E Label Help` will post a comment explaining what's needed.

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
| `.github/workflows/branch-checks.yml` | Required non-E2E PR checks. Triggers on `push: pull-request/[0-9]+`. |
| `.github/workflows/branch-e2e.yml` | Opt-in standard, GPU, and Kubernetes HA E2E. Triggers on `push: pull-request/[0-9]+` and runs jobs selected by `test:e2e`, `test:e2e-gpu`, or `test:e2e-kubernetes`. |
| `.github/workflows/helm-lint.yml` | Helm chart validation. Triggers on `push: pull-request/[0-9]+` and skips lint jobs unless Helm inputs changed. |
| `.github/actions/pr-gate/action.yml` | Composite action that resolves PR metadata and verifies the required label is set. |
| `.github/actions/pr-merge-base/action.yml` | Composite action that resolves and fetches the merge-base commit for `pull-request/<N>` push workflows. |
| `.github/workflows/required-ci-gates.yml` | Posts required PR-head statuses for push-based CI workflows. This is what branch protection should require. |
| `.github/workflows/e2e-label-help.yml` | When a `test:e2e*` label is applied, posts a PR comment telling the maintainer the next manual step (re-run an existing workflow run, or `/ok to test <SHA>` to refresh the mirror). |

## Release workflows

These workflows run after merge to publish dev/tagged artifacts and verify them. They are not PR-gated.

| File | Role |
|---|---|
| `.github/workflows/release-dev.yml` | Publishes the rolling `dev` build on every push to `main`. Builds gateway/supervisor images and binaries, packages, wheels, and pushes the Helm chart as `oci://ghcr.io/nvidia/openshell/helm-chart:0.0.0-dev` (plus an immutable `0.0.0-dev.<sha>` pin). Also dispatchable manually. |
| `.github/workflows/release-tag.yml` | Publishes a tagged public release. |
| `.github/workflows/release-canary.yml` | Smoke-tests published artifacts on `macos`, `ubuntu`, `fedora`, and `kubernetes` (kind + Helm) runners. Triggers automatically when `Release Dev` succeeds, and via `workflow_dispatch` on any branch (`gh workflow run release-canary.yml --ref <branch>`). The `kubernetes` job pins to `0.0.0-dev` artifacts; the other jobs install the latest tagged release via `install.sh`. See the `test-release-canary` skill for the manual-dispatch playbook and local kind reproduction. |

## Required status contexts

Require these statuses in the branch ruleset for push-based CI:

- `OpenShell / Branch Checks`
- `OpenShell / E2E`
- `OpenShell / GPU E2E`
- `OpenShell / Helm Lint`

Do not require the underlying push workflow jobs directly. Those jobs only appear after copy-pr-bot mirrors trusted code, so they cannot independently prove that an untrusted or stale PR head was tested.
