# CI

This document describes how OpenShell's continuous integration works for pull requests, with a focus on what contributors need to do to get their PR tested.

For local test commands see [TESTING.md](TESTING.md). For PR conventions see [CONTRIBUTING.md](CONTRIBUTING.md).

## Overview

PR CI that runs on NVIDIA self-hosted runners uses NVIDIA's copy-pr-bot. The bot mirrors trusted PR commits to internal `pull-request/<N>` branches in this repository. The gated workflows trigger on pushes to those branches, not on the original PR.

`Branch Checks` run automatically after copy-pr-bot mirrors the PR. E2E suites are opt-in because they are more expensive and publish temporary images.

Two opt-in labels enable the suites:

- `test:e2e` runs `Branch E2E Checks` (non-GPU E2E)
- `test:e2e-gpu` runs `GPU Test`

Both are required to merge once the corresponding `E2E Gate` checks are marked required in branch protection.

## Commit signing

copy-pr-bot decides whether to mirror a PR automatically based on whether the author is trusted. For org members and collaborators, "trusted" means **all commits in the PR are cryptographically signed**. Unsigned commits, even from an org member, force the bot to wait for a maintainer's `/ok to test <SHA>`.

DCO sign-off (`-s` / `Signed-off-by`) is a separate requirement and does not count as commit signing.

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
2. The mirror push runs `Branch Checks` automatically. The first `Branch E2E Checks` / `GPU Test` run only resolves metadata and skips expensive jobs unless the matching label is already set.
3. A maintainer applies `test:e2e` and/or `test:e2e-gpu`. `E2E Label Help` posts a comment with a link to the existing gated workflow run.
4. The maintainer opens that link and clicks **Re-run all jobs**. This time `pr_metadata` sees the label and the build/E2E jobs run.
5. When the run finishes, the `E2E Gate` check on the PR flips to green automatically.
6. New commits push to the mirror automatically and re-trigger `Branch Checks` plus any labeled E2E/GPU workflows.

### Forked PR

Prerequisites:

- DCO sign-off (`git commit -s`) on every commit. Commit signing is not required for forks - copy-pr-bot trusts forks based on maintainer review, not signing.
- A maintainer must vouch you. See the [Vouch System](AGENTS.md#vouch-system).

Flow:

1. Open the PR. The vouch check confirms you are vouched (otherwise the PR is auto-closed).
2. copy-pr-bot does not mirror forks automatically. A maintainer reviews the diff and comments `/ok to test <SHA>` with your latest commit SHA.
3. After `/ok to test`, copy-pr-bot mirrors to `pull-request/<N>`. From here the flow is identical to internal PRs: maintainer applies the label, follows the comment from `E2E Label Help`, and re-runs the workflow.

Important: every new commit you push requires another `/ok to test <new-SHA>` from a maintainer before E2E will run on it. If a label is applied while the mirror is stale, `E2E Label Help` will post a comment explaining what's needed.

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
| `.github/workflows/branch-e2e.yml` | Non-GPU E2E. Triggers on `push: pull-request/[0-9]+`. |
| `.github/workflows/test-gpu.yml` | GPU E2E. Triggers on `push: pull-request/[0-9]+`. |
| `.github/actions/pr-gate/action.yml` | Composite action that resolves PR metadata and verifies the required label is set. |
| `.github/workflows/e2e-gate.yml` | Posts the required `E2E Gate` check on the PR. Re-evaluates after the gated workflow completes. |
| `.github/workflows/e2e-gate-check.yml` | Reusable gate logic shared by E2E and GPU E2E. |
| `.github/workflows/e2e-label-help.yml` | When a `test:e2e*` label is applied, posts a PR comment telling the maintainer the next manual step (re-run an existing workflow run, or `/ok to test <SHA>` to refresh the mirror). |
