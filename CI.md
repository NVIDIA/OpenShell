# CI

This document describes how OpenShell's continuous integration works for pull requests, with a focus on what contributors need to do to get their PR tested.

For local test commands see [TESTING.md](TESTING.md). For PR conventions see [CONTRIBUTING.md](CONTRIBUTING.md).

## Overview

E2E tests run on self-hosted runners (`build-arm64`, GPU runners). To keep untrusted PR code off those runners we use NVIDIA's [copy-pr-bot](https://docs.gha-runners.nvidia.com/platform/apps/copy-pr-bot/), which mirrors trusted PRs to internal `pull-request/<N>` branches. The gated workflows trigger on pushes to those branches, not on the original PR.

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

If you have older unsigned commits on a branch, sign them by rebasing:

```shell
git rebase --exec 'git commit --amend --no-edit -S' origin/main
```

## Pull request flows

### Internal contributor PR

Prerequisites:

- Org member or collaborator on the repo.
- All commits cryptographically signed (see [Commit signing](#commit-signing)).
- All commits include a DCO sign-off (`git commit -s`).

Flow:

1. Open the PR. copy-pr-bot mirrors it to `pull-request/<N>` automatically.
2. A maintainer applies `test:e2e` and/or `test:e2e-gpu`.
3. `E2E Label Dispatch` detects the label and triggers the matching workflow against the mirror.
4. Results post as checks on your PR head SHA.
5. New commits push to the mirror automatically; gated workflows re-run on their own. No re-labeling needed.

### Forked PR

Prerequisites:

- DCO sign-off (`git commit -s`) on every commit. Commit signing is not required for forks - copy-pr-bot trusts forks based on maintainer review, not signing.
- A maintainer must vouch you. See the [Vouch System](AGENTS.md#vouch-system).

Flow:

1. Open the PR. The vouch check confirms you are vouched (otherwise the PR is auto-closed).
2. copy-pr-bot does not mirror forks automatically. A maintainer reviews the diff and comments `/ok to test <SHA>` with your latest commit SHA.
3. After `/ok to test`, copy-pr-bot mirrors to `pull-request/<N>`.
4. A maintainer applies `test:e2e` / `test:e2e-gpu`. The dispatcher runs the matching workflow against the mirror.
5. Results post as checks on your PR.

Important: every new commit you push requires another `/ok to test <new-SHA>` from a maintainer before E2E will run on it. If a label is applied while the mirror is stale, `E2E Label Dispatch` will post a comment explaining what's needed.

## Workflow files

| File | Role |
|---|---|
| `.github/workflows/branch-e2e.yml` | Non-GPU E2E. Triggers on `push: pull-request/[0-9]+`. |
| `.github/workflows/test-gpu.yml` | GPU E2E. Triggers on `push: pull-request/[0-9]+`. |
| `.github/actions/pr-gate/action.yml` | Composite action that resolves PR metadata and verifies the required label is set. |
| `.github/workflows/e2e-gate.yml` | Posts the required `E2E Gate` check on the PR. Re-evaluates after the gated workflow completes. |
| `.github/workflows/e2e-gate-check.yml` | Reusable gate logic shared by E2E and GPU E2E. |
| `.github/workflows/e2e-label-dispatch.yml` | Triggers gated workflows when a `test:e2e*` label is applied. Posts a comment if the mirror is missing or stale. |
