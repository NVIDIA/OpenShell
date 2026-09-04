# CI

This document describes how OpenShell's continuous integration works for pull requests, with a focus on what contributors need to do to get their PR tested.

For local test commands see [TESTING.md](TESTING.md). For PR conventions see [CONTRIBUTING.md](CONTRIBUTING.md).

## Overview

PR CI that runs on NVIDIA self-hosted runners uses NVIDIA's copy-pr-bot. The bot mirrors trusted PR commits to internal `pull-request/<N>` branches in this repository. The gated workflows trigger on pushes to those branches, not on the original PR.

`Branch Checks` run automatically after copy-pr-bot mirrors the PR. `Required CI Gates` posts PR-head statuses that verify the mirror exists, is current, and ran the expected push-based workflows. E2E suites are opt-in because they are more expensive and publish temporary images.

Merge queue validation is a second integration gate for `main`. After a PR has passed the required PR-head statuses, a maintainer adds it to the merge queue. GitHub creates a temporary merge-group branch that combines the latest `main`, the queued PR, and any earlier queued PRs. The same required `OpenShell / ...` status contexts are then published against the merge-group SHA before GitHub merges it.

Three opt-in labels enable the long-running E2E suites:

- `test:e2e` runs the Docker, rootless Podman, Kubernetes, and VM E2E suites
  with both managed and standalone compute drivers in `Branch E2E Checks`
- `test:e2e-gpu` runs GPU E2E in `Branch E2E Checks`
- `test:e2e-kubernetes` runs Kubernetes E2E with the HA Helm overlay
  (`replicaCount: 2` and bundled PostgreSQL) and the credential-driver suite
  (Kubernetes Secrets plus Vault) in `Branch E2E Checks`

When multiple labels are present, `Branch E2E Checks` builds each generic multi-architecture artifact set once and fans out enabled suites in parallel. Runtime-specific reusable workflows define the Docker, Podman, VM, and Kubernetes lanes. Composite actions own the replaceable Podman, KVM, kind, and mise setup. Each lane depends only on the artifact categories it consumes: VM does not wait for container-driver artifacts or supervisor images, and GPU does not wait for the gateway image. Docker, Podman, GPU, Rust, Python, MCP, and VM E2E reuse matching prebuilt gateway and CLI binaries instead of compiling debug binaries in test jobs. Standalone-driver lanes additionally reuse driver-free gateway and compute-driver artifacts. Kubernetes managed-driver lanes consume published gateway and supervisor images, while the standalone-driver lane composes its gateway image from prebuilt binaries.
The `OpenShell / E2E` and `OpenShell / GPU E2E` required statuses are evaluated from separate suite result jobs inside that workflow. `test:e2e-kubernetes` is optional while Kubernetes HA and credential-driver behavior are under active iteration: failures are visible in the workflow run but do not publish a required CI gate status.

The GitHub ruleset should require the `OpenShell / ...` statuses published by
`Required CI Gates` plus the direct `OpenShell / Trivy Changes` result, not the
push-triggered workflow jobs themselves.

## Informational security reports

Security workflow compute runs directly on GitHub-hosted runners instead of
NVIDIA self-hosted runners. The PR-oriented workflows receive no secrets and run
on fork pull requests without waiting for copy-pr-bot. Codex Security release
qualification is the exception: it runs only for maintainer-created
pre-release tags and receives a scoped NVIDIA Inference API key for the scan
step. Scanner jobs request `security-events: write` to publish SARIF to Code
Scanning. GitHub permits Code Scanning uploads from `pull_request` runs even
when fork and Dependabot contexts receive a read-only `GITHUB_TOKEN`, so those
scanners upload results directly:

- `Workflow Security Reports` runs Actionlint and Zizmor. Actionlint reports
  workflow syntax and expression findings. Zizmor reports only High severity,
  its maximum level. Nix provides both scanners. They publish SARIF to Code
  Scanning and retain report artifacts.
- `Dependency Review` compares the base and head dependency graphs and reports
  newly introduced vulnerabilities with a High-or-higher policy. It runs in
  warn-only mode. A preflight turns an unavailable GitHub Dependency Graph into
  a warning, so the workflow remains neutral until the repository feature is
  available.
- `CodeQL` analyzes product Rust code, examples, and the Go, Python, and
  TypeScript SDKs. Rust `cfg(test)` blocks, Rust integration-test targets, and
  E2E test code are excluded. It runs nightly on `main`, remains manually
  dispatchable for diagnostics, uploads results to Code Scanning, and retains
  workflow artifacts.
- `Codex Security Release Qualification` analyzes each `vX.Y.Z-pre.N`
  candidate against the previous stable release. Every candidate in a release
  train therefore rescans the cumulative stable-to-candidate diff. It calls
  `https://inference-api.nvidia.com/v1` with
  `openai/openai/gpt-5.6-sol` at medium reasoning effort. The
  `CODEX_SECURITY_API_KEY` secret must contain an API key authorized for that
  NVIDIA endpoint. Results are uploaded against the candidate commit on `main`
  under a category shared by the train, for example
  `codex-security/v0.1.1`, so later candidates replace earlier analyses. The
  slash-qualified NVIDIA model identifier prevents Codex Security 0.1.24 from
  enforcing `--max-cost`, so the workflow relies on its timeout, serialized
  concurrency, and the inference account's spend controls. Raw reports are not
  retained as workflow artifacts. Pre-release creation and stable-promotion
  enforcement remain part of RFC 0014 and are not implemented by this workflow.

Findings do not fail these workflows. Tool startup, configuration, build, and
analysis failures still fail so a broken scanner cannot appear healthy. The
PR-oriented reports also run on merge groups; CodeQL is not a PR or merge-queue
check. None of these reports are required statuses or gate merges.

Run the workflow-definition scanners locally with:

```shell
nix develop --command actionlint -shellcheck= -pyflakes=
nix develop --command zizmor --offline --persona=regular --min-severity=high --no-exit-codes .
```

## Artifact scanning

`Trivy Scan` differs from the reports above in what it looks at rather than in
how it reports: it scans what a release publishes instead of what a change
contains — the final container images, the Helm charts, the final image
Dockerfiles, and the raw Kubernetes manifests. Nix provides Trivy and Helm, and
the jobs run on GitHub-hosted runners like the other scanners.

Findings are informational for now, while we learn what the scanner reports in
practice. They raise a warning and the run stays green; a scanner that cannot
run still fails, so a broken scan cannot look clean. The `fail-on-findings`
input flips that to a hard failure once the findings have been worked through.

The workflow is reusable and takes OCI references as input, so it knows nothing
about how a release is assembled. `HIGH` and `CRITICAL` are what get reported as
findings; everything below is listed without comment. Image scanning
additionally ignores vulnerabilities with no upstream fix, because a base-image
CVE without a patch would otherwise be permanent noise. That option does not
apply to misconfigurations.

It is not listed in any release workflow's `needs:`, so no publication depends
on it. Wiring it into `release-dev.yml` and `release-tag.yml` is a separate
change, and one that only makes sense once findings fail.

The configuration scan targets `deploy/` in one pass, which covers both charts,
the published Dockerfiles and the raw manifests. The macOS Dockerfiles export a
binary from `FROM scratch` and the CI image is toolchain rather than a release
artifact, so both are skipped.

Chart coverage additionally depends on value combinations. The chart defaults
render 10 of the chart's 19 templates, while some conditional resources only
render with overrides stored under `deploy/helm/openshell/ci/values-*.yaml`.
The scan exercises each of these CI fixtures to cover resources such as the
high-availability Deployment, Gateway API objects, OpenShift Route, and broader
workspace-mode ClusterRole. These fixtures are test inputs, not a set of
separately supported product profiles.

Exceptions live in `.trivyignore.yaml`, one justification per entry. Trivy
auto-loads a plain `.trivyignore` but not the YAML variant, so the scripts pass
`--ignorefile` explicitly. An entry qualifies only when the finding is wrong:
the condition it reports is not true of this repository, or it is an artifact of
how the scan renders the chart. Hardening we have not done and risks we have
accepted stay in the report, where they can be seen and argued about, even when
that means the gate fails.

Four checks report today: `KSV-0014` (`readOnlyRootFilesystem` unset on the
gateway container), `KSV-0041` and `KSV-0056` (RBAC grants the managed workspace
mode needs and that RBAC cannot express more narrowly), and `DS-0002` (the
supervisor image runs as root by design). Resolving or consciously accepting
each of those is what has to happen before `fail-on-findings` is worth turning
on.

Scans write full-severity reports and never fail on findings, so a report is
always available to upload; a separate `gate` step re-reads them and applies the
threshold. Run them locally with:

```shell
nix develop --command tasks/scripts/trivy-scan.sh config
nix develop --command tasks/scripts/trivy-scan.sh images ghcr.io/nvidia/openshell/gateway:dev
nix develop --command tasks/scripts/trivy-scan.sh gate
```

### Pull-request change gate

`Trivy Changes` runs directly on pull requests and merge groups. It detects
changes to Helm charts, release Dockerfiles, and the Trivy tooling, then scans
both the base revision and the candidate with the same scanner logic. The check
fails only when the candidate introduces a new `HIGH` or `CRITICAL`
misconfiguration, so existing findings do not block unrelated work. Reports
from both revisions are retained as workflow artifacts.

This check analyzes Helm and Dockerfile configuration. It does not build
container images, so package and operating-system CVEs remain the responsibility
of the release-artifact image scan.

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
- `OpenShell / Trivy Changes`

`Required CI Gates` publishes the stable statuses for mirror-based workflows.
`Trivy Changes` runs directly on pull requests and merge groups and publishes
its own stable result status.

Merge-group runs use the `merge_group` event. The event is distinct from `pull_request` and `push`, and GitHub will not report required checks for queued PRs unless the workflows include it. In this repository:

- `Branch Checks` runs the standard non-E2E gates on the merge-group SHA.
- `Branch E2E Checks` runs core E2E and GPU E2E for merge groups. Kubernetes HA E2E remains optional and label-driven on PRs.
- `Helm Lint` runs for merge groups without the PR diff optimization, because the merge-group branch is the final integration state.
- `Trivy Changes` compares the merge-group configuration with its base and rejects new High or Critical findings.
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
| `.github/workflows/branch-e2e.yml` | Standard, GPU, Kubernetes HA, and Kubernetes credential-driver E2E. PR mirror pushes use `test:e2e`, `test:e2e-gpu`, and `test:e2e-kubernetes` labels; merge groups run core and GPU E2E. |
| `.github/workflows/build-{cli,gateway,sandbox}-binaries.yml` | Independent target matrices used by branch and release workflows without creating skipped jobs. |
| `.github/workflows/package-release-binaries.yml` | Packages raw build artifacts into release tarballs without rebuilding them. |
| `.github/workflows/e2e-docker-test.yml`, `e2e-podman-test.yml`, `e2e-vm-test.yml`, `e2e-kubernetes-test.yml` | Reusable runtime lanes called directly by branch and release workflows. Callers select suites and declare only the artifacts each runtime consumes. |
| `.github/actions/setup-e2e-*` | Shared artifact, Podman, KVM, and kind setup used by the runtime lanes. |
| `.github/workflows/helm-lint.yml` | Helm chart validation. PR mirror pushes skip lint jobs unless Helm inputs changed; merge groups always validate Helm because they represent the final integration state. |
| `.github/actions/setup-nix/action.yml` | Installs Nix and configures the OpenShell Cachix cache, using read-only cache access when no authentication token is available. |
| `.github/actions/pr-gate/action.yml` | Composite action that resolves PR metadata and verifies the required label is set for PR mirror pushes. Non-push events are allowed through. |
| `.github/actions/pr-merge-base/action.yml` | Composite action that resolves and fetches the merge-base commit for `pull-request/<N>` push workflows. |
| `.github/workflows/required-ci-gates.yml` | Posts required PR-head and merge-group statuses for gated CI workflows. This is what branch protection and merge queue should require. |
| `.github/workflows/e2e-label-help.yml` | When a `test:e2e*` label is applied, posts a PR comment telling the maintainer the next manual step (re-run an existing workflow run, or `/ok to test <SHA>` to refresh the mirror). |
| `.github/workflows/workflow-security.yml` | Runs informational Actionlint and High-severity Zizmor reports on GitHub-hosted runners. |
| `.github/workflows/dependency-review.yml` | Reports dependency changes when GitHub Dependency Graph is available; otherwise publishes a neutral warning. |
| `.github/workflows/codeql.yml` | Runs nightly informational CodeQL analysis on `main` for Rust and the Go, Python, and TypeScript SDKs and retains SARIF artifacts. |
| `.github/workflows/codex-security.yml` | Scans the cumulative diff from the previous stable release to each pre-release candidate and publishes train-scoped SARIF on `main`. |
| `.github/workflows/trivy-changes.yml` | Blocks pull requests and merge groups that introduce new High or Critical Helm or Dockerfile misconfigurations. |
| `.github/workflows/trivy-scan.yml` | Reusable scan of published container images and deployment configuration. Findings are informational by default and can be configured to fail the workflow. |

## Release workflows

These workflows run after merge to publish dev/tagged artifacts and verify them. They are not PR-gated.

| File | Role |
|---|---|
| `.github/workflows/release-dev.yml` | Publishes the rolling `dev` build on every push to `main`. Builds gateway/supervisor images and binaries, packages, wheels, and pushes the Helm chart as `oci://ghcr.io/nvidia/openshell/helm-chart:0.0.0-dev` (plus an immutable `0.0.0-dev.<sha>` pin). Also dispatchable manually. |
| `.github/workflows/release-tag.yml` | Publishes a tagged stable release. Its automatic tag trigger excludes `-pre.*`; manual dispatch remains maintainer-controlled. |
| `.github/workflows/release-canary.yml` | Smoke-tests published artifacts on `macos`, `ubuntu`, `fedora`, and `kubernetes` (kind + Helm) runners. Triggers automatically when `Release Dev` succeeds, and via `workflow_dispatch` on any branch (`gh workflow run release-canary.yml --ref <branch>`). The `kubernetes` job pins to `0.0.0-dev` artifacts; the other jobs install the latest tagged release via `install.sh`. See the `test-release-canary` skill for the manual-dispatch playbook and local kind reproduction. |

## Required status contexts

Require these statuses in the branch ruleset for PR and merge-queue CI:

- `OpenShell / Branch Checks`
- `OpenShell / E2E`
- `OpenShell / GPU E2E`
- `OpenShell / Helm Lint`
- `OpenShell / Trivy Changes`

For mirror-based workflows, require the statuses published by
`Required CI Gates`, not their underlying jobs. `OpenShell / Trivy Changes` is
the stable result job of the direct pull-request workflow. Together these
contexts prove the expected checks completed for the commit GitHub is about to
merge.

Do not add the informational Actionlint, Zizmor, Dependency Review, or CodeQL
jobs to the required status list while they remain in observation mode.
