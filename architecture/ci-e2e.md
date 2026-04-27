# E2E CI Architecture

This document describes the architecture of the E2E CI flow: every workflow involved, the trigger each one listens on, why those triggers were chosen, and how the pieces fit together. For the contributor-facing how-to (labels, signing, fork flow), see [CI.md](../CI.md).

## Goals and constraints

Three independent goals shape the design:

1. **Self-hosted runner safety.** E2E runs on `build-arm64` and on GPU runners. Standard `pull_request`-triggered workflows would let any PR author execute code on those hosts. GitHub's recommended pattern for self-hosted CI is "never trigger workflows directly from `pull_request`", and we follow it via copy-pr-bot mirroring to `pull-request/<N>` branches.
2. **Label as a hard merge gate.** When a PR carries `test:e2e` (or `test:e2e-gpu`), the corresponding suite *must* have actually executed and passed for the PR head SHA. The label has to be enforcing, not advisory: it blocks merge unless the suite ran with the label set.
3. **Per-job least privilege on the GitHub token.** Each workflow declares `permissions: {}` at the top, and each job declares only what it needs. This follows the hardening pattern described at <https://astral.sh/blog/open-source-security-at-astral>.

These three goals do not compose cleanly: the safety goal forces `push: pull-request/<N>` triggers (which the PR author can't influence), but `push` triggers don't fire on label changes, so the label gate has to come from a separate workflow on a different trigger. That is the heart of the architecture.

## Pieces at a glance

| File | Trigger | Role |
|---|---|---|
| `.github/copy-pr-bot.yaml` | (config) | Tells copy-pr-bot to mirror trusted PRs into `pull-request/<N>` branches. Pre-existed. |
| `.github/workflows/branch-e2e.yml` | `push: pull-request/[0-9]+` + `workflow_dispatch` | Runs non-GPU E2E on `build-arm64`. |
| `.github/workflows/test-gpu.yml` | `push: pull-request/[0-9]+` + `workflow_dispatch` | Runs GPU E2E on self-hosted GPU runners. |
| `.github/actions/pr-gate/action.yml` | (composite) | Resolves PR metadata for a `pull-request/<N>` push and decides whether the run should proceed. Used by the two workflows above. |
| `.github/workflows/e2e-gate.yml` | `pull_request` + `workflow_run` | Posts the required `E2E Gate` check on the PR. Re-evaluates after the gated workflow completes. |
| `.github/workflows/e2e-gate-check.yml` | `workflow_call` | Reusable gate logic shared by E2E and GPU E2E. |
| `.github/workflows/e2e-label-dispatch.yml` | `pull_request_target: [labeled]` | Dispatches the gated workflow when a `test:e2e*` label is applied after the mirror already exists. |
| `.github/workflows/e2e-test.yml`, `e2e-gpu-test.yaml`, `docker-build.yml` | `workflow_call` | Reusable worker workflows. Unchanged by this design - called from the gated workflows and from release workflows. |

## Trigger taxonomy

Five GitHub Actions trigger types appear in this flow. Each one was chosen for a specific reason - they are not interchangeable.

| Trigger | Workflow context | Token scope | Why we use it here |
|---|---|---|---|
| `push: pull-request/[0-9]+` | The pushed commit (mirror branch) | Repo-default | Only fires for branches copy-pr-bot created. Decouples test execution from PR author actions: the author cannot create a `pull-request/<N>` branch themselves. |
| `pull_request` | The PR head SHA, but actions checkout the *base* branch's workflow files | Read-only for forks | Lets us post a status check on the PR's head SHA (so branch protection sees it). Used by the `E2E Gate` evaluation jobs. |
| `pull_request_target` | Base branch | Write-capable, even for forks | Needed for the label dispatcher: a forked PR's `GITHUB_TOKEN` is read-only on `pull_request`, so it cannot dispatch workflows or post comments. The dispatcher never checks out PR code, so the `pull_request_target` foot-gun does not apply. |
| `workflow_run` | Default branch | Repo-default | Fires when the gated workflow finishes. Lets us run a re-evaluation step in a trusted (default-branch) context. |
| `workflow_dispatch` | Caller's ref | Repo-default | Maintainer escape hatch and the mechanism the label dispatcher uses to call the gated workflow (`gh workflow run --ref pull-request/<N>`). |

The non-obvious move here is that the same logical "did E2E pass for this PR" check has to be posted from at least two of these trigger contexts: a `pull_request`-triggered run (which can attach a check to the PR head SHA) and a `workflow_run`-triggered run (which knows the gated workflow finished but can only attach checks to `main`). The flow stitches them together by re-running the original `pull_request`-triggered run after the gated workflow completes.

## Happy-path flow (trusted PR with label set up-front)

```mermaid
sequenceDiagram
    autonumber
    participant Author as PR Author (org member)
    participant GH as GitHub
    participant Bot as copy-pr-bot
    participant BranchE2E as Branch E2E Checks<br/>(self-hosted)
    participant Gate as E2E Gate<br/>(github-hosted)
    participant Dispatcher as E2E Label Dispatch<br/>(github-hosted)
    participant Maintainer

    Author->>GH: Open PR (signed commits)
    GH->>Bot: PR opened
    Bot->>GH: push pull-request/N (mirror)
    GH->>BranchE2E: push event on pull-request/N
    BranchE2E->>BranchE2E: pr_metadata: should_run = false<br/>(no label yet)
    BranchE2E-->>GH: workflow concludes success<br/>(only metadata job ran)

    GH->>Gate: pull_request opened
    Gate->>Gate: no label, gate passes (no-op)

    Maintainer->>GH: apply test:e2e label
    GH->>Gate: pull_request labeled
    Gate->>Gate: label set,<br/>upstream only ran metadata<br/>→ FAIL (red)
    GH->>Dispatcher: pull_request_target labeled
    Dispatcher->>GH: gh workflow run branch-e2e.yml<br/>--ref pull-request/N
    GH->>BranchE2E: workflow_dispatch
    BranchE2E->>BranchE2E: pr_metadata: should_run = true<br/>(label set, SHA matches)
    BranchE2E->>BranchE2E: build + e2e jobs run

    BranchE2E-->>GH: workflow concludes success
    GH->>Gate: workflow_run completed
    Gate->>GH: rerun original pull_request gate run
    GH->>Gate: pull_request rerun (replays event)
    Gate->>Gate: label set,<br/>upstream success + non-gate jobs ran<br/>→ PASS (green)
```

The key moment is step 11: the dispatcher closes the loop that the `push` trigger doesn't. Without it, applying the label leaves the gate stuck red until a maintainer manually re-runs the gated workflow.

## Forked PR flow

The shape is identical but with two extra round trips: the maintainer has to vet each commit before copy-pr-bot will mirror it.

```mermaid
sequenceDiagram
    autonumber
    participant Author as PR Author (fork)
    participant GH as GitHub
    participant Bot as copy-pr-bot
    participant Maintainer

    Author->>GH: Open PR from fork
    GH->>Bot: PR opened
    Bot->>Bot: not trusted, wait
    Maintainer->>GH: comment "/ok to test <SHA>"
    Bot->>GH: push pull-request/N
    Note over Bot,GH: From here, identical to the trusted flow:<br/>label → dispatcher → gated workflow → rerun gate
    Author->>GH: push new commit
    Bot->>Bot: still untrusted, wait again
    Maintainer->>GH: comment "/ok to test <new-SHA>"
```

## Why each design choice exists

### Why `push` on `pull-request/<N>` instead of `pull_request`

`pull_request` workflows execute the workflow file from the PR's own branch. On a self-hosted runner, that means an attacker can rewrite our workflow YAML and run anything. `push: pull-request/<N>` only fires for branches that copy-pr-bot creates, so the workflow file source is always one that the bot vetted (signed commit + trusted author, or `/ok to test`).

### Why the gate has to verify a non-gate job actually ran

The gated workflows always start with a `pr_metadata` job. When the label is missing, `pr_metadata` reports `should_run=false` and the build/E2E jobs are skipped. From GitHub's perspective the workflow concluded `success`. If the gate only checked top-level conclusion, an unlabeled run from earlier would satisfy the gate forever - the label could be added without ever causing E2E to actually execute. The gate's "at least one non-gate job succeeded" check (`e2e-gate-check.yml:106-110`) is what forces a re-run after labeling.

### Why `workflow_run` is needed for the gate flip

Once the label dispatcher kicks off `branch-e2e.yml`, the workflow runs and finishes - but the `pull_request`-triggered gate check posted earlier still says "fail". `workflow_run` is the only event that fires when an arbitrary other workflow completes, and it's how we know to re-evaluate the gate. But `workflow_run` runs in the *default branch context*, so a check posted from there lands on `main` instead of the PR. Workaround: instead of posting a new check, look up the most recent `pull_request`-triggered gate run for the same head SHA and call `POST /actions/runs/<id>/rerun`. The re-run replays the original `pull_request` event, so the new check posts against the PR's head SHA and branch protection picks it up.

### Why `pull_request_target` for the label dispatcher

A `pull_request` workflow on a forked PR receives a read-only `GITHUB_TOKEN`. That's intentional: it prevents PR-supplied workflow code from escalating. But our dispatcher doesn't *run* PR code - it never checks out the PR head, only the workflow file from `main`. It needs `actions: write` to dispatch the gated workflow and `pull-requests: write` to post a status comment. `pull_request_target` provides a write-capable token while still loading the workflow definition from `main`. The standard `pull_request_target` warning ("don't check out PR code with this token") doesn't apply here because we don't check out anything.

### Why labels and not comment commands

Labels persist as PR metadata and survive re-runs and force-pushes. Comment-based commands like `/ok to test` don't survive the same way: a comment from yesterday doesn't enable today's commit. Branch protection rules can require a check be present; they cannot require a comment. The label is the merge gate's primary signal because it is the only thing GitHub's branch protection knows how to look at.

### Why a separate `E2E Label Dispatch` workflow instead of dispatching from the gate

The gate runs on `pull_request`. If we tried to dispatch the gated workflow from the gate, the dispatch call would fail on forked PRs because the gate's token is read-only. Splitting the dispatcher into its own `pull_request_target` workflow gives it the write-capable token without giving it to the gate evaluation logic.

## Permission posture

Every workflow declares `permissions: {}` at the top. Per-job grants are the minimum needed:

| Workflow | Job | Grants |
|---|---|---|
| `branch-e2e.yml`, `test-gpu.yml` | `pr_metadata` | `contents: read`, `pull-requests: read` |
| | `build-*` | `contents: read`, `packages: write` |
| | `e2e*` | `contents: read`, `packages: read` |
| `e2e-gate.yml` | `e2e`, `gpu` (`workflow_call`) | inherits via the called workflow |
| | `rerun-on-completion` | `actions: write` |
| `e2e-gate-check.yml` | `check` | `contents: read`, `pull-requests: read`, `actions: read` |
| `e2e-label-dispatch.yml` | `dispatch` | `actions: write`, `pull-requests: write` |

The reusable worker workflows (`e2e-test.yml`, `e2e-gpu-test.yaml`, `docker-build.yml`) declare their own internal permissions; the calling job grants are an upper bound for them.

Two workflows hold "interesting" tokens:

- `rerun-on-completion` in `e2e-gate.yml` has `actions: write`. It calls one specific endpoint - `POST /actions/runs/<id>/rerun` for an `e2e-gate.yml` run on the same head SHA - and never executes PR code.
- `dispatch` in `e2e-label-dispatch.yml` has `actions: write` + `pull-requests: write`. It calls `gh workflow run` against `branch-e2e.yml` or `test-gpu.yml` (only) and posts a comment on the PR. It never executes PR code.

Both are small, github-hosted workflows whose source lives only on `main`.

## Release flow

`release-tag.yml` and `release-dev.yml` call `e2e-test.yml` directly on `main` / tag pushes. Tags and `main` are inherently trusted refs, so they bypass copy-pr-bot. E2E still blocks the release jobs (`tag-ghcr-release: needs: [..., e2e]`).

Permissions on the release workflows are not yet scoped per-job. Tracked separately.

## Edge cases

| Case | What happens |
|---|---|
| Label applied before copy-pr-bot mirrors the PR | Dispatcher detects no `pull-request/<N>` branch and posts a comment telling the maintainer to wait or run `/ok to test <SHA>`. |
| Label applied while mirror is stale (new commit pending `/ok to test`) | Dispatcher detects mirror SHA != PR head SHA and posts the corresponding comment with the SHA the maintainer needs to vet. |
| Label removed | No dispatcher reaction. The next PR event (push, label, etc.) re-evaluates the gate, which now sees no label and passes as a no-op. |
| Author force-pushes after label set | copy-pr-bot re-mirrors the new SHA → gated workflow fires on `push` → finishes → `workflow_run` fires the gate re-run → new green check on the new SHA. No re-labeling needed. |
| Maintainer re-runs the gated workflow manually from the Actions UI | Same as above without the force-push. |
| Gate's first evaluation fails (label set, upstream not yet started) | Email-on-failure noise. The check eventually flips to success once upstream finishes and `workflow_run` re-runs the gate. Tracked as a known rough edge; possible fix is posting `neutral` until the upstream completes. |

## References

- copy-pr-bot: <https://github.com/apps/copy-pr-bot>
- Astral hardening guidance: <https://astral.sh/blog/open-source-security-at-astral>
- GitHub Actions security pattern for self-hosted runners: <https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions>
- `pull_request_target` foot-gun: <https://securitylab.github.com/research/github-actions-preventing-pwn-requests/>
- Contributor-facing flow doc: [../CI.md](../CI.md)
