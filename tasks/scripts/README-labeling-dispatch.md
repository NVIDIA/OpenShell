# Acceptance dispatch and coordination

This is the dormant dispatch layer for [#5412](https://github.com/NVIDIA/OpenShell/issues/5412),
initially based on [#5407](https://github.com/NVIDIA/OpenShell/pull/5407).
It is **not ready for activation**. Rebase onto the PR for
[#5411](https://github.com/NVIDIA/OpenShell/issues/5411), reconcile the runner
interface, and complete the integration steps below before enabling previews.

## Design and boundaries

`labeling-dispatch.yml` selects explicit acceptance labels (including draft PRs),
new authorized human PR commands, and authorized manual workflow dispatches.
Creation/reopening, unrelated labels, and checkpoint bookkeeping do not select
classification. Current permission lookup errors fail the run. The acceptance
writer may dispatch as `github-actions[bot]`; this identity cannot use force.
All selected runs still pass through the shared runner's current eligibility gate.

The proposed #5411 adapter is `labeling_runner.run(repository, number, *, force,
apply) -> report`. Confirm this against the actual runner during rebase. The
runner owns prepare, evidence expansion, deterministic unchanged/ineligible skips,
classification, validation, preview, application, and recovery. This layer must
never duplicate those operations or treat a historical acceptance event as current
authority. Force bypasses only unchanged detection.

A workflow concurrency group alone cannot coordinate direct helper calls on
another host. `labeling_item_lock.item_lock` instead arbitrates ownership through
atomic GitHub ref creation at `refs/labeler-locks/NUMBER`. Each acquisition creates
a unique audit commit based on trusted repository code. All mutation paths must
use this same guard; until they do, cross-entry-point serialization is incomplete.
This is not a new classification checkpoint or a lease. Checkpoints and partial
write reconciliation remain in the shared helper. No external datastore is used.
See the [GitHub refs API](https://docs.github.com/en/rest/git/refs).

Successful execution verifies ownership and removes the ref. Failure, lost
responses, cancellation, or crashes leave it in place. There is no time-based
steal or blind retry. A busy run fails visibly rather than silently dropping a
request. It creates no model session or item writes. Inspect the lock commit and
owner execution, stop that execution, inspect current labels/events and the
runner's partial-write report, and explicitly reconcile before removing the lock.
Only then rerun with fresh preparation. Never delete a lock while its owner may
still execute. Do not enable automatic retry of an uncertain operation.

Successful PR application always calls the existing reviewer reconciler under
the same guard. An unchanged result also calls it, allowing a prior handoff to
be recovered without another classification. The reconciler preserves draft,
closed PR, author, engagement, and manual reviewer protections. A failure retains
the lock and requires the recovery above. Preview and ineligible skips do not
mutate reviewer requests. Routine outcomes never post item comments.

## Required integration on rebase

- Replace the provisional adapter with #5411's real interface and report statuses.
  Preserve the runner's actionable recovery report on errors.
- Guard direct shared-helper classification and assessment application, runner,
  human and triager calls with this same mutex. Avoid nested acquisitions: one
  lock must cover preparation through final writes and reviewer handoff. Callers
  must not have an uncoordinated mutation escape hatch. Update `/label-issue` and
  triager instructions against the actual combined helper.
- In #5260's acceptance writer, call
  `acceptance_written(repository, number, default_branch, api=api)` immediately
  after a successful acceptance-label POST and before any reviewer operations or
  draft return. Grant its workflow `actions: write`. Explicit workflow dispatch
  works with `GITHUB_TOKEN`; its label event does not start a downstream workflow.
  A dispatch failure must surface independently of later routing. When retrying
  a previously successful write, explicitly enqueue again; the fresh runner
  checkpoint determines whether work is needed. Add integration tests at the
  actual writer covering drafts, routing failure and dispatch failure.
- Obtain the human policy for materializing implicit issue acceptance; use the
  shared accepted-work policy and deterministic authority checks. No model may
  decide acceptance. This branch intentionally implements no policy before that
  decision. Add its reviewed materialization path and tests here after approval.
- Register the mutex in the real helper and test separate processes/hosts,
  duplicate delivery, current eligibility loss, uncertain writes and reviewer
  recovery using the actual runner and helper interfaces. The injected tests in
  this branch do not substitute for those integration tests.

## Preview and application rollout

Keep `LABELING_PREVIEW_ENABLED` and `LABELING_APPLICATION_ENABLED` unset initially.
The workflow installs without running. Merging the dormant workflow does not
satisfy the issue's observed end-to-end acceptance criteria.

After dependency wiring and reviewed policy, provision the dedicated CMA
configuration and scoped credentials described in
[the runtime guide](README-labeling-agent.md). Finalize environment variable names
against #5411; never derive configuration or code paths from item text. Give the
configured labeling identity authority for the shared helper and access to the
repository's refs, issues and PRs. Provision canonical labels, routing support,
and the approved checkpoint label from #5151/#5355. Verify custom ref creation,
content permissions, and recovery in a disposable repository first; no live ref
writes have been performed by this branch's offline tests.

Create separate `labeling-preview` and `labeling-application` GitHub environments.
Store `LABELING_ANTHROPIC_API_KEY` in the appropriate environment. Protect the
application environment with required human reviewers and default-branch
restrictions. Enable `LABELING_PREVIEW_ENABLED=true` first, leaving application
unset. Observe human and automation-applied acceptance, drafts, human command and
force, triager, duplicate, missing evidence, and partial-failure paths. Record
run URLs and the reviewed results in the PR before requesting application.

Only after observed previews and explicit human approval, enable
`LABELING_APPLICATION_ENABLED=true`. This switches selected invocations to the
protected application environment. Inspect one-item writes and reviewer handoff
before broad operation. Unset the variable to return to preview; disable the
preview variable to stop dispatch entirely. Neither setting resolves an existing
lock or authorizes replay of uncertain writes.

## Verification

```shell
mise run test:labeling-agent
```

Tests exercise the dispatch boundary with an injected runner and fake GitHub
service. They make no remote writes, model calls, or claims of live integration.
