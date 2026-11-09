# Label-Issue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract an observed `/label-issue` classifier and shared deterministic reconciliation helper, including legacy migration and persistent label-event checkpoints.

**Architecture:** The skill judges substantive evidence and produces a desired classification. Focused Python modules collect expandable evidence, enforce policy, validate output, and apply labels/checkpoints. Triage delegates label writes while retaining assessment judgment; automatic agent dispatch is a later delivery.

**Tech Stack:** Python 3.11+, stdlib, `uv`, GitHub CLI, GitHub REST/GraphQL, `unittest`, Markdown contributor skills.

**Spec:** [Approved design](../specs/2026-11-07-label-issue-design.md). Read it before this plan. These durable contributor design/plan records are not a formal RFC or published product documentation. The checklists retain implementation and validation requirements; final PR validation reports observed outcomes and unavailable tools rather than treating every checkbox as an attestation.

## Global Constraints

- Issues and PRs both require exactly one primary area: zero or multiple areas are invalid.
- Existing labels describe reconciliation state, not reliable evidence of subject matter.
- Never post a comment to the issue or PR. Ambiguity stays in preview/application reports.
- Reuse the shared accepted-work library from #5260; it remains read-only.
- Area/topic classification requires accepted work; separately authorized assessment updates may precede acceptance.
- Migrate obsolete and `retired:*` associations contextually under #5151; preserve unrelated labels and human dispositions.
- Target Terra/Sonnet-level models; hundreds or thousands of invocations daily require deterministic, model-free unchanged skips.
- Checkpoints use label-addition event rationale, at most 280 characters, with no external datastore or session-history dependency.
- `force` bypasses unchanged detection only, never acceptance, lifecycle exclusions, or validation.
- No automatic dispatch, backlog writes, repository-wide label provisioning, or new provider runtime in this delivery.
- Use Conventional Commits with `--signoff`; push only to `purp/OpenShell`.

## Review Focus

1. Edited/deleted old comments and externally cycled labels can invalidate a checkpoint even when recent item contents look unchanged: Task 5 must test this.
2. A GraphQL HTTP-200 response can contain errors or partially successful aliases: Tasks 2 and 6 must test recovery and separate final reads.
3. A malformed label can resemble a human workflow label: Task 3 must test evidenced removals without fuzzy deletion.
4. A provider-omitted patch or truncated thread can hide a second relevant topic: Tasks 1 and 4 must test honest coverage and targeted expansion.
5. Concurrent evidence changes after checkpoint creation must not be recorded as examined: Tasks 5 and 6 must test stale/partial outcomes.

## File map

Create these focused modules and matching `*_test.py` files in `tasks/scripts/`:

- `label_issue_github.py`: bounded authenticated transport, headers, retries, pagination, telemetry.
- `label_issue_policy.py`: taxonomy scopes, result validation, desired-state diff, lifecycle decisions, report formatting.
- `label_issue_evidence.py`: item identity, eligibility adapters, evidence manifest/artifacts, refresh and fingerprints.
- `label_issue_checkpoint.py`: compact rationale codec, trusted event discovery, checkpoint validation and mutation sequencing.
- `label_issue.py`: importable orchestration and preview-first CLI; no model invocation.

Extend `accepted_work.py` and its tests for the shared issue adapter. Add `.agents/skills/label-issue/SKILL.md` and `references/result-contract.md`. Modify `triage-issue`, applicable label-write paths in `apply-triage-action`, the maintenance map in `sync-agent-infra`, and CONTRIBUTING.md. Inspect `review-triage-queue`; retain its read-only contract and change it only if a preview delegation is useful. Do not modify review-readiness routing or introduce #5151's pending taxonomy changes.

Use JSON-compatible dictionaries at module boundaries and validate them. Avoid a parallel class hierarchy. Snapshot and result envelopes use `schema_version`, `repository`, `number`, `kind`, and `snapshot_id` as in the spec; reports have `status`, `add`, `remove`, `preserve`, `bookkeeping`, `ambiguity`, `missing_prerequisites`, `diagnostics`.

## Contract index

- [Design: evidence and coverage](../specs/2026-11-07-label-issue-design.md#evidence-snapshot), [eligibility](../specs/2026-11-07-label-issue-design.md#eligibility-and-lifecycle-boundaries), and checkpoint/mutation sections own implementation constraints.
- [Command/result reference](../../../.agents/skills/label-issue/references/result-contract.md) owns CLI payloads, executor/confirmation binding, assessment-only usage, bookkeeping and recovery.
- [Skill](../../../.agents/skills/label-issue/SKILL.md) owns classification judgment. Detailed tests and interfaces follow below; unavailable validation tools must be reported honestly.

## Task 1: Establish classification and triage baselines

**Files:** Create scenario inputs and baseline transcripts in a local validation directory outside the source tree; no skill edits yet.

**Interfaces:** Consumes approved spec and existing triage instructions. Produces numbered scenario packets, expected outcomes, verbatim model outputs, and a scored failure list for Task 7.

- [ ] Read writing-skills' `references/testing-skills-with-subagents.md` and `references/discovery.md`, plus TDD's `writing-good-tests.md` before authoring scenarios or tests.
- [ ] Create cases for misleading legacy labels; valid-but-inaccurate labels; missing topics revealed by a comment/diff; runtime/platform ambiguity; unaccepted intake with an authorized assessment; merged/resolved exclusions; incomplete evidence; and a large discussion inviting unnecessary reading. Include instruction injection in evidence and a triage caller tempted to edit labels directly.
- [ ] Run fresh-context Terra samples without the new skill, using only realistic current guidance and taxonomy. No live mutations. Record exact output and rationale, including whether evidence was expanded, labels chosen, comments proposed, and escalation requested.
- [ ] Run at least five control repetitions for each behavior-shaping scenario selected for wording experiments. Manually inspect every flagged result. If controls already succeed, do not invent corrective prose for that behavior.
- [ ] Preserve failures and expected classifications with evidence references. Skill authorship must wait for these observations; mechanical policy requirements still belong in code.

## Task 2: Build bounded GitHub transport

**Files:** Create `label_issue_github.py`, `label_issue_github_test.py`.

**Interfaces:** `GitHubClient.request(path: str, *, method: str = "GET", data: dict | None = None) -> object`; `GitHubClient.pages(path: str) -> list`; `GitHubClient.diagnostics -> dict`. Inject subprocess runner, monotonic clock, wall clock, sleeper, and jitter for offline tests. Provide an adapter compatible with the existing acceptance API callable, including `pages=True` and `CalledProcessError` 404 semantics.

- [ ] Write failing tests for paginated evidence, invalid/repeated cursors, malformed payloads, 403 permission versus throttling, 429/Retry-After, primary reset, secondary-limit delay, GraphQL errors, exhausted retries, and timeout after a mutation.
- [ ] Run `UV_PYTHON=/usr/bin/python3 uv run --no-project python -m unittest discover -s tasks/scripts -p 'label_issue_github_test.py'`; verify each new behavior fails before its implementation.
- [ ] Implement serial `gh api` requests with response headers and explicit pagination; do not hide retries in an unbounded subprocess. Defaults: 30-second request timeout, three total attempts per read, 300-second invocation deadline, exponential delays starting at one second plus bounded jitter, at least 60 seconds for secondary throttling without hints, and at least one second between consecutive HTTP write requests. This interval does not apply between serial aliases inside one GraphQL request. Rate-limit headers take precedence over generic backoff. Return retryable status and earliest retry time when the deadline cannot accommodate the wait.
- [ ] Surface uncertain writes to orchestration rather than retrying them blindly. Test that sleeps and retries respect the shared deadline and perform no real waiting in tests.
- [ ] Run the transport suite to green, then commit with `git commit --signoff -m "feat(labels): add bounded GitHub transport"`.

## Task 3: Validate classification and compute safe differences

**Files:** Create `label_issue_policy.py`, `label_issue_policy_test.py`.

**Interfaces:** `load_taxonomy(markdown: str, definitions: list[dict]) -> dict`; `validate_result(snapshot: dict, result: dict) -> dict`; `plan_labels(snapshot: dict, result: dict, *, assessment: dict | None = None) -> dict`; `format_report(report: dict) -> str`.

- [ ] Write failing tests asserting that `area=None`, zero/multiple area output, duplicate topics, retired output, wrong snapshot/item identity, unsupported evidence references, and arbitrary result commands are rejected. Test missing live/canonical labels as preview prerequisites that block apply.
- [ ] Add cases for `area:docs` to content-derived area plus documentation, contextual compatibility/L7 mappings, nested SDK topic plus broad subscription topic, malformed evidenced removals, and unrelated human workflow labels. Assert `preserve` includes unrelated labels and no acceptance/roadmap/execution write is generated.
- [ ] Add output assertions: `Ambiguity: chose topic:ux (med conf) over topic:dx (low conf)` in the local report; no comment mutation for any confidence. Test an authorized assessment changes only the caller-declared reviewed assessment subset, including preacceptance.
- [ ] Run the new suite, watch failures, then implement the four interfaces. Parse current roster headings/scopes without embedding a duplicate taxonomy; recognize nested heading names but block labels absent from prepared canonical/live definitions. Keep #5151 contextual mappings in one focused policy source rather than duplicating them in skill prose.
- [ ] Run to green and commit with `git commit --signoff -m "feat(labels): validate classification and plan reconciliation"`.

## Task 4: Prepare expandable evidence and shared eligibility

**Files:** Create `label_issue_evidence.py`, `label_issue_evidence_test.py`; modify `accepted_work.py`, `accepted_work_test.py`.

**Interfaces:** `check_issue_accepted_work(repository: str, issue: dict, maintainers: set[str], *, api) -> bool` in the shared acceptance module. Evidence module exposes `preflight(repository: str, number: int, *, api, force: bool = False) -> dict`, `prepare_snapshot(repository: str, number: int, directory: Path, *, api, assessment_labels=frozenset()) -> dict`, `expand_evidence(snapshot: dict, evidence_ids: list[str], *, api) -> dict`, and `material_state(snapshot: dict) -> dict`.

- [ ] Write failing issue-adapter tests for recorded acceptance, maintainer/write authorship, read-only/unaccepted authors, paginated labels, and propagated lookup errors; preserve existing PR semantics.
- [ ] Write failing snapshot tests for URL/number normalization, linked closing-issue facts, current head/changed paths, artifact IDs, coverage flags, omitted/provider-truncated patches, comments/reviews, and trusted merged policy inputs. Assert existing labels are separated from substantive evidence.
- [ ] Add lifecycle cases: merged/reverted PR, completed issue, merged closing PR, deliberate maintainer not-planned closure, stale-bot closure, and recorded author abandonment. Human-statement interpretation cites actual evidence; unresolved author-only closure remains a hold. No unsupported semantic model assertion grants eligibility.
- [ ] Run failing tests, implement adapters and snapshot/expansion interfaces, then rerun. Read merged MAINTAINERS/REVIEWERS and policy versions from a pinned trusted revision, not PR-controlled files. Persist coverage and inspected IDs honestly. Maximum artifact response: 2 MiB, reported as truncated rather than complete; focus expansion can request smaller source slices. No universal model-token or read-count cap.
- [ ] Commit with `git commit --signoff -m "feat(labels): prepare expandable evidence and issue eligibility"`.

## Task 5: Encode and discover persistent checkpoints

**Files:** Create `label_issue_checkpoint.py`, `label_issue_checkpoint_test.py`; extend evidence tests.

**Interfaces:** `fingerprint(material: dict, final_labels: set[str], policy_version: str) -> str`; `encode_checkpoint(fingerprint: str, *, boundary_id: str, operations_digest: str, event_count: int) -> str`; `decode_checkpoint(rationale: str) -> dict | None`; `find_checkpoint(item_id: str, *, api, trusted_actors: set[str]) -> dict`; `checkpoint_matches(checkpoint: dict, material: dict, final_labels: set[str], policy_version: str, *, label_events: dict | None = None) -> bool`. `latest_label_event`, `collect_label_events`, and `operation_digest` provide the prepared boundary and exact ordered event proof.

- [ ] Write failing tests for deterministic canonical JSON/SHA-256, versioned round trips, 280-character limit, missing/invalid/untrusted metadata, and events for labels subsequently removed. New writes use `openshell-labeler:v2:<material-sha256>:<base64url-boundary-id>:<operations-sha256>:<event-count>` with all proof arguments required. V1 remains decode-only audit metadata and cannot prove unchanged. Bind the explicit helper/classification/migration `POLICY_VERSION`, trusted document-policy hash, and intended final labels.
- [ ] Test newest-first filtered LabeledEvent lookup, 100 events/page, ten-page lookup bound, correct pagination, and explicit exhausted/not-found outcomes. Never interpret a bounded search miss as unchanged success.
- [ ] Test unchanged versus edited/deleted old comment, changed review/diff, policy/label-definition changes, external label remove/re-add, ordinary command-looking comments, and protocol-owned bookkeeping. Suppress only verified protocol-owned events, not every event by the same actor. Fingerprint complete fetched source facts without claiming model inspection. Any relevant unseen change or incomplete source coverage invalidates the candidate; local inspection flags are excluded from semantic fingerprints. Provider reactions/profile metadata and label colors are semantic no-ops; content, edits, identities, authority and taxonomy changes invalidate freshness. Raw artifact bounds still apply.
- [ ] Run failing tests, implement codec/discovery/matching, then rerun. Preflight verifies fresh acceptance/lifecycle each time. Discovery precedes expensive evidence retrieval; collect only required changes, but do not claim a constant-cost skip if correctness requires pagination. Record counts and durations.
- [ ] Commit with `git commit --signoff -m "feat(labels): persist trusted examination checkpoints"`.

## Task 6: Apply labels and checkpoints through one boundary

**Files:** Create `label_issue.py`, `label_issue_test.py`; extend checkpoint module/tests.

**Interfaces:** `prepare(repository, number, directory, *, api, force=False, trusted_actors, assessment_only=False, assessment_labels=frozenset()) -> dict`; `preview(snapshot, result, *, api, assessment=None, bookkeeping_label=DEFAULT_BOOKKEEPING_LABEL, executor=None) -> dict`; `apply(snapshot, result, *, api, trusted_actors, bookkeeping_label=DEFAULT_BOOKKEEPING_LABEL, assessment=None, expected_preview=None, executor=None) -> dict`. The default approved bookkeeping name is `meta:labeler-checkpoint`; see the [command/result reference](../../../.agents/skills/label-issue/references/result-contract.md).

- [ ] Write failing tests asserting an unchanged preflight never calls a classifier or writes; force re-examines but cannot bypass exclusions; stale inputs block apply; uncertainty and technical failure never produce successful examination.
- [ ] Test real additions attaching rationale to the last addition; removal-only bookkeeping addition followed by removal; no-change examination bookkeeping cycle; and missing bookkeeping-label prerequisites. The default and only trusted code-approved name is `meta:labeler-checkpoint`. `--bookkeeping-label` cannot grant authority for arbitrary cycling or cleanup; alternate names require reviewed allowlist changes. Missing live definitions block only paths requiring bookkeeping. Detect approved temporary leftovers independently of cycle selection and never authorize unchanged while one remains attached. Do not provision labels. Test recovery from a known approved leftover with explicit cleanup/cycle operations.
- [ ] Test partial GraphQL alias success, timed-out writes followed by fresh label reads, additions before removals, final read differing from nested mutation response, concurrent external labels, and unseen evidence arriving after checkpoint creation. Assert no candidate checkpoint is trusted before independent final labels, material and exact event transcript match. Use one-label serial top-level GraphQL aliases per phase; independently verify live replacements, exact event prefix and material before sending removals. Never assume event order inside label arrays. Never mutate comments; read comments as evidence through the shared read-only interfaces.
- [ ] Run failing tests; implement orchestration and CLI subcommands `prepare`, `expand`, `preview`, `apply`. Accept `--repo`, `--item`, `--snapshot`, `--result`, `--output`, `--force`, repeated `--trusted-actor`, `--bookkeeping-label`, `--executor`, and `--expected-preview` where relevant. Assessment-only uses `--assessment-only`, separately reviewed `--assessment-policy`, and `--assessment`. Use exit 0 for ready/preview/applied/no-op/unchanged/skipped, 2 for held/prerequisite/stale, 1 for error/partial. Reports distinguish each outcome and show bookkeeping operations separately.
- [ ] Serialize local per-item mutation with an OS advisory lock and re-read after acquisition. Test lock contention. Document that this cannot serialize separate machines: this delivery supports one coordinated manual executor per item, uses optimistic live rechecks, and reports concurrent drift; the later runner must enforce cross-machine per-item concurrency. Do not claim atomicity or silently build a GitHub lock branch/service.
- [ ] Run the combined labeler and acceptance suites to green and commit with `git commit --signoff -m "feat(labels): reconcile item labels with checkpoint recovery"`.

## Task 7: Write and validate the skill, then delegate triage

**Files:** Create `.agents/skills/label-issue/SKILL.md`, `references/result-contract.md`; modify `.agents/skills/triage-issue/SKILL.md`, `.agents/skills/apply-triage-action/SKILL.md` where label actions occur, `.agents/skills/sync-agent-infra/SKILL.md`, CONTRIBUTING.md.

**Interfaces:** Skill consumes helper snapshot/artifacts, writes the spec's result JSON, and uses the Task 6 CLI. Triage supplies an explicit reviewed assessment subset/outcome; it retains its own evidence/request comments and human-disposition rules.

- [ ] Convert Task 1's observed failures into minimal guidance using the appropriate recipe, required output field, or conditional instruction. No new skill text before the baseline. Read bulletproofing guidance only for observed discipline failures.
- [ ] Write compact frontmatter: `name: label-issue`, description beginning `Use when...` with issue/PR classification, incorrect labels, and legacy migration triggers, plus `metadata.internal: true`. Explain classification from content, focused expansion, one area, supported topics, migration, and preview/apply. Link the single authoritative output example and actual commands through their interpreters.
- [ ] Run five fresh Terra samples per shaping variant with the full skill, alongside the no-guidance control; inspect all results manually. Then run full realistic scenarios with the skill, preserve transcripts, compare classifications/evidence/latency, and refactor only observed failures. Observe targeted context expansion and low-confidence choices without comments or routine human escalation. Report that this validates Terra samples, not Sonnet or Luna generally.
- [ ] Before editing each existing skill, run the relevant baseline delegation scenario. Then have `triage-issue` call `/label-issue` directly for label reconciliation while retaining triage judgment/commenting. Preserve per-write confirmations in `apply-triage-action`; show bookkeeping as part of its exact payload. Keep `review-triage-queue` read-only.
- [ ] Rerun those delegation scenarios with edits. Confirm no competing taxonomy instructions or direct ad hoc label writes remain in changed paths.
- [ ] Update contributor inventory/labeling guidance and the maintenance map, including exactly one area for both accepted issues and PRs. Fix related stale acceptance guidance to reference the existing canonical policy rather than inventing a new exception. Check discovery, local links, frontmatter limits, one good example, quick reference, common mistakes, and absence of narrative eval transcripts in skill prose. Use a flowchart only if the observed workflow needs one.
- [ ] Complete writing-skills' RED/GREEN/REFACTOR/quality checklist in the validation record; mark irrelevant items with reasons. Commit with `git commit --signoff -m "feat(skills): extract shared issue and PR labeling"`.

## Task 8: Verify the branch and prepare the extraction PR

**Files:** Completed implementation, validation record in a local validation directory outside the source tree, PR description.

- [ ] Run `UV_PYTHON=/usr/bin/python3 uv run --no-project python -m unittest discover -s tasks/scripts -p '*_test.py'`. Report every failure by name; resolve failures caused by the change. Run changed Python through Ruff check/format and changed Markdown through repository Markdown lint when available; report tool/environment limits accurately.
- [ ] Run `git diff --check` and scoped syntax, frontmatter, links, inventory, and sync-agent-infra consistency checks. Do not run Rust or SDK suites for isolated contributor-tooling changes. Run the existing JavaScript issue-acceptance tests if shared acceptance behavior or related guidance changed.
- [ ] Obtain read-only real-item previews covering representative classifications and legacy migration without applying live labels. Record API/page counts, model-free skip evidence from offline tests, missing taxonomy/bookkeeping prerequisites, and actual observed model limitations. Preview must never create checkpoints.
- [ ] Review against every approved requirement, especially comments, cardinality, metadata protocol, concurrent drift, hidden incomplete evidence, and triage authorization. Resolve findings and repeat only affected checks.
- [ ] Verify current target-repository permission and issue acceptance using create-github-pr; do not alter #5260. Push only this branch to `purp`. If #5260 remains unmerged and its base is a cross-repository fork branch unavailable upstream, target upstream main with an explicit dependency and parent-to-child compare link; never create or push an upstream branch to imitate a base. Otherwise target the available appropriate base or current main after a non-destructive update. Do not force-push.
- [ ] Open a draft PR with `gh` through create-github-pr. Close the focused extraction issue #5353 and reference Part 2 of #5276 without closing the multi-part tracker. Explain behavior, observed validation, practical concurrency/notification limits, and missing prerequisites. Attach the PR to the task with `codex_app.attach_artifact`.

## Later delivery boundaries

The agent delivery owns acceptance-event dispatch, the `GITHUB_TOKEN` explicit-dispatch path, the authorized PR-comment command analogous to `/ok to test` and its force variant, cross-machine runner concurrency, and Claude Managed Agents configuration. Creation/reopening are not independent triggers. Evals and Luna/Haiku tuning remain subsequent work.

## Self-review

Coverage: Tasks 1/7 own observed skill validation; 2 owns API resilience; 3 owns output/cardinality/migration/assessment boundaries; 4 owns evidence and lifecycle; 5/6 own repeat invocation, scale, checkpoint protocol and recovery; 7 owns triage/discovery/docs; 8 owns verification and reviewable delivery. Interface names and dictionary contracts above are shared across tasks. The five Review Focus cases each have an explicit test task. This retained plan states requirements; draft-PR validation records implementation/check outcomes separately. No live backlog mutation is needed for validation.
