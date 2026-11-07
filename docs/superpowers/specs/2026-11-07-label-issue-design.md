# Label-issue skill and deterministic helper

Approved working design, updated 2026-11-07. Records the skill-extraction delivery of [OpenShell #5276](https://github.com/NVIDIA/OpenShell/issues/5276), building on [#5260](https://github.com/NVIDIA/OpenShell/pull/5260). Automatic dispatch is a later delivery. This is a working implementation design for the existing issue, not a request to open or number a formal RFC.

## Intent

Reduce maintainer work and label-filtered notification noise by accurately classifying accepted issues and PRs. The first delivery is an observable, manually invocable `/label-issue` skill with a reusable deterministic helper. It corrects inaccurate current classification as well as migrating obsolete associations under [#5151](https://github.com/NVIDIA/OpenShell/issues/5151).

Design for hundreds or thousands of invocations daily. Unchanged eligible items must skip without a model call, and checkpoint lookup/API use must remain efficient at that scale.

Target Terra/Sonnet-level models. Optimize for a functioning observed workflow before tuning for smaller models. The skill provides judgment; code handles mechanical validation and GitHub mutation.

## Agreed behavior

- Accept one issue/PR number or URL in a selected repository. No batch application.
- Classify from title/body, relevant comments, linked-issue context, and, for PRs, changed paths, reviews, and diffs.
- Existing labels describe reconciliation state, not reliable evidence of subject matter. They may be wrong, misspelled, obsolete, or retired.
- Return the complete desired area/topic classification. Issues and PRs both require exactly one primary area: zero or multiple areas are invalid. Topics must be substantively supported, with no arbitrary count cap.
- Migrate legacy and `retired:*` area/topic associations during normal skill invocation, including the observed prototype. Choose replacements from current taxonomy and evidence, using #5151's contextual migration guidance rather than blind substitutions.
- Apply clear changes and make the best-supported choice under ordinary classification ambiguity. Never post a comment to the issue or PR. Retain ambiguity details, including the choice, next-best alternative, and confidence in each, in the local preview/application report for classification tuning. Do not request approval or wait for a human solely because taxonomy classification is ambiguous.
- Preserve unrelated labels and human-owned dispositions. Inaccurate area/topic labels may be corrected regardless of who originally applied them. Acceptance, roadmap placement, and execution state are not classification choices.
- Triage keeps its assessment judgment and passes an explicit assessment outcome to the skill/helper. Intake assessment labels remain possible before acceptance; model-based area/topic classification requires accepted work.
- Preview and observable scenarios precede automatic application. A specifically authorized one-item apply invocation does not require another approval round for each reversible label change.

## Primary area and documentation migration

Issues and PRs both require exactly one primary area. For obsolete `area:docs`, use `topic:documentation` and choose the area from the content. The earlier topics-only issue exception in [#5151](https://github.com/NVIDIA/OpenShell/issues/5151) is mistaken and does not apply. Cross-component work still gets one primary area; ordinary uncertainty follows the preview ambiguity reporting rule below.

## Goals and non-goals

Goals: dependable per-item classification/migration; evidence-based best choices; visible preview; reusable mutation boundary; direct delegation from triage; tests demonstrating both helpful instruction and mechanically safe application.

Non-goals: automatic event dispatch, model-provider orchestration, an external datastore, agent-session scanning, autonomous acceptance/triage/PR review, repository-wide label creation/renaming/deletion, or a backlog sweep.

Anti-goals: anchoring on existing labels; flooding subscribers with unaccepted work; asking humans to resolve routine taxonomy ambiguity; reading indefinitely without a plausible effect on labels; silently treating missing evidence as inspected; mutating human dispositions; passing an untested skill to the later agent.

## Approaches considered

### Complete fixed evidence packet

Collect title/body, all comments, reviews, files, and diff into one model input. This is easy to reproduce but large threads/diffs can bury the useful evidence and consume context unnecessarily.

### Expandable evidence snapshot — selected

Give the classifier a useful compact starting packet and retain additional evidence in addressable artifacts. The model can inspect relevant comments, reviews, or diff sections when that could change classification or distinguish migration alternatives. This was selected with the user because it supports Terra/Sonnet-level judgment without making exhaustive reading the normal path.

Unstructured ad hoc GitHub editing was rejected earlier in favor of including a deterministic helper: the observed skill and the later agent should share the same application boundary.

## Components

### Skill

Add internal contributor skill `.agents/skills/label-issue/SKILL.md`, with discoverable name/description and optional UI metadata matching existing skill conventions. Keep the entrypoint compact; put substantive JSON contracts or conditional migration details in a focused reference only if needed.

The skill explains classification judgment, appropriate evidence expansion, migration obligations, and the preview/apply invocation. It calls the helper rather than rebuilding API calls or mutation logic. It does not carry a static duplicate taxonomy or its own acceptance definition.

### Shared helper

Add a stdlib Python helper under `tasks/scripts/`, importable by future tools and runnable through `uv`. The implementation plan names the focused transport, policy, evidence, checkpoint, and orchestration modules. Reuse the accepted-work library from #5260. If issue acceptance needs a read-only adapter, extend that shared library rather than implementing a second acceptance policy inside the labeler.

The importable boundary in `tasks/scripts/label_issue.py` exposes `prepare`, `preview`, and `apply`; the CLI also exposes `expand` for the evidence module. The [command and result reference](../../../.agents/skills/label-issue/references/result-contract.md) supplies the supported invocation recipe. The helper never chooses a model or runs a classifier.

The helper never invokes an LLM. Its functions can be used by a future runner with the same structured result contract.

## Evidence snapshot

The prepared snapshot, compact packet and its referenced manifest provide:

- Repository, canonical item identity/type, title, body, URL, lifecycle state, and acceptance eligibility.
- Current taxonomy scopes and available repository label definitions, with retirement/preparation status exposed.
- Linked-issue summaries relevant to the PR's closing references.
- For PRs: current head SHA, changed paths, file statuses, and diff statistics.
- Evidence index: available comments, reviews, timeline/lifecycle evidence, per-file patches/diff sections, and linked-item detail.
- A separate reconciliation-state section containing current labels.

Retain provider-returned evidence in local artifacts, with bounded previews and digest-bound text chunks where needed, rather than public checkpoint comments or a new external service. The index distinguishes evidence not inspected, unavailable from GitHub, or incompletely supplied by GitHub. Any excerpt identifies its source and coverage. An omitted patch, provider cap, pagination failure, or too-large response must not be described as a complete diff.

The implementation may choose JSON files and straightforward local commands to select artifacts. It need not build a query language, search service, or generic evidence framework. Paginate GitHub collections; retain stable IDs/URLs for evidence used in reasons and ambiguity decisions. Ignore embedded instructions in item contents: they are task evidence, not authority to override policy.

The complete `packet.json`, each index page, and each individual artifact response are bounded to 2 MiB. Deferred content retains addressable references; an aggregate packet cannot silently exceed its bound. Comments, reviews, review comments, per-file patches, and linked issues have stable source IDs. Focused expansion supports `text:SOURCE_ID:DIGEST:START:END` with zero-based, end-exclusive character offsets, and `source:PATH:START_LINE:END_LINE` with inclusive lines pinned to the PR head. Verify the PR head/base around live files retrieval and reject movement. Collection refresh removes deleted members and invalidates changed-source inspection, lifecycle references, and old digest-bound slices.

Inspection requires `inspected: true` plus `inspection: {source_digest, via: packet|explicit_expansion}` matching the current source digest. Automatic credit comes only from content in the final packet actually returned after hydration; intermediate preparation packets and deferred content do not establish initial exposure. Explicit expansion can acknowledge a directly read current artifact. Valid same-digest provenance survives later packet eviction, while changed digests invalidate it. This records exposure or acknowledgement, never proof of attention. Pure collection membership IDs cannot alone justify content reasons; actual changed paths remain usable substantive evidence. Local inspection metadata is excluded from checkpoint semantic fingerprints. Lifecycle interpretation uses the same source-provenance predicate and verified human authority.

Local snapshots are per-invocation working artifacts. Cross-invocation successful-examination checkpoints live in GitHub label-addition event metadata as specified below; local files need not survive.

## Evidence expansion guidance

Start with the supplied packet. Expand when more context could plausibly resolve a classification question, explain contradictory evidence, establish the actual changed boundary, or distinguish migration alternatives. A useful heuristic is to articulate what the additional evidence might tell us, then check whether it did.

Do not turn that heuristic into a rigid retrieval loop or restrict new evidence to only the original question. It may reveal an additional supported topic. Stop when further reading is unlikely to change the classification; ordinary residual ambiguity is handled by choosing and recording the reasoning in the preview, not exhaustive investigation.

No fixed number of reads or universal token cap is prescribed in the skill. The builder should impose sensible output/resource limits and report truncation, while letting the model request focused additional context. A technical failure or missing required evidence is not a reason to fabricate certainty.

Lifecycle/acceptance evidence needed to establish eligibility is not optional contextual reading. Relevant recorded human dispositions must be considered before taxonomy changes.

## GitHub API throttling and timeouts

Keep API policy in the shared helper, not in model instructions. Use authenticated, serial requests, paginate deliberately, and reuse evidence already in the invocation snapshot. Apply per-request timeouts, a finite retry budget, and an overall invocation deadline; expose conservative defaults in the implementation plan.

Follow [GitHub's REST best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api): honor `Retry-After`; when primary quota is exhausted, wait until `X-RateLimit-Reset`; for a secondary limit without either hint, wait at least one minute and increase subsequent delays. Pace consecutive writes. If the required wait exceeds the invocation deadline, return a retryable result with the earliest retry time instead of sleeping indefinitely. Inspect the response body and headers: a permission-denied 403 is not automatically throttling. Handle GraphQL error payloads as errors even when the HTTP response succeeds, following its [rate-limit guidance](https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api).

Retry transient read timeouts and server failures with bounded exponential backoff and jitter. Surface permanent authentication, authorization, and invalid-request errors promptly. A failed page remains incomplete evidence; failed eligibility checks never become successful skips or permission to mutate.

After a timed-out mutation, its outcome is unknown. Re-read live labels before retrying and reconcile them to desired state. If that verification fails, report the uncertain/partial outcome rather than blindly repeating the write. Preserve completed work in the local report so another invocation can resume through fresh validation.

## Classifier result

Use a versioned structured result bound to the prepared item/snapshot. The logical contents are:

- Complete desired `area` and `topics`; `area` is one non-null canonical area for both issues and PRs.
- Brief reasons with evidence references for selected labels and consequential removals.
- An optional structured ambiguity record containing the ambiguous boundary, chosen label/set, next-best alternative, and confidence in each.
- If needed, evidence-backed lifecycle interpretation for recorded human closure/disposition statements that cannot be decided from mechanical GitHub fields alone.

Choose the requested outcome, affected OpenShell boundary, and substantive technical concerns before assigning topics. Routine implementation or verification alone adds no topic; substantive testing work retains its testing topic.

The result contains desired classification, not arbitrary GitHub commands. The helper derives label additions/removals. Use the following example as the skill’s output template. The command/result reference defines validation details and the restricting-only lifecycle extension; do not introduce fields with no consumer.

Use high/medium/low confidence rather than unsupported numerical precision. High-confidence choices do not require ambiguity records. No confidence level causes a ticket comment. Medium- and low-confidence choices include the next-best alternative in the ambiguity record. Render confidence as `high conf`, `med conf`, or `low conf` in the preview report. The choice must be the best-supported option; equal qualitative confidence levels are allowed when that vocabulary cannot express the finer distinction. The helper formats the structured record consistently in the preview/application report; it has no comment-posting operation.

### Output template

The skill must show and follow this structured shape, replacing sample values with the prepared snapshot identity and evidence references. This is an illustrative PR, not a classification of an existing ticket. `body` and `patch:proxy-policy` stand for IDs actually supplied in that snapshot's evidence index.

```json
{
  "schema_version": 1,
  "repository": "NVIDIA/OpenShell",
  "number": 1234,
  "kind": "pull_request",
  "snapshot_id": "example-snapshot-id",
  "area": "area:runtime",
  "topics": ["topic:networking", "topic:policy"],
  "reasons": [
    {
      "labels": ["area:runtime", "topic:networking", "topic:policy"],
      "evidence": ["body", "patch:proxy-policy"],
      "reason": "The change modifies sandbox proxy policy enforcement."
    }
  ],
  "ambiguity": null
}
```

Existing `area:gateway` or `retired:topic:l7` associations belong to reconciliation state; they do not establish that desired result. For a consequential removal not explained by the selected-label reasons, add a reason referencing the observed association and content evidence. The helper derives the actual additions/removals from the complete desired set.

When a choice has medium or low confidence, replace `null` with this shape (illustrating a separate CLI-versus-contributor-tooling boundary):

```json
{
  "boundary": "CLI interaction versus contributor tooling",
  "chosen": {"labels": ["topic:ux"], "confidence": "medium"},
  "alternative": {"labels": ["topic:dx"], "confidence": "low"},
  "evidence": ["body"]
}
```

The chosen labels must appear in the desired classification. The helper renders the ambiguity information only in the local report, for example:

> Ambiguity: chose `topic:ux` (med conf) over `topic:dx` (low conf)

The invocation report also provides a short human-readable result:

```text
NVIDIA/OpenShell#1234 — preview
Add: area:runtime, topic:networking, topic:policy
Remove: area:gateway, retired:topic:l7
Preserve: state:accepted
Ambiguity: none
```

Report actual observed differences, not this example's fixed labels. Application uses the same layout with an applied, no-op, held, partial, or error outcome and any outstanding work. Neither this report nor its ambiguity information is posted to the ticket. Ambiguity informs tuning and is not an additional approval gate or a reason by itself to skip the best-supported choice.

## Eligibility and lifecycle boundaries

Use the canonical accepted-work definition and shared PR checker. For issues, recorded acceptance or implicit maintainer/write-access authorship follows the same shared contribution policy; model assertions alone cannot establish acceptance.

Enforce #5151's exclusions: merged PRs stay unchanged, including reverted merges; issues closed as completed or resolved through a merged closing PR stay unchanged; recorded author abandonment/displacement/closure intent and maintainer rejection are preserved. Deliberate maintainer not_planned/duplicate closure is resolution without requiring a comment. Stale-bot closure alone is not resolution. Author-only and unclear closures retain the review treatment required by #5151.

Code enforces observable mechanical exclusions. The skill interprets actual recorded human statements when semantic interpretation is required and cites them; it does not invent a new disposition. The helper must verify referenced evidence and relevant actor authority where its application depends on that interpretation. A lifecycle hold is distinct from ordinary classification ambiguity and cannot be bypassed through an ambiguity record or confidence score. Optional `result.lifecycle` has `disposition: hold|excluded`, evidence IDs, and a reason; it can only restrict eligibility. Bot statements cannot establish human intent. Verified stale closure recognizes the maintained literal automation protocol, including the current `github-actions[bot]` actor, current closure-event provenance, and latest unedited close comment within the bounded 60-second window; unrelated bot closures remain held.

For accepted or unaccepted work, explicit assessment-only preparation can apply a separately supplied, authorized triage assessment outcome while leaving area/topic classification unchanged. The model is not asked to classify subject matter through this path. Eligibility lookup failures surface as errors rather than as unaccepted/skipped success.

## Validation and label application

Validate before any mutation:

- The result belongs to this repository, item, and snapshot.
- Desired labels exist in both the active canonical taxonomy and live repository label definitions. Preview can display a desired classification together with its missing prerequisites, but application is blocked until those prerequisites are satisfied. Do not create a label or silently replace it with an obsolete label.
- Exactly one area is supplied for both issues and PRs, labels are unique, retired names are never desired output, and language-specific SDK topics retain their broad SDK subscription topic once those topics are prepared and supported by routing.
- Removals cover obsolete and inaccurate classification associations while preserving unrelated labels. For malformed names outside recognizable classification namespaces, require membership in the trusted prepared malformed-candidate allowlist plus observed association and substantive evidence. Automatic candidates use only a one-edit namespace error, including adjacent transposition, with an exact canonical suffix; classifier output cannot nominate unrelated labels for deletion.
- An optional caller-supplied triage assessment only changes the reviewed assessment subset. It cannot grant acceptance, change roadmap/ownership/execution decisions, or arise merely from the classifier's area/topic output.

Immediately before apply, refresh eligibility, relevant item/evidence facts, taxonomy/definitions, and labels. Preparation rechecks the eligibility in its refreshed snapshot before requesting classification. Assessment-only decisions also bind prepared substantive facts and are rejected when body, discussion, or other relevant material changes. If the decision's inputs materially changed, return a stale-preview result and require a fresh classification/preview rather than applying a decision to unseen evidence. Snapshot identity is not permission: always re-read live acceptance and lifecycle facts.

Prefer targeted label operations that preserve unrelated concurrent changes. Add supported replacements before removing obsolete associations so a failed addition does not strip the old classification. Report partial failures accurately and make retry converge through the same desired-state calculation; never post a ticket comment or mark a failed operation as successful.

Preview exposes `ordered_writes` and the exact batched `mutation_request`. Callers with existing confirmation rules pass the saved confirmed report through `expected_preview` / `--expected-preview`; changed regenerated payloads return stale before writes. Ordinary authorized label-issue invocation can omit that binding.

The executor defaults to the authenticated `GET /user` identity. For tokens without that endpoint, `executor` / `--executor` is separately trusted caller configuration, never classifier or snapshot authority. Apply requires configured trusted-actor membership, and actual event actor/transcript verification must match before completion. A configured identity does not grant token permissions.

Label operations are not an atomic transaction. If some additions/removals succeed and others fail, report partial completion and reconcile live labels idempotently on retry. Local invocation artifacts may retain that result for the caller, but cross-invocation recovery must use live state and event metadata. Comment creation and comment retry/deduplication are outside this helper entirely.

GitHub's label timeline supplies the label-change audit. The caller receives a compact preview/application report, including skipped/held/error status, additions/removals, missing prerequisites, and any ambiguity sentence. A classification no-op is explicit in that report; a newly completed examination may still require the checkpoint bookkeeping events described below. An unchanged-item preflight skip causes no writes. All outcomes are silent on the ticket apart from GitHub’s native label timeline entries.

## Persistent checkpoints in label-addition event metadata

Include checkpoints in the first shared-helper delivery. Existing authorized experiments recorded in [#5276](https://github.com/NVIDIA/OpenShell/issues/5276) verified the metadata mechanism; validation of this implementation requires no repeated live label experiment.

Use GraphQL `addLabelsToLabelable` with `labels: [{labelId, rationale}]` on the last real addition. Retrieve metadata through `LabeledEvent.intent.rationale`, including events whose labels are no longer attached. Use REST `node_id` values as GraphQL label and item IDs, never numeric REST IDs. Re-adding an attached label does not produce a new event or replace old intent metadata.

### V2 completion proof

New checkpoint writes require `encode_checkpoint(fingerprint, *, boundary_id, operations_digest, event_count)` and always emit v2:

```text
openshell-labeler:v2:<material-sha256>:<base64url-boundary-id>:<operations-sha256>:<event-count>
```

An empty-history boundary uses `-` only after a complete query establishes no prior label event. Enforce the 280-character limit without truncating fields. V1 metadata remains decode-only for audit and cannot authorize an unchanged skip.

The fingerprint binds prepared source facts, intended final labels, trusted taxonomy/definitions and policy. Bind the explicit helper/classification/migration `POLICY_VERSION` together with the trusted document-content policy hash; unrelated repository commits are not policy changes. Fetched source digests detect edited/deleted or concurrent evidence independently of model inspection. Required comments and PR files/reviews/review-comments must have complete collection membership and source coverage. A hash is not a claim that a model read every source. Incomplete, missing, stale, or unresolved source facts cannot prove completion.

Material includes title/body, PR head/base/changed paths/diffs, linked-issue and authority facts, comments/reviews, and lifecycle events. Fetch filtered CLOSED/REOPENED events and bind their complete source digest instead of downloading the full unfiltered timeline on every invocation. Do not use blanket `updatedAt` as a change detector. Normalize current classification labels to the intended final set; exclude local paths, inspection metadata, and verified derivative excerpts from semantic fingerprints. Retain actual external label and lifecycle events.

The prepared immutable boundary is the latest observed LabeledEvent or UnlabeledEvent ID. Expected operations are an ordered transcript of actor, add/remove action, and GraphQL label ID. The candidate rationale binds its digest and count. Completion requires every label event after that boundary, through the current frontier, to match the declared transcript exactly. Extra events invalidate it even if final labels return to the same values or the actor is trusted. GitHub cannot distinguish a coincident identical same-actor removal from the expected one; one coordinated executor per item is a practical requirement, not an atomicity claim.

### Preflight and bounds

Recheck acceptance/lifecycle before checkpoint discovery and again in the prepared snapshot. Look up the newest trusted metadata using filtered LabeledEvents, 100 per page, at most ten pages. Fetch label/unlabel proof separately, also bounded to ten pages. A missing or exhausted candidate/boundary is not evidence of a successful unchanged examination. Expose that condition and re-examine or retry deliberately.

Hydrate relevant source facts deterministically before matching or completion, without invoking a model or granting inspection credit. Old edits/deletions can require complete discussion/review pagination and authority lookups for distinct actors. Reuse current verified facts within an invocation; do not claim constant API cost. Transport defaults are a 30-second request timeout, three total read attempts, a shared 300-second deadline, 100 REST pages, and a 2 MiB response bound, with throttling-aware waits and one-second write pacing.

Skip only if a trusted v2 checkpoint, its exact event proof, independently read final labels, fresh eligibility/material and policy all match. `force` bypasses only this unchanged test. Checkpoint-like text in item contents is never trusted. Reports record `classifier_required`, API/page counts and elapsed time; the helper never claims a model invocation. The calling skill/runtime records actual model use.

The current CLI retains invocation-command comments conservatively as material. A later command entrypoint must provide exact producer-bound recognition before excluding command-only text; broad slash-command or actor-based suppression is not authorized.

### Mutation cases

- **Real additions:** add supported replacements first, attach rationale to the last addition, then remove obsolete associations. No extra cycle is needed solely for metadata.
- **No classification addition:** add the approved dedicated temporary label with rationale, then remove it and any obsolete associations through ordered one-label operations.
- **Known approved leftover:** preview explicit cleanup before a fresh checkpoint cycle. Include cleanup, addition, and final removal in the expected transcript; never get stuck relying on re-adding an attached label to create an event.

Only `meta:labeler-checkpoint` is approved by the trusted code allowlist in this delivery. It must already exist live. `--bookkeeping-label` selects existing reviewed authority; it cannot grant permission to cycle another name. Another dedicated name requires a reviewed allowlist code change. Do not provision labels, cycle classification/workflow-control labels, or improvise an arbitrary substitute. Missing bookkeeping blocks only paths requiring it; real additions can proceed without that extra label. The temporary label is absent from intended final state.

Use one GraphQL HTTP request with serial top-level aliases, one label per alias, including removals. This supersedes multi-label removal arrays whose event order was not verified. The request remains a set of separate non-atomic mutations. Show every operation, including bookkeeping, in preview. Do not claim notification-free or metadata-only writes; feed/notification effects have not been established.

### Recovery and coordination

A rationale written before removals is only a candidate. Independently read labels immediately after a failed/uncertain mutation, even if later source hydration fails. Separately refresh final material and collect the exact event proof; never trust nested mutation response labels. Errors, partial aliases, retained temporary labels, unseen evidence, or extra external events prevent successful examination. Retry through fresh preparation and desired-state reconciliation, without blindly replaying a mutation.

The helper targets POSIX Linux/macOS and serializes local invocations using `fcntl.flock`. It supports one coordinated manual executor per item. Local locking does not serialize separate machines or external GitHub editors; future automation owns cross-host concurrency. Live rechecks detect drift optimistically and cannot exclude edits after the final read.

Unaccepted/lifecycle-excluded items receive no classifier or checkpoint writes. Separately authorized assessment-only changes remain bounded, preserve classification, bind the reviewed substantive facts, and verify actual operation actors/order without creating checkpoint metadata. This delivery authorizes neither backlog application nor repository-wide label preparation and does not bypass [#5151](https://github.com/NVIDIA/OpenShell/issues/5151) routing prerequisites.

## Triage integration

Update `triage-issue` so assessment decisions remain there and label reconciliation is delegated directly to `/label-issue`. Update other triage entry points only where they currently own label mutation or need an explicit delegation; preserve the read-only guarantee of `review-triage-queue`.

Existing confirmation requirements in `apply-triage-action` remain scoped to that workflow; this extraction does not loosen them or add those prompts to every ordinary authorized label-issue invocation. Do not introduce acceptance decisions into the labeler to make delegation convenient.

Update CONTRIBUTING.md's skill inventory and relevant workflow guidance, plus sync-agent-infra's maintenance map. No acceptance-trigger workflow or managed-agent runtime is added in this PR.

## Testing and observed validation

Use Superpowers writing-skills' baseline-first process. Before authoring the skill or editing triage instructions, run realistic scenarios without the proposed guidance and preserve observed outputs/failures. Then write the minimal guidance needed and rerun equivalent scenarios with it. For behavior-shaping wording, include control samples and enough repetitions to distinguish improvement from one lucky result.

Test both premature classification and unproductive evidence expansion. Include ambiguous boundaries, comments/diffs that change the answer, misleading current labels, migration mappings that require context, unrelated labels to preserve, and lifecycle exclusions. Observe preview ambiguity information and whether the model makes a choice instead of routinely asking a human. Verify that neither the skill nor the helper posts ticket comments, regardless of confidence or outcome; this does not change comments owned by the separate triage workflow.

Write failing behavioral tests before implementing helper features. Cover pure classification-result validation, live prerequisite checks, acceptance/lifecycle errors, assessment boundaries, stale snapshots, pagination/completeness, malformed/legacy associations, unrelated concurrent labels, idempotent application, partial failures, and preview ambiguity formatting and the absence of comment mutations for all confidence levels and outcomes. Cover checkpoint encoding/size, trusted event discovery including removed labels, model-free unchanged skips and efficient lookup over large histories, real-addition/no-change/removal-only paths, unchanged skips, forced examination, policy/input changes, bookkeeping normalization, unavailable bookkeeping labels, concurrent invocations, partial mutations, and fresh final-state verification. Include throttling headers, secondary-limit responses, retry/deadline exhaustion, read and write timeouts, GraphQL error payloads, incomplete pagination, and verification before retrying uncertain writes. Use an injected clock/sleeper so retry tests do not wait in real time. GitHub test doubles replace network/mutations; no live labels need change to validate the helper.

Validate skill frontmatter/discovery and links, and run scoped repository checks appropriate to contributor tooling. Obtain observed previews on representative real items without applying backlog changes. Do not claim an eval program or full model-tier validation from unit tests alone.

## Later agent entry points

The later automated delivery invokes the same skill/helper on `state:accepted`, including explicit dispatch for acceptance written with `GITHUB_TOKEN`. Also retain an authorized human PR-comment command analogous to `/ok to test`, plus a force variant. Exact command spelling belongs to that delivery's design. Normal command invocation uses unchanged-item detection; force bypasses only that detection, never acceptance, lifecycle exclusions, validation, or actor authorization. Triagers retain direct invocation through the same boundary.

A comment command is an explicit invocation entry point, not permission to classify on every comment. The later entrypoint must recognize exact invocation-command text and verify protocol-owned bookkeeping events before suppressing them as changes. Until that command protocol exists, this CLI retains command comments conservatively. The labeler posts no response or ambiguity comments; the invoking workflow exposes results through its execution report. Creation and reopening alone do not dispatch classification. Terra/Sonnet remains the first target.

## Delivery boundary and review status

The focused modules, artifact layout, CLI flags, v2 codec, approved bookkeeping label, POSIX lock and inspection provenance above record the approved implementation contracts. The [implementation plan](../plans/2026-11-07-label-issue.md) covers the task boundaries and validation requirements; the [command/result reference](../../../.agents/skills/label-issue/references/result-contract.md) is the executable usage contract.

Automatic acceptance dispatch, the `GITHUB_TOKEN` explicit-dispatch path, authorized comment commands, cross-host runner concurrency, provider/runtime integration, and broader quality/model-tier evaluation remain later work. This design is not a formal RFC and authorizes no live backlog label application. Draft-PR validation must report unavailable checks and observed model limits instead of treating the planning checklist as proof of completion.
