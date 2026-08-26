# Triage Duty Playbook — Working Draft

**Duty period:** 2026-08-19 to 2026-09-01  
**Owner:**  
**Status:** Discovery

## Goal

Define a semi-automated, agent-assisted triage practice that reliably identifies incoming work, preserves human judgment for consequential public actions, and can be handed to the next duty owner without losing context.

## Outcomes to Produce

- [ ] Reuse or update the per-issue `triage-issue` SKILL.
- [x] Create the read-only `review-triage-queue` SKILL.
- [x] Create the user-gated `apply-triage-action` SKILL.
- [ ] Define and exercise the queue-review workflow.
- [ ] Keep a local-only checkpoint log for the queue-review workflow.
- [ ] Design the shared daily workflow and handover process after queue processing is proven.

## Decisions to Make

### 1. Work-item scope

**Question:** What sources count as triage-duty work?

- [x] GitHub issues with `state:triage-needed`
- [x] Newly opened GitHub issues without `state:triage-needed` (reporting-process gap lane)
- [x] Newly opened community pull requests
- [x] CI failures on `main`
- [ ] GitHub Discussions (out of scope for v1; current activity is primarily vouch requests)
- [ ] Security reports (out of scope for v1)
- [ ] Support channels
- [x] Internal/customer Slack questions — [channel C0AE9P50JVA](https://nvidia.enterprise.slack.com/archives/C0AE9P50JVA)
- [x] Team-internal Slack design/engineering context — [channel C0AR6QP0CKH](https://nvidia.enterprise.slack.com/archives/C0AR6QP0CKH)
- [ ] Other:

**Decision:** Include the named internal/customer Slack channel as a monitored intake source, use the team-internal design/engineering Slack channel as supporting evidence, and report newly opened GitHub issues without `state:triage-needed` as a separate intake-gap category.  
**Rationale:** Internal users and customers ask questions in the first channel; unresolved questions may reveal support work, bugs, documentation gaps, or feature requests. The design/engineering channel supplies decisions and constraints relevant to candidate work items, but is not itself a direct-question queue. Unlabelled new issues identify gaps in the current reporting and routing process without forcing ad-hoc triage outside the normal queue.

**Unlabelled-issue rule:** The queue review lists newly opened, unlabelled issues separately. The agent may recommend adding `state:triage-needed` when an issue is open, substantive, lacks a triage marker, and is not an obvious duplicate, spam, security disclosure, or already-routed roadmap item. Treat roadmap/accepted labels, milestones, Project membership, and explicit maintainer assignment/scheduling comments as routing signals. Issues created by maintainers or core contributors are also excluded because they may intentionally bypass the label. The on-duty engineer decides whether to apply the label so that an eligible community issue enters the standard triage queue on a subsequent run.

**Pull requests and CI:** List newly opened community pull requests and failed CI runs on `main` as queue inputs. The agent may infer and recommend a release-blocker classification for relevant CI failures, subject to the evidence and confidence requirements. Add a configurable long-lived-branch pattern after the first Stable release.

**Slack intake rule:** Use a pull-based review: the on-duty engineer manually invokes the queue-review skill. Do not send an immediate alert for every new message. Review new messages and threads for unresolved, actionable asks. An agent may recommend that a thread merits a work item when it indicates a repeated question, a general defect, a documentation gap, a support-process gap, or a requested product change. Treat documentation and support improvements as bug-fix or feature work, not as a separate, lower-priority class. The on-duty engineer must agree before any concrete work item is created or routed. Do not post customer-facing replies automatically.

**Resolved-thread evidence:** Treat active or unanswered Slack threads as candidate queue entries. Consult resolved threads only while investigating a candidate for related evidence, within the prior 30 days. Do not list resolved threads as new queue items; identify their dates and links when they materially support a recommendation.

### 2. Agent authority

**Question:** Which actions can an agent take without a human approval step?

| Action | Autonomous | Requires approval | Notes |
|---|---|---|---|
| Read/search/assemble queue | Yes |  |  |
| Diagnose and recommend classification | Yes |  | Read-only recommendation |
| Add or remove labels |  | Yes | Includes adding `state:triage-needed` to an unlabelled issue |
| Draft public comments | Yes |  | Draft only; include in report or apply preview |
| Post public comments |  | Yes | Only for explicitly selected recommendation IDs |
| Create GitHub issues |  | Yes | Only for explicitly selected recommendation IDs |
| Close duplicates or user-error reports |  | Yes | Only for explicitly selected recommendation IDs |

**Guardrails:**

### 3. Service level and cadence

**Question:** What daily cadence and response targets should the duty owner meet?

| Activity | Proposed cadence/target | Decision |
|---|---|---|
| Queue scan | On-duty engineer invokes manually; include GitHub intake and monitored Slack-channel questions/comments |  |
| First acknowledgement |  |  |
| Triage completion |  |  |
| Escalations |  |  |
| End-of-day log update |  |  |

### 4. System of record

**Question:** Where will the durable duty log live?

- [ ] GitHub Project
- [ ] Checked-in Markdown document
- [ ] Dedicated GitHub issue or Discussion
- [ ] Other:

**Decision:** Deferred. For the initial queue-processing iteration, use a local-only checkpoint log.  
**Required properties (when revisited):** readable by the incoming owner, easy to update, links to source items, records owner and next action.

### Local queue checkpoint (initial iteration)

Store local state in an ignored file, for example `architecture/plans/triage-duty-state.local.yml`. Keep only source cursors and the time of the last successful scan. Read the checkpoint at the start of each run, search with an overlap window, deduplicate results, and update it only after the run completes successfully.

### Triage-duty inbox (initial iteration)

Capture ad-hoc process ideas and follow-up prompts in the ignored local file
`architecture/plans/triage-duty-inbox.md`. At the start of every queue review,
read its unchecked entries as prompts for the review; they are not evidence or
authorization to take an external action. When an entry materially informs the
review, list it in the dated report's **Local inbox follow-up** section with its
outcome and any resulting recommendation ID or finding. Once that report is
written, mark the inbox entry complete with the report filename. Leave entries
unchecked when they were not yet actionable or were not considered.

**First-run baselines:** For Slack candidate activity, start at the beginning of the most recent two-week triage period. For GitHub, include all open issues already labeled `state:triage-needed` regardless of age. Define a separate backlog-discovery process for older unlabelled GitHub issues rather than treating them as newly opened intake gaps.

**Older unlabelled GitHub backlog:** Measure and report the count before processing historical issues. If there are 20 or fewer, perform a one-time baseline audit. If there are more than 20, inspect the five oldest open unlabelled issues per recurring sweep; do not silently begin an unbounded historical scan. Apply the same eligibility rule as for new unlabelled issues: substantive, no triage marker, not an obvious duplicate/spam/security disclosure, and not maintainer/core-contributor authored. Age determines review order only; it never changes handling and is never sufficient evidence to recommend closure.

### Queue-review output (initial iteration)

Write each manual queue review to a dated, immutable local Markdown report under `architecture/plans/triage-duty-reports/`, for example `2026-08-19T093000Z.md`. Start with a short, priority-ranked **Needs your decision** section when the volume warrants it, then provide the supporting findings. Each recommendation includes a concise concrete proposed action, rationale, linked evidence, applicable public-documentation links, and its approval requirement. Do not include full issue bodies or lengthy Slack replies in this report; generate the exact action payload only in the application skill's preview for selected IDs. The report also lists queue entries, intake-gap candidates, and Slack questions/comments.

Include a **Local inbox follow-up** section containing only inbox entries that
materially informed that review. For each, record the outcome and any resulting
recommendation ID or finding; do not duplicate the full inbox.

**Attention-budget rule:** Group duplicate/similar evidence into one recurring signal, rank actionable recommendations above informational findings, and summarize low-priority material. Show at most five decision-worthy recommendations per review. Preserve all discovered items in an appendix or a clearly identified deferred section; do not silently discard items solely to reduce report length. A high-severity item may appear even when the budget is otherwise full.

**Recommendation schema:** Every recommendation in **Needs your decision** contains:

| Field | Purpose |
|---|---|
| ID | Report-local ID, such as `R-01` |
| Priority | `critical`, `high`, `normal`, or `low`; original priority retained while deferred |
| Classification | Bug, feature, documentation/support improvement, duplicate, intake-gap routing, release blocker, or security finding |
| Proposed action | Concise concrete action the engineer may apply, reject, or defer |
| Confidence | `high`, `medium`, or `low`; include an uncertainty note unless `high` |
| Evidence | Linked source items and a short explanation of the cross-source match or observed behavior |
| Documentation | Applicable public documentation links, or an explicit “none found” |
| Current disposition | Pending, applied, rejected, or deferred; include the engineer's reason when applicable |

Include report metadata: generation time, duty-period start, source/checkpoint coverage, and any scan limitations.

Reserve `critical` for security findings and release blockers. Other recommendations may be `high`, `normal`, or `low` only.

**Data minimization:** Keep reports local and ignored. Store source links and minimal paraphrased evidence only; do not copy Slack message bodies, credentials, personal data, or other sensitive material into reports. Never commit queue reports or checkpoint state.

**Decision persistence:** A recommendation-worthy item retains its original priority and remains pending until the on-duty engineer explicitly chooses one of these dispositions:

- **Apply:** execute the approved external action and record the outcome.
- **Reject:** terminal local decision; do not recommend again unless new material evidence changes the case.
- **Defer:** non-terminal decision; carry the item into the next report's decision section with the engineer's reason.

Do not mark an item as processed merely because the agent reviewed it. Historical backlog progression uses these explicit local dispositions to avoid both repeated investigation and silent loss of work. Defer has no delayed/snoozed state in v1.

**Decision backpressure:** Deferred and otherwise pending recommendations count toward the five-item decision budget. If five pending items exist, continue scanning and record newly found work, but do not add further ordinary recommendations to **Needs your decision** until the engineer resolves an existing item. Only a security finding or release blocker may appear as an explicit exception to the cap. The agent may infer a release blocker, but must state the concrete evidence, source links, and confidence in the report. Handle security findings through the project's private reporting process, never by creating a public GitHub issue.

**Supported recommended actions (initial iteration):** queue a community issue for triage by recommending `state:triage-needed`; create a new GitHub issue; provide or draft a concise explanatory Slack support reply, including applicable public documentation when available; flag an existing issue as a likely duplicate. Longer-than-link-only Slack replies are allowed only through the per-action preview and confirmation gate.

**Documented Slack questions:** When a new Slack question has a clear applicable public-docs answer and no stronger recurring/defect signal, recommend replying in its thread with the direct documentation link and a concise explanation. This remains an individually previewed and confirmed Slack action.

**Existing triage queue:** List all open issues labeled `state:triage-needed` in a dedicated **Triage queue** section of the queue-review report, regardless of age, ordered by most recent update. State the total queue count and the number not listed. Show up to five items in this section and preserve the remaining items in an overflow list. For every shown item, include its number, title, last-update time, and a concise summary of current context plus material comments or changes since the prior queue review. This section does not consume the five-item **Needs your decision** budget. Do not perform full assessment in queue review; the on-duty engineer invokes the existing `triage-issue` skill separately for a selected issue.

**Community pull requests:** List newly opened community pull requests in a dedicated **Community pull requests** section. Show up to five items, with any additional items in overflow. Include the PR number, title, author, current check status, and link. Do not recommend or perform PR actions in v1.

**CI failures:** Treat failed CI runs on `main` as general findings in the ordinary queue-review and recommendation flow; do not create a dedicated CI section. Promote only inferred release blockers as `critical` exceptions.

**User-gated application:** Use two skills. The read-only queue-review skill assigns report-local IDs (for example, `R-01` through `R-05`) in its dated report; IDs do not need to be globally unique. The action-application skill accepts exactly one ID from the most recent queue-review report per invocation; natural-language approval without an ID is insufficient. Before writing, that skill re-reads the target, verifies it has not materially changed, and previews the exact external write. It performs no write until the engineer gives an explicit second confirmation for that individual action. Revalidate and record the outcome in a companion dated action report.

**Revalidation failure:** Record a harmless no-op when the action is already completed or would have no effect. Stop and request renewed approval when a material change would make an action unsafe or substantially different from the recommendation.

**Disposition recording:** Use the action-application skill to record one disposition for one ID from the most recent report per invocation. For **reject** or **defer**, the engineer supplies the recommendation ID and a reason; the skill appends the no-write decision to the action report. For **apply**, it follows the per-action preview and confirmation workflow before making the external write.

### 5. Handover threshold

**Question:** Which conditions require explicit handover rather than ordinary queue processing?

- [ ] Awaiting reporter information
- [ ] Needs maintainer/product judgment
- [ ] Reproduction or investigation in progress
- [ ] Security-sensitive or private handling
- [ ] Blocked by external dependency
- [ ] Other:

**Decision:**

### 6. `state:needs-info` lifecycle

**Open question:** How should issues in `state:needs-info` remain visible, be
followed up, and return to active triage without relying on the current duty
owner's memory?

- [ ] Decide whether the triage-duty queue review lists all `state:needs-info`
      issues, only recently updated issues, or only issues with new reporter
      activity.
- [ ] Define what event returns an issue to `state:triage-needed` or otherwise
      prompts reassessment, including whether an agent may recommend that
      transition after detecting a substantive reply.
- [ ] Assign responsibility for monitoring replies and establish any reminder,
      follow-up, or inactivity cadence.
- [ ] Define what the outgoing owner records for each unresolved issue: the
      information requested, date requested, current owner, latest response,
      and next action.
- [ ] Decide how issues with no response are handled; elapsed time alone must
      not be treated as evidence that the issue is invalid or should be closed.

**Decision:** Open; resolve while designing the shared daily workflow and
handover process.

## Initial Design Hypothesis

- Retain `triage-issue` as the per-issue assessment and routing procedure.
- Add automation only for discovery, deduplication hints, queue summaries, and drafts until trust is earned.
- Require human approval for public comments and closing issues during the initial rollout.
- First validate queue processing with a local checkpoint; defer shared logging and handover design.

## Open Questions / Notes

_Capture answers, examples, and edge cases here as we work through them._

- Consider scheduled invocation only after the manual workflow has been exercised and calibrated.
- Classify recurring signals by the corrective change needed: bug fix, feature, documentation, or support tooling. Documentation and support work qualify as bug-fix or feature work when they resolve a demonstrated user need.
- Detect repetition across intake sources. A Slack question may match GitHub issues, prior Slack threads, documentation gaps, or other signals; the originating source remains provenance, not a boundary for evidence. Search the team-internal design/engineering Slack channel for related decisions that affect a candidate work item's behavior, and search published repository documentation for an applicable public answer. Include a direct documentation link when it resolves or helps answer the question. Every recommendation must link the matching evidence and identify its source.
- Define a backlog-discovery workflow for older unlabelled GitHub issues.

## Next Session

Define the shared daily workflow and handover process after exercising the local queue workflow.

## Proposed Skill Contracts

### `review-triage-queue`

**Purpose:** Read-only intake review. Collect the configured GitHub, Slack, documentation, and local-checkpoint context; identify cross-source signals; and write the dated queue-review report.

**Example invocation:** `Review triage queue.`

**Inputs:** No item ID. On an initial run without a checkpoint, ask the engineer for the duty-period start date, store it locally, and use it as the Slack baseline. Do not infer the date from the calendar.

**Writes:** Local checkpoint and a dated immutable report only. Never writes to GitHub or Slack.

### `apply-triage-action`

**Purpose:** Record one explicit disposition for one recommendation from the most recent queue-review report; make one external write only after preview and per-action confirmation.

**Example invocations:**

- `Apply triage action R-01.`
- `Reject triage action R-02 because it duplicates the team roadmap.`
- `Defer triage action R-03 because we need the release decision first.`

**Inputs:** Exactly one report-local recommendation ID. `reject` and `defer` require a reason. `apply` revalidates the target, previews the exact external write, then requires a second explicit confirmation.

**Writes:** Append a local action record for every disposition. For an approved `apply`, perform only the revalidated external write associated with that ID.
