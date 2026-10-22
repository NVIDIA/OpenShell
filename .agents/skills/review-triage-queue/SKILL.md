---
name: review-triage-queue
description: Create a read-only, local triage queue report from OpenShell GitHub intake. Use to review the triage queue, scan incoming issues and community PRs, check main-branch CI failures, or resume a triage pass.
metadata:
  internal: true
---

# Review Triage Queue

Create a decision-focused, local Markdown report. Do not write to GitHub.

## Local state

Use these ignored local paths under `.agents/triage-duty/`:

- Checkpoint: `state.local.yml`
- Reports: `reports/<UTC timestamp>.md`
- Action records: `actions/<UTC timestamp>.md`
- Inbox: `inbox.md`

Record first-run coverage. Update cursors only after a complete report; partial reads must not skip unread items. Search with overlap and deduplicate source items.

Keep the checkpoint minimal: repository, last successful scan, source and backlog cursors, explicit dispositions, and next triage issue. Action records are authoritative; reconcile the checkpoint from them before proceeding. Reports are immutable. Never store credentials, personal data, private reasons, or vulnerability details; never stage duty files.

Read unchecked inbox entries at the start of every review. Treat them as local follow-up prompts, not as independent evidence or authorization for an external action. When an entry materially informs the review, include it in the report's **Local inbox follow-up** section. After the dated report is written, mark that entry complete in the inbox with the report filename. Leave entries unchecked when they were not yet actionable or were not considered.

## Gather intake

Follow [Label Discovery](../../../CONTRIBUTING.md#label-discovery), retrieving all pages of current label definitions. Identify the triage queue by its description. Read all pages of each source:

- All open GitHub issues in the triage queue, ordered by most recently updated.
- Newly opened community issues with **no `state:*` label**; exclude maintainer/core-contributor issues and already-routed work from label recommendations. This includes stale lifecycle labels.
- Older open community issues meeting the same eligibility rule: measure first; audit all when there are at most 20, otherwise inspect the five oldest remaining candidates per run. Use a separate `(created_at, number)` backlog cursor, advanced only after inspection and reporting; wrap at the end. Advancing it must not drop pending recommendations. Age sets ordering only and never justifies closure.
- Open non-draft Dependabot pull requests. Surface these explicitly so they do not age out or go stale while waiting for maintainer attention.
- Newly opened non-draft community pull requests.
- Failed CI runs on `main`.
- Published repository documentation for applicable public answers.

Do not scan GitHub Discussions or a dedicated security-reporting source in v1. Route suspected vulnerabilities through [SECURITY.md](../../../SECURITY.md).

Treat an unlabelled issue as already routed when it has roadmap placement, a milestone, a Project item, or an explicit maintainer comment that assigns, schedules, or otherwise intentionally removes it from triage. Report that signal as context; never recommend adding the triage-queue label to it. If authorship or routing is uncertain, report the uncertainty instead of recommending a label.

## Analyze and rank

Use repository-scoped object IDs: `I<number>` for issues, `P<number>` for PRs, and `C<run_id>` for GitHub Actions runs. Link each ID to its canonical source; attempts share the run ID. PRs are informational in v1.

Detect related signals across sources. Preserve each source as linked provenance. Group similar evidence into one recommendation; do not count a global fixed number of occurrences as the only evidence of repetition.

Recommend work for repeated questions, defects, documentation/support gaps, requested product changes, or likely duplicates. Treat documentation and support improvements as bug-fix or feature work when they address a demonstrated user need.

Classify recommendations as bug, feature, documentation/support improvement, duplicate, intake-gap routing, release blocker, or security finding. The agent may infer a release blocker only with concrete evidence, source links, and confidence. Keep `critical` for security findings and release blockers; use `high`, `normal`, or `low` for all other items. Set confidence to `high`, `medium`, or `low`, and explain uncertainty unless it is high.

Give new and carried pending/deferred recommendations separate five-item budgets. Preserve carried priorities and recheck live sources outside scan windows. Keep excess findings in overflow; only security findings and release blockers may exceed either cap. Never mark recommendations processed merely because they were reviewed; carry pending/deferred items until applied or rejected through `apply-triage-action`.

## Resume an in-progress triage pass

When the on-duty engineer asks for the “next issue” without asking for a new queue review, resume from the latest local report's **Triage queue** order. Select the first item that has not been explicitly dispositioned in local duty state. Do not query live GitHub data to silently reorder an in-progress pass: newly opened or newly updated issues belong in the next queue review. Use `triage-issue` for assessment.

An engineer can explicitly request a refresh or the newest live issue; either request supersedes the continuation order. If the report has no remaining listed candidate, say so and offer a fresh queue review rather than choosing an item from an older overflow list.

## Write the report

Create a dated immutable report using [the report template](references/report-template.md). Use links and short paraphrases only. Record its first listed triage issue as `next_triage_issue` in the checkpoint.
