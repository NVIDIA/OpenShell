---
name: review-triage-queue
description: Create a read-only, local triage queue report from OpenShell GitHub and Slack intake. Use when the on-duty engineer asks to review the triage queue, scan incoming work, inspect new community PRs, check main-branch CI failures, or summarize the configured Slack channels. Never use to post, label, close, or otherwise mutate GitHub or Slack.
---

# Review Triage Queue

Create a decision-focused, local Markdown report. Do not write to GitHub or Slack.

## Local state

Use these ignored local paths:

- Checkpoint: `architecture/plans/triage-duty-state.local.yml`
- Reports: `architecture/plans/triage-duty-reports/<UTC timestamp>.md`
- Inbox: `architecture/plans/triage-duty-inbox.md`

On the first run, ask for the triage-duty start date and store it. Do not infer it. Use that date as the initial Slack baseline. Update source cursors only after the report is complete. Search with an overlap window and deduplicate source items.

Keep the checkpoint minimal: duty-period start, last successful scan, source cursors, and explicit local dispositions. Never store copied Slack content, credentials, or personal data.

Read unchecked inbox entries at the start of every review. Treat them as local
follow-up prompts, not as independent evidence or authorization for an external
action. When an entry materially informs the review, include it in the report's
**Local inbox follow-up** section. After the dated report is written, mark that
entry complete in the inbox with the report filename. Leave entries unchecked
when they were not yet actionable or were not considered.

## Gather intake

Use these sources:

- All open GitHub issues labeled `state:triage-needed`, ordered by most recently updated.
- Newly opened community issues without that label; exclude maintainer/core-contributor issues and already-routed work from label recommendations.
- Older open, unlabelled community issues: measure first; audit all when there are at most 20, otherwise inspect the five oldest unresolved candidates per run. Age sets ordering only and never justifies closure.
- Open non-draft Dependabot pull requests. Surface these explicitly so they do
  not age out or go stale while waiting for maintainer attention.
- Newly opened non-draft community pull requests.
- Failed CI runs on `main`.
- Unresolved/actionable questions in Slack channel `C0AE9P50JVA`.
- Related engineering/design context in Slack channel `C0AR6QP0CKH`.
- Published repository documentation for applicable public answers.

Do not scan GitHub Discussions or a dedicated security-reporting source in v1. Do not treat the design/engineering Slack channel as a direct-question queue. Consult resolved Slack threads only as evidence for a candidate, within the prior 30 days.

Treat an unlabelled issue as already routed when it has a roadmap/accepted label, a milestone, a Project item, or an explicit maintainer comment that assigns, schedules, or otherwise intentionally removes it from triage. Report that signal as context; never recommend adding `state:triage-needed` to it.

## Analyze and rank

Detect related signals across sources. Preserve each source as linked provenance. Group similar evidence into one recommendation; do not count a global fixed number of occurrences as the only evidence of repetition.

Recommend work for repeated questions, defects, documentation/support gaps, requested product changes, or likely duplicates. Treat documentation and support improvements as bug-fix or feature work when they address a demonstrated user need. If a Slack question has a clear public-docs answer without a stronger signal, recommend a concise documentation-backed Slack reply.

Classify recommendations as bug, feature, documentation/support improvement, duplicate, intake-gap routing, release blocker, or security finding. The agent may infer a release blocker only with concrete evidence, source links, and confidence. Keep `critical` for security findings and release blockers; use `high`, `normal`, or `low` for all other items. Set confidence to `high`, `medium`, or `low`, and explain uncertainty unless it is high.

## Write the report

Create a dated immutable report. Include generation time, duty-period start, source/checkpoint coverage, and scan limitations. Use links and short paraphrases only.

Include these sections:

1. **Needs your decision** — at most five decision-worthy recommendations. Each entry has report-local ID (`R-01`...), priority, classification, concise proposed action, confidence, linked evidence, applicable public-doc links or `none found`, and current disposition.
2. **Triage queue** — state the total count of open `state:triage-needed` issues and how many are unlisted. Show up to five recently updated items, each with number, title, last-update time, and a concise summary of current context and material changes since the prior review. Put the rest in overflow. Do not assess these issues; direct the engineer to `triage-issue`.
3. **Dependabot pull requests** — open non-draft Dependabot PRs that need maintainer action, with number, package/update, check status, whether they are waiting for `/ok to test mirror`, and link. Put this section before the general PR list so dependency updates do not become stale. Do not recommend or act on PRs in v1.
4. **Community pull requests** — up to five new non-draft community PRs with number, title, author, check status, and link. Exclude Dependabot PRs already listed above. Put the rest in overflow. Do not list draft PRs, and do not recommend or act on PRs in v1.
5. **Deferred and overflow findings** — preserve lower-priority and capacity-limited findings without silently dropping them.
6. **Local inbox follow-up** — list each inbox entry incorporated into this report, its outcome, and any resulting recommendation ID or finding. Do not copy the whole inbox.

Pending and deferred recommendations retain their original priority and consume the five-item decision budget. When all five slots are pending, record new ordinary findings but do not add them to **Needs your decision**. Only security findings and release blockers may exceed this cap.

Never mark a recommendation as processed merely because it was reviewed. Carry it forward until the engineer explicitly applies, rejects, or defers it through `apply-triage-action`.
