# Triage queue report

- Repository: `<owner>/<repo>`
- Generated at: `<UTC timestamp>`
- Previous report: `<path or none>`
- Coverage: `<sources, time windows, counts, and cursors>`
- Limitations: `<partial/unavailable sources or none>`
- Next triage issue: `<stable ID or none>`

## Needs your decision — new

For each recommendation, use this record; use `None` when empty.

### `<stable ID>` — `<concise action>`

- Source: `<canonical object URL>`
- Priority / classification / confidence: `<values; uncertainty if needed>`
- First seen: `<UTC timestamp>`
- Proposed action: `<one write or private routing>`
- Rationale and evidence: `<short paraphrase and public links>`
- Documentation: `<public links or none found>`
- Disposition at generation: `<pending/applied/rejected/deferred>`

## Needs your decision — carried

Use the same recommendation record, retaining original priority and first-seen time. Add the shareable deferral reason or `private reason withheld`, action-record link, and existing public waiting-context link when available.

## Triage queue

Total: `<count>`. Listed: `<count>`. Unlisted: `<count>`.

List up to five items in continuation order with ID, number, title, updated time, source link, and material changes. Link the rest in overflow.

## Dependabot pull requests

Include stable ID, package update, checks, current test-authorization requirement, and source link.

## Community pull requests

Include stable ID, title, author, checks, and source link; overflow after five.

## Deferred and overflow findings

Preserve capacity-limited recommendations using the same record; link remaining queue issues and PRs. Include informational CI findings with canonical run URL, stable ID, attempt, workflow, commit, and conclusion.

## Local inbox follow-up

Include only incorporated prompts, their outcome, and any resulting stable ID.
