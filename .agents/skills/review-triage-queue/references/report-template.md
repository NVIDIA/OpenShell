# Triage queue report

Include repository, generation time, source/checkpoint coverage, scan limitations, and `next_triage_issue`. Retain empty sections with `None`.

## Needs your decision — new

Each entry has an object ID, canonical source link, priority, classification, concise proposed action, confidence, linked evidence, applicable public-doc links or `none found`, and disposition at generation.

## Needs your decision — carried

Use the same fields; include the shareable deferral reason or `private reason withheld`, action-record link, and existing public waiting-context link when available.

## Triage queue

State total and unlisted queue counts. Show up to five recently updated items with ID, title, updated time, and a concise summary of context and material changes. Put the rest in overflow. Do not assess these issues; direct the engineer to `triage-issue`.

## Dependabot pull requests

List open non-draft Dependabot PRs needing maintainer action, with ID, package/update, checks, current test-authorization requirement, and link. Use the current repository workflow.

## Community pull requests

List up to five new non-draft community PRs with ID, title, author, checks, and link. Exclude Dependabot entries; put the rest in overflow.

## Deferred and overflow findings

Preserve lower-priority and capacity-limited findings with the recommendation fields above. Include informational CI findings with ID, canonical run link, attempt, workflow, commit, and conclusion.

## Local inbox follow-up

List each incorporated inbox entry, its outcome, and any resulting recommendation ID or finding. Do not copy the whole inbox.
