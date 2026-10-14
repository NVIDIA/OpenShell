---
name: apply-triage-action
description: Apply, reject, or defer exactly one issue or CI recommendation from a local triage queue report. Use when the on-duty engineer explicitly supplies an item ID.
metadata:
  internal: true
---

# Apply Triage Action

Process exactly one item ID from a queue-review report. Do not accept a natural-language approval without an ID. PRs are informational in v1.

## Locate and validate

1. Read the checkpoint and action records under `.agents/triage-duty/`; reconcile dispositions using the [local-state rules](../review-triage-queue/SKILL.md#local-state).
2. Use the named report, or the latest report containing the ID. Read the recommendation and current disposition. Material changes to a previously selected recommendation require fresh review and selection.
3. Reject missing, superseded, already-final, or ambiguous recommendations without making a write. Never substitute another item.
4. Append every explicit disposition or attempted action to a dated local action record. Record repository, target, source report, ID, timestamp, disposition, reason, confirmed payload, and outcome; update the checkpoint afterward. Keep sensitive content out of the record; use `private reason withheld` for private reasons.

## Reject or defer

For **reject** or **defer**, require the engineer to give a reason. Record the local disposition.

- **Reject** is terminal locally. Do not recommend the item again unless material new evidence changes the case.
- **Defer** is non-terminal. Preserve its original priority and carry it into the next review's carried **Needs your decision** section.

For shareable deferrals, draft a GitHub issue comment with reason, public links, and next step, or link existing waiting context. Use the confirmation rule below; declined posting leaves a local-only deferral. Keep private reasons out of external payloads and committable files. For missing reporter evidence, also propose the awaiting-information assessment state using `triage-issue`; unrelated dependency waits do not change lifecycle labels.

## Apply

Before any external write, re-read the target and determine whether it materially changed. Follow [Label Discovery](../../../CONTRIBUTING.md#label-discovery), retrieving all pages of current definitions before proposing a label change; use [`triage-issue`](../triage-issue/SKILL.md) for assessment states and maintainer authority.

- If the action is already complete or would be a harmless no-op, make no external write and record the reason.
- If new information makes the action unsafe or substantially different, stop and request a fresh review/selection.

You MUST ALWAYS preview the exact payload, item ID, source report, and canonical target, then receive explicit confirmation for each individual external write. Selecting or deferring an item is not confirmation; comments, label changes, and closures require separate confirmations. Revalidate immediately before execution; changed payloads require a new preview and confirmation. Never reuse confirmation for a later invocation.

After confirmation, perform only the approved action and record its outcome and public URL; mark applied only after success.

Supported v1 actions:

- Add the discovered triage-queue label to an open substantive community issue; recheck the [intake eligibility rules](../review-triage-queue/SKILL.md#gather-intake) and exclude duplicates, spam, and security disclosures.
- Create one GitHub issue using [`create-github-issue`](../create-github-issue/SKILL.md).
- Post one public issue comment, including waiting context or a duplicate explanation.
- Change an issue's assessment state to awaiting information.
- Close one issue with an evidenced reason; identify the canonical issue for duplicates.

Never create a public GitHub issue for a security finding. Follow [SECURITY.md](../../../SECURITY.md).
