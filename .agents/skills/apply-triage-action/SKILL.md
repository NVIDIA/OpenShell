---
name: apply-triage-action
description: Apply, reject, or defer exactly one recommendation from the most recent local triage queue report. Use when the on-duty engineer explicitly supplies one report-local ID such as R-01. For external actions, revalidate and preview the exact write, then require a second per-action confirmation before posting, labeling, creating, or closing anything.
---

# Apply Triage Action

Process exactly one report-local recommendation ID from the most recent dated queue-review report. Do not accept a natural-language approval without an ID. Do not accept an ID from an older report.

## Locate and validate

1. Find the most recent report in `architecture/plans/triage-duty-reports/`.
2. Read the selected recommendation and its current local disposition.
3. Reject missing, expired, already-final, or ambiguous IDs without making a write.
4. Append every explicit disposition to a dated local action report beside the queue reports. Record the source report, ID, timestamp, disposition, reason, and outcome. Keep sensitive content out of the record.

## Reject or defer

For **reject** or **defer**, require the engineer to give a reason. Record the no-write disposition.

- **Reject** is terminal locally. Do not recommend the item again unless material new evidence changes the case.
- **Defer** is non-terminal. Preserve its original priority and carry it into the next review's **Needs your decision** section.

## Apply

Before any external write, re-read the target and determine whether it materially changed.

- If the action is already complete or would be a harmless no-op, make no external write and record the reason.
- If new information makes the action unsafe or substantially different, stop and request a fresh review/approval.
- Otherwise, show the exact single external write and require explicit second confirmation for that action.

After confirmation, perform only the approved action and record the outcome.

Supported v1 actions:

- Add `state:triage-needed` to an eligible community issue.
- Create one GitHub issue.
- Post one concise explanatory Slack reply, including a public-doc link when applicable.
- Mark an existing issue as a likely duplicate, including any approved comment or close action.

Never create a public GitHub issue for a security finding. Route it through the project's private security process instead.
