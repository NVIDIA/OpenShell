---
name: apply-triage-action
description: Apply, reject, or defer one stable item ID from a local triage queue report. Use when an engineer selects an issue or CI recommendation; preview and confirm each external write before performing it.
metadata:
  internal: true
---

# Apply Triage Action

Process exactly one stable item ID, such as `I2991` or a CI run's `C<hash>`, from a report created by `review-triage-queue`. `R-01` is display order only: ask for the stable ID instead. Natural-language approval without an ID does not select a recommendation. PR IDs are informational and have no supported action in v1.

## Locate and validate

1. Read `.agents/triage-duty/state.local.yml`, the relevant immutable report under `reports/`, and action records under `actions/`. Action records are authoritative; reconcile the checkpoint index from them before proceeding.
2. Resolve the ID to its recorded repository and canonical source object, never to a row in the newest report. If the engineer names a report, use that snapshot; otherwise use the latest snapshot containing that ID and show its report filename, source, and action. If it differs materially from a prior recommendation the engineer may have read, require selection of the new action before previewing it.
3. Stop for a missing, colliding, ambiguous, already-final, or superseded recommendation. An older report may select the same object, but a materially changed action requires a fresh review. Rejected items can return only with recorded material new evidence. Never substitute another item.
4. Record every explicit disposition or attempted action in a dated append-only action record: repository, canonical source, stable ID, source report, timestamp, action, disposition, reason, confirmation, and outcome. Update the checkpoint index afterward; do not edit reports. Exclude secrets, private reasons, and vulnerability details. Private reasons stay with the engineer; record only `private reason withheld` locally.

## Reject or defer

Require a reason for **reject** or **defer**. Reject is terminal locally until material new evidence; defer preserves original priority and carries into later reports independently of the new-intake budget.

A shareable deferral (waiting on reporter evidence, a dependency, or linked PR changes) should survive a duty handoff on the GitHub issue. Draft a concise comment with the reason, relevant public links, and next step, then use the same per-write preview/confirmation gate below. Do not post automatically because the engineer requested deferral. If posting is declined, record that the deferral is local only. Private reasons remain local and must never enter an external payload or committable file.

For missing reporter evidence, separately propose the current lifecycle label whose discovered description denotes awaiting information. Do not replace lifecycle labels for unrelated dependency waits. A comment and a label transition are separate writes and require separate confirmations; do not infer that one approves the other. Existing public waiting context can be linked instead of repeated.

## Apply

Re-read the target and current labels/comments/checks before previewing a write. Follow [Label Discovery](../../../CONTRIBUTING.md#label-discovery), including all pages; use current definitions instead of a fixed label inventory. If a definition is unclear, resolve it before proposing a state change. Do not accept work, place it on the roadmap, or infer implementation authority from a label.

- If already complete or a harmless no-op, make no external write and record why.
- If evidence or the target changed materially, stop for a fresh review and selection of the revised action.
- Otherwise, show the stable ID, source report, canonical target, and exact **one** external write: full body/title, label diff, or closure reason as applicable. Require explicit confirmation of that payload. Selection of `apply <ID>` alone is not confirmation.

After confirmation, revalidate that the preview remains valid, perform only that write, and record its result and resulting public URL. If a material change occurred after preview, request a new preview/confirmation. If a write times out or its outcome is uncertain, inspect the target before retrying; do not duplicate a comment or issue. Keep failed/partial actions pending with the observed outcome; mark applied only once the selected action succeeds. Never reuse confirmation for a later invocation or changed payload.

Supported v1 writes:

- Add the discovered triage-queue label to an open substantive community issue with **no `state:*` label**, no intentional routing signal, and no duplicate, spam, or security-disclosure indication. Exclude maintainers/core contributors; uncertain eligibility stops the write. Recheck eligibility at application time.
- Create one GitHub issue using `create-github-issue`, including its first-hand user-story requirements. Confirmation does not waive missing evidence.
- Post one public issue comment, including shareable waiting context or a duplicate explanation.
- Change an issue's assessment state to awaiting information, following the existing `triage-issue` conventions and replacing its prior assessment state as appropriate.
- Close one issue, with the exact closure reason and evidence previewed separately. For duplicates, identify the canonical issue; approval to comment or label is not approval to close.

Never create a public issue for a suspected vulnerability. Follow [SECURITY.md](../../../SECURITY.md). This workflow supports GitHub only.
