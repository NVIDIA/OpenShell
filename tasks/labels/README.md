# Repository label preparation

`taxonomy.json` records the concise definitions and category colors agreed in
[#5151](https://github.com/NVIDIA/OpenShell/issues/5151). `REVIEWERS.md` remains the
source for full scopes and reviewer membership. The active names must match.

Preview all definition changes without modifying GitHub:

```shell
uv run --no-project python tasks/scripts/prepare_label_taxonomy.py --repo NVIDIA/OpenShell > label-definition-plan.json
```

The preview retrieves every page, records original definitions (including label
IDs), and lists creates, updates, and identity-preserving retirements. It rejects
unreviewed active names, conflicting retirement targets, archived definitions,
and drift between the catalog and roster. It also reports missing descriptions
in other label families for separate review; it never guesses workflow states.
`--labels-file` accepts an exported JSON array for an offline preview.

## Rollout

1. Land reviewed routing and roster support first. SDK language topics accompany
   `topic:sdk`; their empty membership tables add subscription scopes without
   volunteering new reviewers. Broad SDK membership supplies reviewer coverage.
2. Review the current repository workflows, scripts, templates, skills, required
   checks, and external webhook/app/project filters for names being retired.
   Repository code alone cannot establish external compatibility. A denied
   webhook lookup is an outstanding check, not evidence that no hooks exist.
3. Refresh the preview immediately before editing definitions and keep its
   original definitions as the recovery record. Create/update active definitions
   first. Rename each obsolete label in place to its complete `retired:` name;
   never delete/recreate it. Verify the same GitHub label ID survives retirement.
4. Use areas `#6699CC`, topics `#B3D1EB`, and retired labels `#EDEDED`. Renaming
   preserves associations but changes displayed names/colors on historical items
   too. Existing saved filters and subscriptions may need updating.
5. Re-read all definitions and compare the result with the plan. Save the verified
   before/after definitions and any exceptions. In-place renames can be reversed
   using the original names, IDs, descriptions, and colors after checking for
   concurrent edits and name collisions.

The preview has no apply mode. Definition edits require the separate authorized
preparation phase after the checks above. Do not change issue/PR assignments,
cycle checkpoint labels, or invoke the item classifier during preparation.
Recoloring/renaming definitions does not backfill reviewer requests. The later
per-item migration uses the shared `/label-issue` path, its current acceptance
and lifecycle checks, and an observed preview/application rollout under #5276.
