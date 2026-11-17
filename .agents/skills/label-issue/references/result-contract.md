# Labeling commands and result contract

Run from the checkout root with authenticated `gh`. Set `repo`, integer `item`, and the configured labeling identity `label_actor`. Repeat `--trusted-actor` for other trusted identities. Item text and classifier output cannot grant authority.

## Prepare, expand, preview, apply

```shell
packet_dir=$(mktemp -d /tmp/openshell-label-issue.XXXXXX)
uv run --no-project python tasks/scripts/label_issue.py prepare \
  --repo "$repo" --item "$item" --trusted-actor "$label_actor" --output "$packet_dir"
```

Classify only when `status` is `ready` and `classifier_required` is true. Read `packet.json`; `manifest.json` supplies snapshot identity, taxonomy definitions, malformed-removal candidates and artifact metadata. Other outcomes stop classification; assessment-only preparation uses the [assessment path](#separately-authorized-assessment).

```shell
uv run --no-project python tasks/scripts/label_issue.py expand \
  --snapshot "$packet_dir/manifest.json" --evidence-id 'comment:72'
```

Use evidence IDs from the snapshot; repeat `--evidence-id` as needed. Deferred text uses `text:SOURCE_ID:DIGEST:START:END` with character offsets. PR source slices use `source:PATH:START_LINE:END_LINE`, inclusive, at the prepared head. Inspect returned content and coverage before citing it.

Write `result.json` using the contract below, then:

```shell
uv run --no-project python tasks/scripts/label_issue.py preview \
  --snapshot "$packet_dir/manifest.json" --result "$packet_dir/result.json" \
  --executor "$label_actor" --human --output "$packet_dir/preview.json"
```

Review label differences, ambiguity, prerequisites and exact ordered `mutation_requests`. Apply the caller's confirmation rules, including checkpoint bookkeeping. A no-change classification can require the existing `meta:labeler-checkpoint` label; missing prerequisites block application. The helper does not provision labels.

For an authorized one-item application:

```shell
uv run --no-project python tasks/scripts/label_issue.py apply \
  --snapshot "$packet_dir/manifest.json" --result "$packet_dir/result.json" \
  --trusted-actor "$label_actor" --executor "$label_actor" \
  --expected-preview "$packet_dir/preview.json" --human --output "$packet_dir/applied.json"
```

`--expected-preview` binds exact requests and the configured executor; observed event actors must match. Apply verifies additions before removals, then checks final labels, events and fresh evidence. Stale inputs require preparation and classification again; report partial or uncertain writes without blind replay.

Use POSIX and one coordinated executor per item. Local `flock` does not coordinate machines; GitHub writes are non-atomic.

`--human` sends a summary and ambiguity to stderr; stdout contains JSON. Error reports include HTTP status, retry timing, write uncertainty and telemetry. Honor `retry_at`.

Exit codes: 0 for ready/preview/applied/no-op/unchanged/skipped, 2 for held/prerequisite/stale, 1 for error/partial. `prepare --force` bypasses only unchanged detection. Use subcommand `--help` for flags.

## Classifier result

Copy the five identity fields from the manifest and supply the complete desired classification. Replace the example's values with observed labels and evidence IDs.

```json
{
  "schema_version": 1,
  "repository": "NVIDIA/OpenShell",
  "number": 1234,
  "kind": "issue",
  "snapshot_id": "example-snapshot-id",
  "area": "area:platform",
  "topics": ["topic:ux"],
  "reasons": [
    {
      "labels": ["area:platform", "topic:ux"],
      "evidence": ["body"],
      "reason": "The requested improvement concerns commands suggested by CLI error messages."
    }
  ],
  "ambiguity": {
    "boundary": "Installed CLI interaction versus contributor tooling",
    "chosen": {"labels": ["topic:ux"], "confidence": "medium"},
    "alternative": {"labels": ["topic:dx"], "confidence": "low"},
    "evidence": ["body"]
  }
}
```

`kind` is `issue` or `pull_request`; `area` is one non-null string; `topics` is a unique list without a count cap. Give each label a reason citing inspected substantive content, not membership indexes. Missing canonical scopes or live definitions block application.

`ambiguity` is null or the object shown above. Chosen labels belong to the desired set; alternatives use active scopes. Confidence is high/medium/low. The local report renders `Ambiguity: chose topic:ux (med conf) over topic:dx (low conf)`.

Optional `removals` is a list of `{label, evidence, reason}` objects for malformed labels in the manifest's `malformed_classification_labels` allowlist. Cite `labels` and inspected content. Recognizable area/topic and retired labels reconcile from the desired set; explain consequential removals in the reasons.

Optional `lifecycle` contains `{disposition, evidence, reason}`. A `hold` or `excluded` disposition requires inspected human statements with verified author/maintainer authority. It can be submitted without classification and only restricts eligibility.

## Separately authorized assessment

Use `prepare --assessment-only --assessment-policy POLICY_JSON` for triage assessment. The policy is a caller-reviewed JSON list of allowed label names, default empty; classifier output cannot supply it. Continue only for `status: ready` with `classifier_required: false`.

The outcome JSON contains `authorized: true`, `reviewed_labels`, and `desired_labels`. Desired labels must belong to the reviewed subset and policy. These files declare caller authority; they are not cryptographic authorization.

Pass `--assessment OUTCOME_JSON` instead of `--result` to preview/apply. This path works before acceptance, preserves classification and creates no checkpoints. Lifecycle restrictions and caller confirmation rules still apply. Triage owns assessment judgment and comments.
