# Review findings contract

Before invoking the reviewer, require JSON with this envelope:

```json
{
  "schema_version": 1,
  "reviewed_head_sha": "<40-character head SHA>",
  "review_mode": "<initial|follow_up|critical_only>",
  "findings": []
}
```

Each proposed finding uses these fields:

```json
{
  "id": "GATOR-12345678-01",
  "severity": "Critical",
  "invariant": "The complete contract shared by equivalent cases.",
  "attacker_or_operator_prerequisite": "Capability required to reach the case.",
  "supported_entry_point": "Supported API, CLI, protocol, or runtime path.",
  "sink": "Operation where the defect becomes observable.",
  "changed_location": {
    "path": "path/to/file.rs",
    "line": 123
  },
  "base_behavior": "Behavior at the reviewed base or previous reviewed tree.",
  "head_behavior": "Behavior introduced or materially worsened at this head.",
  "observable_impact": "Concrete security, data-loss, correctness, or maintainability impact.",
  "reproducer": "Minimal deterministic test or constrained reproducer.",
  "pr_ownership": "Why the pull request owns or worsens this problem.",
  "requested_change": "A proportionate fix that closes the invariant.",
  "scope": "latest_delta",
  "sibling_sites": [
    "Other known site covered by this same invariant and finding ID."
  ]
}
```

`severity` is `Critical`, `Warning`, or `Suggestion`. `scope` is:

- `latest_delta` for a new issue introduced by the mode-appropriate diff.
- `carried` for an existing obligation. Preserve its finding ID and do not
  create a replacement thread.
- `unchanged_critical` only for newly evidenced Critical security, data-loss,
  or correctness defects in unchanged code.

Run:

```bash
validate-review-findings review-findings.raw.json \
  > review-findings.json
```

The validator sets `blocking`, `classification`, and `validation_errors`.
Only entries with `blocking: true` may block or become inline comments. A
Critical or Warning missing any evidence field becomes a non-blocking
`hypothesis`. A second finding with the same invariant is also downgraded;
list sibling sites on the first finding instead. Suggestions always remain
non-blocking.

For a finite family, put every known member in `sibling_sites` under one
invariant and one finding ID. On later rounds, update that finding instead of
creating a sibling finding.
