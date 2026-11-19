# Gator review replay

Replays historical pull requests through Gator's reviewer and scores how many
known defects it finds. Use it to baseline the reviewer and to check reviewer
prompt or team changes before they reach live pull requests.

Replays run on the host with your local harness login (Codex today). They never
write to GitHub: `gh` is replaced with a stub, and the reviewer sees a checkout
whose only ref is the replayed head, so later history, including the fix, is not
reachable from it.

## Cases

`cases.jsonl` holds one case per line: the pull request, the reviewed `base_sha`
and `head_sha`, its title and body, and `expected` defects that shipped and were
fixed later. Kinds:

- `gator_review_miss`: Gator reviewed this head, and another reviewer found an
  actionable defect that Gator did not.
- `gator_network_escape`: a networking defect that merged through a
  Gator-reviewed pull request and was fixed later. The head is the squash
  commit, so the diff is the merged change.
- `network_positive_control`: a networking defect from before Gator review data
  exists, kept because a reviewer can see it in the diff.

Tags `small`, `medium`, and `large` describe diff size. Large diffs are left in
`pr.diff` for the reviewer to read in chunks instead of being inlined.

Every replay uses `initial` review mode against an empty feedback ledger, even
when Gator originally found the defect's code in a follow-up round.

## Run

```shell
scripts/agents/gator/replay/run-replay --list
scripts/agents/gator/replay/run-replay --tag small --jobs 3
scripts/agents/gator/replay/run-replay --case n3530 --label baseline
```

Pass `--team` to replay `bin/review-team` with the payload's team
configuration; member prompts and outputs are kept in each case's `team/`
directory. Otherwise the run replays the subagent that `agent.yaml` exposes as
`REVIEWER_COMMAND`, with the manifest's harness model and reasoning. Use
`--manifest` to replay another manifest, `--expose` for another exposed
command, or `--reviewer-command` for an arbitrary command. A reviewer command
runs in the case directory, reads `task.md`, and writes
`review-findings.raw.json`; `$REPLAY_PAYLOAD` points at the staged payload.

Each case directory holds `task.md`, the reviewer's raw and validated findings,
the judge's `judgment.json`, logs, and `result.json`. The run directory holds
`run.json` and `summary.json`.

## Scoring

A Codex judge compares the validated findings with each expected defect and
reports `blocking`, `nonblocking`, `partial`, or `none`. It also labels every
unmatched blocking finding `plausible` or `dubious`, since the expected list
only covers defects that were fixed later. The summary reports blocking recall,
any-severity recall, extra blockers, time, and tokens, overall and by kind.

Compare two runs case by case:

```shell
scripts/agents/gator/replay/score BASELINE_RUN_DIR CANDIDATE_RUN_DIR
```

Judges and reviewers are nondeterministic. Treat a change of one or two cases as
noise unless it repeats across runs.

## Test

```shell
scripts/agents/gator/replay/replay_test.sh
```

The test uses a fixture repository, a fake reviewer, and a fake judge.
