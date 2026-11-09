# One-item labeling runner

The runner connects the shared [label-issue skill](../../.agents/skills/label-issue/SKILL.md)
and helper to the managed classifier from [#5407](https://github.com/NVIDIA/OpenShell/pull/5407).
The helper owns eligibility, evidence, validation, writes, checkpoints and local
reporting. No automatic trigger or backlog execution is installed.

## Setup

Use a trusted checkout containing the helper and runner, POSIX, Python, `uv`, and
authenticated `gh`. Configure a trusted GitHub labeling identity with the required
repository permissions. Provision canonical taxonomy/routing definitions and the
approved `meta:labeler-checkpoint` label before corresponding live applications;
the runner never creates repository labels.

Provision a dedicated single-agent CMA agent, pin its version, and use an
environment without preinstalled secrets. Start with a Sonnet-level model.
Configure `ANTHROPIC_API_KEY` in the invoking environment; never put credentials
in instructions, evidence, arguments or committed files. The adapter supplies no
GitHub credentials, repository mounts or vaults. It overrides tools, MCP servers
and attached skills to empty lists. Verify these controls in an observed live run
before unattended use. Offline tests do not verify the saved CMA configuration.

## Preview and application

From the checkout root, preview one issue or PR by number or same-repository URL:

```shell
packet_dir=$(mktemp -d /tmp/openshell-label-run.XXXXXX)
uv run --no-project python tasks/scripts/label_issue_runner.py 5411 \
  --repo NVIDIA/OpenShell --output "$packet_dir" \
  --trusted-actor "$label_actor" --executor "$label_actor" \
  --agent-id agent_CONFIGURED_ID --agent-version 1 \
  --environment-id env_CONFIGURED_ID --human
```

A ready item starts billable classification; preview performs no GitHub writes.
Ineligible, excluded, held, unchanged or errored preparation stops before creating
a transport or model session. `--force` is an invoking human's override of
unchanged detection only. It confers no eligibility or write authorization.

Use `--request-preview` to save `request.json` without a CMA call or API key.
This mode still prepares live GitHub evidence and needs the non-secret CMA IDs.
It replaces the adapter's temporary prepared-input CLI.

The runner reads trusted classification instructions, result contract and migration
policy from its checkout. Prepared content stays in the untrusted user message.
The classifier may request `{"expand_evidence": ["ID", "..."]}` as its entire
response. The runner expands those IDs through the shared helper and sends the
delivered packets with the next round. It includes taxonomy definitions, malformed
removal candidates and navigation metadata. Index membership never substitutes
for inspected content. Deferred delivery, failed expansion and unresolved partial
coverage remain explicit and cannot produce a successful checkpoint.

Defaults are at most four sessions, a 180-second classification deadline, and a
25-US-cent total list-price ceiling. `--max-rounds` accepts 1–8. The runner divides
`--budget-cents` into equal integer per-session ceilings; their sum never exceeds
the invocation budget. The budget must allow at least one cent per possible round.
Evidence input is capped at 2 MiB; larger cases require local inspection.

Read `preview.json`, including exact ordered `mutation_requests`, ambiguity,
prerequisites and bookkeeping. After explicitly authorizing this one-item
application, use the same directory and identity:

```shell
uv run --no-project python tasks/scripts/label_issue_runner.py 5411 \
  --repo NVIDIA/OpenShell --output "$packet_dir" \
  --trusted-actor "$label_actor" --executor "$label_actor" --apply --human
```

Application loads the saved result and exact preview. It creates no CMA session
and needs no CMA IDs or API key. The shared helper rechecks current eligibility,
material and label events, compares exact payloads, verifies replacement
additions before removals, and separately verifies completion. A no-change
classification can still require checkpoint bookkeeping. See the shared
[command/result contract](../../.agents/skills/label-issue/references/result-contract.md).

## Reports and recovery

Stdout is one JSON report; `--human` adds the helper's concise summary and
normalized ambiguity sentence to stderr. Never post labeling comments.

Keep the output directory private to the invoking session: it contains item
evidence, proposals and exact mutation payloads. Each new preparation needs an
empty directory. `executions.json` records each session ID before polling;
`proposal-N.json`, `result.json`, `preview.json` and `applied.json` preserve the
review and application artifacts. Exceptions include the stage and known
execution references. If session creation has an uncertain response, no ID may
be available; inspect CMA before starting another run.

Session failure or timeout attempts archival; archival failure reports its ID.
Successful sessions remain available for review. Session creation is never
automatically retried. Error reports preserve HTTP status, retryability,
earliest retry time and write uncertainty. Honor retry times. Stale inputs
require a fresh preparation and review. Partial/uncertain GitHub writes require
fresh reconciliation, never blind replay of saved requests. A candidate
checkpoint is not proof of successful completion.

Exit codes match the helper: 0 for ready/preview/applied/no-op/unchanged/skipped,
2 for held/prerequisite/stale, and 1 for error/partial.

Use one coordinated executor per item. The helper's POSIX lock serializes local
applications only; it does not serialize different hosts. Automatic acceptance
dispatch and cross-entry-point coordination belong to the follow-up. In
particular, [#5260](https://github.com/NVIDIA/OpenShell/pull/5260)'s successful
`GITHUB_TOKEN` acceptance write needs an explicit runner hook, including drafts
and independently of later reviewer-routing success; it does not trigger another
workflow. `labeling_agent_events.select_invocation` remains a selector for those
future callers, which must pass force only from authorized human invocations.
No such hook is installed here.

## Verification

```shell
mise run test:labeling-agent
```

Offline tests use the actual shared helper with fake GitHub and CMA services.
Before activation, observe representative live previews and explicitly authorized
one-item applications covering legacy migration, missing evidence, unchanged
skips, human force and partial failures. Record session IDs and verified outcomes
locally. Dedicated CMA configuration and live verification remain pending.
