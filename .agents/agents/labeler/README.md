# One-item labeling runner

The labeler prepares one issue or PR, expands evidence through the shared helper,
classifies it with CMA, and returns a validated preview. Explicitly authorized
application uses the saved exact preview without reclassification. No automatic
trigger or backlog execution is installed.

## Setup

Use a trusted POSIX checkout with `uv` and authenticated `gh`. Configure a
trusted labeling identity with repository permissions. Provision canonical
taxonomy/routing definitions and the approved `meta:labeler-checkpoint` label
before corresponding applications; the runner never provisions repository labels.

Provision a dedicated single-agent CMA configuration and an environment without
preinstalled secrets. Pin a Sonnet configuration for initial observed runs.
Configure `ANTHROPIC_API_KEY` in the invoking environment, never in evidence,
arguments or committed files. The pinned version selects the model. The adapter
disables tools, MCP servers and attached skills and supplies no GitHub credentials,
repository mounts or vaults. Verify the saved configuration and CMA consumption
on representative live runs before rollout; offline tests cannot establish them.

## Invocation

From the checkout root, preview one issue or PR number or same-repository URL:

```shell
packet_dir=$(mktemp -d /tmp/openshell-label-run.XXXXXX)
uv run --no-project .agents/agents/labeler/run.py 5411 \
  --repo NVIDIA/OpenShell --output "$packet_dir" \
  --trusted-actor "$label_actor" --executor "$label_actor" \
  --agent-id agent_CONFIGURED_ID --agent-version 1 \
  --environment-id env_CONFIGURED_ID --human
```

Ready work starts billable classification; preview performs no GitHub writes.
Other preparation outcomes stop before creating an SDK client or session.
Human `--force` bypasses only unchanged detection. `--request-preview` saves
`request.json` without calling CMA or requiring an API key.

The entry point installs the pinned `anthropic` SDK through script metadata.
Imports and offline tests need no SDK. It replaces the adapter's temporary CLI.
The SDK owns request retries and pagination; the runner never retries a
classification. `--help` lists the shared budget/deadline defaults.
`--budget-cents` is the invocation ceiling, divided into equal integer session
ceilings across `--max-rounds` (1–8, default four). It must allow at least one
cent per round. Classification rounds share a deadline; SDK retries can extend
individual requests beyond it.

Review `preview.json`, including exact `mutation_requests`, ambiguity,
prerequisites and bookkeeping. After authorizing this one-item application:

```shell
uv run --no-project .agents/agents/labeler/run.py 5411 \
  --repo NVIDIA/OpenShell --output "$packet_dir" \
  --trusted-actor "$label_actor" --executor "$label_actor" --apply --human
```

Application needs no CMA IDs or API key. The shared helper rechecks eligibility,
material, labels and events, binds the exact preview, verifies additions before
removals, and independently verifies completion. A classification no-op can
still need checkpoint bookkeeping. See the [command/result contract](skills/label-issue/references/result-contract.md).

## Evidence and reports

Trusted instructions come from this agent's skill, result contract, migration
policy and [expansion prompt](prompts/classify.md). Item content stays in the
untrusted user message. The classifier may request evidence IDs; the helper
expands them and the next round receives all delivered packets. Metadata never
substitutes for inspected content. Failed expansion, deferred delivery and
partial coverage remain explicit. The runner caps evidence input at 2 MiB;
larger cases need local inspection.

Stdout is one JSON report. `--human` adds the shared summary and normalized
ambiguity sentence to stderr. Never post labeling comments. Keep the output
directory private: it holds evidence, proposals and exact payloads. Each fresh
preparation needs an empty directory. `executions.json` records IDs before
polling; `proposal-N.json`, `result.json`, `preview.json` and `applied.json`
preserve review/application artifacts. Failures retain stage and execution
references. Exit codes match the helper: 0 for success/skips, 2 for
held/prerequisite/stale, 1 for error/partial.

## Recovery and activation

On failure or interruption, the SDK adapter sends `user.interrupt`, waits for
idle, and archives with a separate cleanup deadline. SDK retries can extend
individual requests. Unconfirmed cleanup reports the session ID and warns that
execution may continue. Successful sessions remain for review. An uncertain
creation response may provide no ID; inspect CMA before starting another run.
See the [session event API](https://platform.claude.com/docs/en/managed-agents/events-and-streaming).

Honor shared-helper retry times. Stale inputs require fresh preparation and
review; partial/uncertain writes require fresh reconciliation, never replay of
saved requests. A candidate checkpoint alone is not completion.

Use one coordinated executor per item. Local POSIX locking does not serialize
different hosts. Automatic acceptance dispatch and coordination across entry
points remain follow-up work; `bin/events.py` only selects future invocations.
In particular, a `GITHUB_TOKEN` acceptance write needs an explicit dispatch
hook, including drafts and independently of later reviewer-routing success.

## Verification

```shell
mise run test:labeling-agent
```

Offline tests use the current shared helper with fake GitHub and SDK services.
Live CMA configuration, representative previews and authorized applications
remain pending, including legacy migration, missing evidence, unchanged skips,
human force and partial failures.
