# Labeling agent runtime integration

These modules start Part 3 of [#5276](https://github.com/NVIDIA/OpenShell/issues/5276):
select invocations and return an unvalidated JSON classification proposal. The
shared `/label-issue` helper from [#5355](https://github.com/NVIDIA/OpenShell/pull/5355)
owns eligibility, evidence, validation, label writes, checkpoints, and local
reporting. No automatic workflow is installed.

## Execution boundary

Select an invocation with `labeling_agent_events.select_invocation`, then call the
shared helper's preparation. Only `status: ready` with `classifier_required: true`
creates a model session. Pass the prepared evidence and trusted classifier
instructions to `managed_label_classifier.session_request`, call `classify`, and
return its proposal to the shared preview/application helper. Follow the shared
[command/result contract](https://github.com/NVIDIA/OpenShell/blob/70fa003b902416459b2c08131b5cc265294d35d6/.agents/skills/label-issue/references/result-contract.md);
this adapter checks JSON shape, not classification validity.

Include the result schema and referenced classification guidance in the trusted
instructions: the runtime cannot fetch referenced files or expand evidence.
The caller must handle required evidence expansion through the shared helper.
Do not silently treat missing or partial evidence as complete.

Trusted instructions become the session system prompt; evidence becomes the user
message. Session overrides disable tools, MCP servers, and attached skills without
changing the saved agent. The adapter supplies no GitHub credentials, repository
mounts, or vaults.

Use a dedicated single-agent CMA configuration and an environment without
preinstalled secrets. Start with a Sonnet-level model; the adapter pins the agent
version rather than choosing a model. Verify overrides in a live smoke test before
enabling automation.

## Smoke-test CLI

This temporary harness previews or submits prepared inputs. Consolidate it into
the real entry point when the shared-helper integration is available.

```shell
uv run --no-project python tasks/scripts/managed_label_classifier.py \
  --instructions /path/to/trusted-classifier-instructions.md \
  --evidence /path/to/prepared-evidence.json \
  --agent-id agent_CONFIGURED_ID --agent-version 1 \
  --environment-id env_CONFIGURED_ID
```

By default it prints the request without API calls or credentials. Output includes
item evidence; keep it in the invoking session or appropriate artifacts.

Add `--run` with `ANTHROPIC_API_KEY` in the environment to create a billable
session. Never include credentials in evidence. Defaults are a 25-US-cent
list-price ceiling (`--budget-cents`) and a 180-second deadline (`--timeout`).
The result contains `session_id` and `proposal`; validate the proposal through
the shared helper. Ambiguity belongs in local reports, never item comments.

## Completion and recovery

Success requires JSON `agent.message` followed by idle `end_turn`. Failure or
timeout archives the session; archival failure reports its ID. Successful
sessions remain available for review. Session creation is never retried
automatically after an uncertain response. Polling is bounded and error bodies
are suppressed. See the [session event API](https://platform.claude.com/docs/en/managed-agents/events-and-streaming).

## Invocation selection

`select_invocation` returns `Invocation(repository, number, force, source)` or no
invocation:

- `issues` / `pull_request_target`: `labeled` with `state:accepted`, including
  automation-applied labels and drafts.
- `issue_comment`: a new human PR comment containing only `/label-issue`,
  `/label-issue force`, or `/label-issue --force`.
- `workflow_dispatch`: a same-repository issue/PR number or URL and a Boolean
  force input.

Human commands require current write, maintain, or admin permission. Supply a live
permission lookup that propagates failures; author association is insufficient.
Force bypasses only unchanged detection in the shared helper. Other label and
lifecycle events do not dispatch the classifier.

## Pending wiring

After observed skill runs succeed, connect these modules using #5276's integration
plan and trusted default-branch code. All entry points need coordinated per-item
execution; #5355's local lock does not serialize separate hosts.

[#5260](https://github.com/NVIDIA/OpenShell/pull/5260) writes acceptance using
`GITHUB_TOKEN`; its label event will not start another workflow. Invoke the shared
entry point explicitly after a successful acceptance-label write, including for
drafts, independently of later reviewer-routing success. An existing acceptance
label alone is not current eligibility: #5260 does not refresh it. Use the shared
helper's preflight, which checks the item's author rather than the triggering
actor and propagates lookup failures.

Remaining prerequisites are the shared interfaces, reviewed CMA configuration,
acceptance-writer hook, label preparation, and observed end-to-end runs. See #5355
for canonical-label and `meta:labeler-checkpoint` prerequisites.

## Verification

```shell
mise run test:labeling-agent
```

Offline tests fake CMA and permissions and perform no remote writes. Live
configuration and model quality require observed runs.
