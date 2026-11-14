# Labeling agent runtime integration

These modules select labeling invocations and return an unvalidated JSON
classification proposal. The shared `/label-issue` helper from
[#5355](https://github.com/NVIDIA/OpenShell/pull/5355) owns eligibility, evidence,
validation, label writes, checkpoints, and local reporting. Activation
prerequisites are tracked in [#5276](https://github.com/NVIDIA/OpenShell/issues/5276).

## Execution boundary

Select an invocation with `labeling_agent_events.select_invocation`, then call the
shared helper's preparation. Only `status: ready` with `classifier_required: true`
creates a model session. Pass the prepared evidence and trusted classifier
instructions to `managed_label_classifier.session_request`, call `classify`, and
return its proposal to the shared preview/application helper. Follow the shared
[command/result contract](https://github.com/NVIDIA/OpenShell/blob/70fa003b902416459b2c08131b5cc265294d35d6/.agents/skills/label-issue/references/result-contract.md).

Include the result schema and referenced classification guidance in the trusted
instructions: the runtime cannot fetch referenced files or expand evidence.

Use a dedicated single-agent CMA configuration and an environment without
preinstalled secrets. The pinned agent version, not this adapter, selects the model.

`force` bypasses only the shared helper's unchanged-item check.

## Smoke-test CLI

This CLI previews or submits prepared inputs.

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
session. Never include credentials in evidence. `--help` lists the budget and
deadline defaults. The result contains `session_id` and `proposal`.

Failed or timed-out sessions are archived; successful sessions remain for review.
See the [session event API](https://platform.claude.com/docs/en/managed-agents/events-and-streaming).

## Verification

```shell
mise run test:labeling-agent
```

Offline tests fake CMA and permissions and perform no remote writes.
