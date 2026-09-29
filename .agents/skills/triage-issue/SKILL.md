---
name: triage-issue
description: Assess community-filed OpenShell issues and send a private, evidence-based handoff to the duty engineer. Takes an issue number or a confirmed batch of open issues labeled state:new. A human directs all public responses and disposition.
metadata:
  internal: true
---

# Triage Issue

Assess a community issue so the duty engineer can quickly accept it, decline it with an explanation, ask for exact missing information, or invite collaborators into the decision. This skill is human-invoked during this rollout. `state:new` calls for screening only; it does not authorize planning or implementation. Maintainer-authored issues normally enter `state:accepted` through the issue-opened workflow and do not need this screening.

The [issue workflow](https://docs.nvidia.com/openshell/latest/contributing/issue-workflow.md) defines the three label axes. The [proposal](https://github.com/NVIDIA/OpenShell/issues/3807) explains the rollout. This skill never decides acceptance or roadmap placement, and never adds or removes `state:accepted`, `roadmap`, `needs:spike`, `needs:plan`, `needs:pr`, or `needs:rfc` without human direction. A human can directly request a specific phase without changing queue labels.

## Prerequisites

- `gh` is authenticated to the OpenShell repository.
- The OpenShell Triage bot is installed in `#openshell-triage` with `chat:write` and `channels:history`, and its token is available through the `OPENSHELL_TRIAGE_SLACK_BOT_TOKEN` secret environment variable. The bot posts under its own identity. If the bot or token is not available, prepare the assessment locally and stop before any public comment or issue mutation.
- `OPENSHELL_TRIAGE_SLACK_CHANNEL_ID` defaults to `C0C20SDLDNW`; `OPENSHELL_TRIAGE_SLACK_DUTY_GROUP_ID` defaults to `S0C099KM56F`. Configure both when the Slack workspace changes. The latter identifies the one-person `@openshell-duty-eng` group; maintaining group membership is outside this skill.

## Select Issues

For a supplied issue number, fetch the issue and comments with `gh issue view <id> --json title,body,state,labels,author,comments`. Stop if closed, accepted, or already on the roadmap, unless the human expressly asks for a new assessment of later evidence. Do not treat a missing or old label as a reason to skip a directly requested assessment.

For batch invocation, list open `state:new` issues with `gh issue list --label state:new --state open --json number,title`. Show the count and up to ten titles, then ask the human to confirm the exact batch before investigating or posting. Each confirmed issue gets its own handoff. Do not run an automatic issue-opened trigger from this skill; that belongs to [#3816](https://github.com/NVIDIA/OpenShell/issues/3816).

Before repeating an assessment, inspect existing Slack handoff and newer GitHub comments. The handoff tool reuses the issue's Slack thread and skips an identical summary. Reassess only when new evidence or a human request justifies it.

## Investigate

1. Check for a substantive User Story, Problem Statement, Impact / Why This Matters, and Acceptance Criteria. Impact should identify consequences, current workaround, and why it is insufficient. A bug also needs reproducible steps and environment; a feature request needs a user-visible proposed design and alternatives. Reporter diagnostics are optional.
2. Search open and closed issues for duplicates and prior declines. For a reported bug, check the reported version against releases and known fixes. Identify a concrete fixing change before calling a report fixed; request a retest if the causal link is uncertain.
3. Validate the reported behavior against code and documentation. Use the `principal-engineer-reviewer` sub-agent for a technical validity check when deeper diagnosis is needed. Record what you actually checked, evidence quality, affected users, scope, regression status, and workaround. Do not turn label frequency or an incomplete historical label into design evidence.
4. Classify the outcome as validated bug, validated feature, needs information, needs investigation, cannot reproduce, fixed in release, duplicate, expected behavior, support request, wrong repository, or possible security report. A technically valid feature may still be declined by a human. A suspected vulnerability follows `SECURITY.md`; do not expand exploit details in a public issue or Slack.

## Hand Off Privately

Write a concise assessment to a local UTF-8 file. Include the issue link, classification, factual summary, evidence and uncertainty, impact and workaround, precise information needed if any, and the human decisions needed. Recommend an immediate accept/decline discussion when the evidence allows one. If a decision is delayed, identify the exact person or evidence needed so `state:validated` does not become a parking place. Keep issue text and secrets out of the summary unless directly needed; redact credentials and personal data.

For ordinary reports, deliver the file with:

```shell
uv run --no-project python scripts/triage_handoff.py \
  --issue-url https://github.com/NVIDIA/OpenShell/issues/<id> \
  --summary-file /path/to/triage-summary.txt
```

For a possible security report, send only a safe routing notice with `--security` instead of a summary file. This mode discards any supplied assessment text. The tool posts as the bot to the configured channel, mentions `<!subteam^S0C099KM56F>` (or the configured replacement group), and reuses the existing issue thread. It checks channel history before posting and fails closed if it cannot check for a prior handoff. If delivery fails, report the error to the operator and stop before public action. A bot installation or token is not required merely to review a draft PR for this integration.

The duty engineer reads the summary in Slack, asks other maintainers for opinions there, and directs the public response and issue label changes. Do not post a public triage assessment or mutate the issue on the strength of the agent's own recommendation. After a human gives explicit direction, carry out only the requested public action and use this marker at the start of any agent-authored comment:

```markdown
> **📋 triage-agent**
```

## Human-Directed Outcomes

| Human direction | Issue labels and status |
| --- | --- |
| Ask for specific missing information | Keep `state:new` or `state:validated` as directed; set `needs:info`; ask only the exact question. |
| Factual assessment complete but decision pending | Set `state:validated`; clear stale `needs:*`; record who will decide and why a delay is needed. |
| Accept | Human applies `state:accepted` or places the issue on the roadmap, then chooses the next work and actor. Agents do not record this decision themselves. |
| Decline, duplicate, fixed, support route, or wrong repository | Explain the reason or route empathetically, then close with the appropriate GitHub reason if directed. Clear `needs:*` on closure. |
| Approved bounded investigation or RFC | A human authorizes `needs:spike` or `needs:rfc` and directs the next step. |

Use `type:bug`, `type:feature`, `type:support`, or `type:spike` only when evidence supports the type. The human may ask the agent to apply those non-acceptance labels after reviewing the handoff. Never add `agent:*` workflow labels to new work. Do not apply `topic:security` to a new public vulnerability report; route privately.
