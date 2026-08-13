---
name: triage-issue
description: Assess, validate, and route community-filed issues for human disposition and roadmap placement. Takes a specific issue number or processes a confirmed batch of issues labeled state:triage-needed. Investigates reported behavior, separates objective findings from product decisions, and prepares validated issues for a human yes/no decision. Trigger keywords - triage issue, triage, assess issue, review incoming issue, triage issues.
---

# Triage Issue

Establish the facts a human needs to decide whether OpenShell should address an issue and, if so, where it belongs on the roadmap. Triage does not authorize work, sequence it, or produce an implementation plan.

## Prerequisites

- The `gh` CLI must be authenticated (`gh auth status`)
- You must be in a git repository with a GitHub remote
- The workflow labels `state:validated`, `state:accepted`, and `state:needs-info` must exist. Report missing labels to the operator; do not create them implicitly.

## Critical: Disposition and Roadmap Placement Are Human-Only

Triage establishes technical validity; it does not decide whether valid work belongs on the roadmap. Agents must never:

- Decide that OpenShell should or should not invest in otherwise valid work.
- Apply or remove `state:accepted`.
- Add an issue to the roadmap project, apply or remove the `roadmap` label, or recommend a specific roadmap item.
- Apply `agent:plan-requested` or `agent:implementation-requested`.
- Treat technical validity as product acceptance.

OpenShell has no `priority:*` labels. Sequencing comes from association with an item on the OpenShell Roadmap, and that association is a maintainer decision.

`state:validated` means the factual assessment is complete and awaits human disposition. A human declines by closing the issue as not planned with a rationale, or accepts by replacing `state:validated` with `state:accepted` and placing the issue on the roadmap as documented in `CONTRIBUTING.md`. Accepted work may remain human-owned. A maintainer can queue deeper agent investigation or planning with `agent:plan-requested`, or directly ask an agent to work on a specific issue.

The optional `agent:*` workflow controls unattended queue pickup: `agent:plan-requested` queues planning, and `agent:implementation-requested` queues implementation after plan review. A direct user instruction separately authorizes the phase it requests and does not require either label.

## Agent Comment Marker

All comments posted by this skill **must** begin with the following marker line:

```
> **📋 triage-agent**
```

This marker distinguishes triage comments from human comments and from other skills (`🏗️ build-from-issue-agent`, `🔒 security-review-agent`, etc.).

## Invocation Modes

This skill supports two modes:

### Single Issue

```
triage issue 250
triage issue #250
```

Assess one specific issue. Proceed to Step 1 with the given issue number.

### Batch

```
triage issues
```

Batch mode requires a confirmation gate before processing. This prevents accidental mass-commenting on a public repository.

**Step 1: Preview.** Query all matching issues and display a summary:

```bash
gh issue list --label "state:triage-needed" --state open --json number,title --jq '.[] | "#\(.number) \(.title)"'
```

Present the results to the user:

```
Found N issues with state:triage-needed:

  #250  Bug: sandbox fails to start with VM driver
  #312  Feature: add --output yaml to sandbox list
  ... (show up to 10, then "and N more")

This will post a triage comment on each issue.
```

**Step 2: Confirm.** Ask the user for explicit confirmation before proceeding. Use `AskUserQuestion` with options "Proceed with all N issues", "Let me pick specific issues", and let them provide custom input. Do **not** proceed without confirmation.

**Step 3: Process.** Only after confirmation, run the full triage workflow (Steps 1-7 below) for each issue. Report a summary at the end listing each issue and its classification.

## Step 1: Fetch the Issue

Strip any leading `#` from the issue number and fetch the issue.

```bash
gh issue view <id> --json title,body,state,labels,author,comments
```

If the issue is closed, report that and stop.

## Step 2: Check for Prior Triage

Search the issue comments for the triage agent marker (`> **📋 triage-agent**`).

- **If the marker is found** and no subsequent human comments exist with new information or questions, report that the issue has already been triaged and stop.
- **If the marker is found** but there are newer human comments with additional information, proceed to Step 3 to re-evaluate with the new context.
- **If a human already declined the issue or applied `state:accepted`**, do not undo or reinterpret that decision.
- **If the marker is not found**, proceed to Step 3.

## Step 3: Validate the Agent-First Gate

Check whether the issue body contains a substantive agent diagnostic section. Treat this as evidence quality, not as a reason to skip obvious safety or routing actions. Look for:

- An "Agent Diagnostic" heading or section (from the bug report template)
- Evidence that the reporter used agent skills (skill names mentioned, diagnostic output pasted)
- Concrete investigation output (not just placeholder text or "N/A")

If the diagnostic is missing, continue when the report already contains enough concrete evidence to assess safely. Otherwise classify it as `needs-information`, request the exact missing evidence, remove `state:triage-needed`, and add `state:needs-info`.

- If a public issue may disclose a security vulnerability, do not repeat or expand sensitive details. Classify it as `security-report` and direct the operator to `SECURITY.md`.
- Route usage questions and support requests to the documented support venue.
- Handle clear duplicates, wrong-repository reports, and objectively expected behavior without requiring a full technical investigation.

Proceed to Step 4 for reports requiring technical validation.

## Step 4: Check Reported Version and Known Fixes

Before deeper diagnosis, determine whether the report may already be fixed in a newer release.

1. Extract the reported OpenShell version from the issue body, Agent Diagnostic, environment section, logs, and comments. If no version is provided, record that as missing context and continue.
2. Check current release information and known fixes when available:
   - `gh release list --limit 10`
   - `gh release view <tag>`
   - linked issues, merged PRs, release notes, local git tags/history, and both open and closed possible duplicates
3. If network access or release metadata is unavailable, state the limitation in the triage comment instead of guessing.

If the issue targets an older OpenShell release and a newer release or merged PR appears to address the same behavior:

- If the reporter has already reproduced the issue on the fixed/current release, continue to Step 5.
- If the reporter has not tested the fixed/current release, identify a concrete fixing change before using `fixed-in-release`. If the causal link is uncertain, request a retest instead of declaring the issue fixed.

## Step 5: Diagnose and Validate

Assess the report by investigating the codebase. Use the `principal-engineer-reviewer` sub-agent via the Task tool:

```
Prompt the sub-agent with:
- The full issue title and body
- The reporter's agent diagnostic output
- Instructions to evaluate with a skeptical lens:
  1. Is this report describing a real problem or user error?
  2. Can the described behavior be reproduced from the information given?
  3. Does the reporter's agent diagnostic match what you see in the codebase?
  4. If this is a bug, what component is affected?
  5. If this is a feature request, is it technically coherent and feasible? Do not decide whether the project should accept it.
  6. Are there any open or closed issues that duplicate this?
  7. What uncertainty remains, and what exact evidence would resolve it?
```

Based on the sub-agent's analysis, also attempt to validate the report directly:

- For bug reports: check the relevant code paths, look for the described failure mode
- For feature requests: assess feasibility against the existing architecture
- For gateway deployment or infrastructure issues: reference the `debug-openshell-cluster` skill's known failure patterns
- For inference and provider-topology issues: reference the `debug-inference` skill's known failure patterns
- For CLI/usage issues: reference the `openshell-cli` skill's command reference

Record impact signals for the human decision: affected users and scope, regression status, workaround availability, severity evidence, and evidence quality. Do not convert those facts into a roadmap or sequencing recommendation.

## Step 6: Classify

Based on the investigation, classify the issue into one of these categories:

| Classification | Meaning | Agent action |
|---|---|---|
| **validated-bug** | Evidence confirms a real defect | Add relevant area/topic labels; replace triage/needs-info state with `state:validated`; leave open |
| **validated-feature** | The proposal is technically coherent and feasible | Add relevant area/topic labels; replace triage/needs-info state with `state:validated`; leave open |
| **needs-investigation** | The report is credible but needs a deeper spike | Add `spike` if available; replace triage/needs-info state with `state:validated`; leave open for a human decision on whether to invest in the spike |
| **needs-information** | Critical reproduction or environment evidence is missing | Replace `state:triage-needed` with `state:needs-info`; request the exact missing evidence |
| **cannot-reproduce** | A faithful attempt did not reproduce, but the report may still be valid | Replace `state:triage-needed` with `state:needs-info`; document the attempt and request discriminating evidence |
| **fixed-in-release** | A concrete released change fixes the reported behavior | Explain the fix and version; close only when the causal link is clear, otherwise request a retest |
| **duplicate** | Another open or closed issue is the canonical report | Link the canonical issue and close |
| **expected-behavior** | Code and documentation establish that the behavior is intentional | Explain the behavior and close |
| **support-request** | The report asks for usage help rather than tracking work | Provide the support route and close |
| **wrong-repository** | Another repository owns the affected component | Link the correct tracker and close |
| **security-report** | The report may contain a vulnerability | Avoid further public analysis and direct the operator to `SECURITY.md` for safe handling |

Do not use `validated-feature` to imply roadmap acceptance. Do not use `expected-behavior` to decline a technically valid feature request.

## Step 7: Post Triage Comment

Post a structured comment with the triage marker:

```markdown
> **📋 triage-agent**
>
> ## Triage Assessment
>
> **Classification:** <validated-bug | validated-feature | needs-investigation>
>
> ### Summary
> <What was established and confidence in the evidence.>
>
> ### Investigation
> <Reproduction results, code/release evidence, affected components, and duplicates.>
>
> ### Impact Signals
> - **Affected users/scope:** <facts or unknown>
> - **Regression:** <yes/no/unknown>
> - **Workaround:** <available/unavailable/unknown>
> - **Evidence quality:** <high/medium/low with reason>
>
> ### Human Decision Required
> Decide whether OpenShell should address this issue. If yes, replace
> `state:validated` with `state:accepted`, associate it with a roadmap
> item, and decide whether the work remains human-owned.
> To queue investigation or planning for an unattended agent, also apply
> `agent:plan-requested`. You can instead directly ask an agent to use
> `create-spike` or `build-from-issue` on this issue. If no, close it as not
> planned and record the rationale.
> Roadmap association is independent sequencing metadata.
```

For other outcomes, replace the impact and decision sections with the exact information request, objective resolution, or safe routing guidance.

Keep exactly one intake/triage state among `state:triage-needed`, `state:needs-info`, and `state:validated`. Remove `state:triage-needed` after every completed assessment. Never apply `state:accepted`, any `agent:*` label, or the `roadmap` label during triage. Never close a validated issue.

## Relationship to Other Skills

```
Community issue filed
        |
  [GitHub Action: instant gate check]
        |
  triage-issue
        |
  state:validated
        |
  human decline OR state:accepted + roadmap placement
        |
  create-spike          (if deeper investigation is approved)
        |
  human queues planning with agent:plan-requested
  OR directly requests planning
        |
  build-from-issue      (creates implementation plan)
        |
  human queues implementation with agent:implementation-requested
  OR directly requests implementation
        |
  implementation
```

- **triage-issue** establishes technical validity and impact evidence.
- **Humans** decide whether to accept valid work and where it lands on the roadmap.
- **create-spike** deepens investigation only after that investment is approved.
- **build-from-issue** may be invoked directly for a specific issue. Unattended agents use `agent:plan-requested` to pick up planning and `agent:implementation-requested` to pick up implementation.

Triage is the assessment layer. It does not sequence work, accept it onto the roadmap, plan, or build.
