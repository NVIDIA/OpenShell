---
name: triage-issue
description: Assess, classify, and route community-filed issues. Takes a specific issue number or processes all open issues with the state:triage-needed label in batch. Validates agent-first gate compliance, attempts diagnosis using relevant skills, and classifies issues for routing into the spike-build pipeline. Trigger keywords - triage issue, triage, assess issue, review incoming issue, triage issues.
---

# Triage Issue

Assess, classify, and route community-filed issues. This is the front door for community inflow — distinct from `build-from-issue`, which is the maintainer execution tool for implementation.

## Prerequisites

- The `gh` CLI must be authenticated (`gh auth status`)
- You must be in a git repository with a GitHub remote

## Critical: `state:agent-ready` Label Is Human-Only

The `state:agent-ready` label is a **human gate**. Triage **never** applies this label. Triage assesses and classifies — humans decide what gets built. This is a non-negotiable safety control.

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

Query all open issues with the `state:triage-needed` label and process them in sequence:

```bash
gh issue list --label "state:triage-needed" --state open --json number,title --jq '.[].number'
```

For each issue returned, run the full triage workflow (Steps 1-6). Report a summary at the end listing each issue and its classification.

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
- **If the marker is not found**, proceed to Step 3.

## Step 3: Validate the Agent-First Gate

Check whether the issue body contains a substantive agent diagnostic section. Look for:

- An "Agent Diagnostic" heading or section (from the bug report template)
- Evidence that the reporter used agent skills (skill names mentioned, diagnostic output pasted)
- Concrete investigation output (not just placeholder text or "N/A")

**If the diagnostic section is missing or clearly placeholder:**

1. Add the `state:triage-needed` label if not already present:
   ```bash
   gh issue edit <id> --add-label "state:triage-needed"
   ```
2. Do not post a standalone redirect comment. Report the missing diagnostic to the operator and stop unless a human explicitly asks you to continue triage anyway.

**If the diagnostic section is substantive**, proceed to Step 4.

## Step 4: Diagnose and Validate

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
  5. If this is a feature request, does the design make sense given the architecture?
  6. Are there any existing issues that duplicate this?
```

Based on the sub-agent's analysis, also attempt to validate the report directly:

- For bug reports: check the relevant code paths, look for the described failure mode
- For feature requests: assess feasibility against the existing architecture
- For cluster/infrastructure issues: reference the `debug-openshell-cluster` skill's known failure patterns
- For inference and provider-topology issues: reference the `debug-inference` skill's known failure patterns
- For CLI/usage issues: reference the `openshell-cli` skill's command reference

## Step 5: Classify

Based on the investigation, classify the issue into one of these categories:

| Classification | Criteria | Action |
|---------------|----------|--------|
| **bug-confirmed** | Agent diagnostic and codebase analysis confirm a real defect | Apply relevant `area:*` or `topic:*` labels as needed, remove `state:triage-needed`, and assign the built-in `Bug` issue type manually if needed |
| **feature-valid** | Design proposal is sound, feasible given the architecture | Apply relevant `area:*` or `topic:*` labels as needed, remove `state:triage-needed`, and assign the built-in `Feature` issue type manually if needed |
| **duplicate** | An existing open issue covers this | Link the duplicate, close with comment |
| **user-error** | The reported behavior is expected, or the issue is a misconfiguration | Comment with explanation and guidance, close |
| **needs-more-info** | Report is substantive but missing critical reproduction details | Comment requesting specifics, keep `state:triage-needed` |
| **needs-investigation** | Report appears valid but requires deeper analysis (spike candidate) | Label `spike`, remove `state:triage-needed` |

## Step 6: Post Triage Comment

Post a structured comment with the triage marker:

```markdown
> **📋 triage-agent**
>
> ## Triage Assessment
>
> **Classification:** <classification from Step 5>
>
> ### Summary
> <2-3 sentences: what was found, whether the report is valid>
>
> ### Investigation
> <Key findings from the codebase analysis. Reference specific files and components.>
>
> ### Recommendation
> <Next steps: ready for spike, needs more info from reporter, can be closed, etc.>
```

Apply the appropriate labels as determined in Step 5.

**Do not apply `state:agent-ready`.** That is always a human decision.

## Relationship to Other Skills

```
Community issue filed
        |
  [GitHub Action: instant gate check]
        |
  triage-issue          ← this skill
        |
  create-spike          (if classification is needs-investigation)
        |
  build-from-issue      (if human applies state:agent-ready)
```

- **triage-issue** decides whether an issue is valid and how to classify it.
- **create-spike** does deep feasibility investigation for issues that need it.
- **build-from-issue** implements once a human approves.

Triage is the assessment layer. It does not plan or build — it evaluates and routes.
