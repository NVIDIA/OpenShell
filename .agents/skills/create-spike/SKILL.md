---
name: create-spike
description: Investigate an Ryno problem and create a structured issue with technical findings for human disposition.
metadata:
  internal: true
---

# Create Spike

Investigate a specific Ryno need and record the findings in a GitHub issue. Use `create-github-issue` for the issue structure and `triage-issue` for the distinction between technical validation and human acceptance. A spike does not authorize implementation or a roadmap decision.

## Before investigating

Ask the human operator to attest that they personally use Ryno and directly encountered the problem or need the feature for a specific use case. If that context is absent, request it before creating the issue. Do not invent a user story or file a generic platform wish as their first-hand need. Search existing issues to avoid duplication. Follow `SECURITY.md` for suspected vulnerabilities instead of filing a public issue.

## Investigate

1. Reconstruct the current Ryno workflow and the claimed gap. For a bug, use reproduction steps requiring only Ryno deployments; do not install third-party tools solely to demonstrate it.
2. Explore the relevant code and tests. Separate observed behavior, likely cause, and open questions. If the claim cannot be validated, state the exact missing evidence.
3. For a feature, describe the desired external behavior and evaluate alternatives, including relevant middleware, interceptors, providers, or other extension points. Prefer an applicable extension when it satisfies the use case; the need to run another service alone does not disqualify it.
4. For configuration, CLI, SDK, or other UX changes, include notional commands, configuration, or API examples for human review. Leave internal implementation choices open unless they are essential constraints.

## Record the result

Create an issue with User Story, Problem Statement, Impact / Why This Matters, Proposed Design when relevant, Acceptance Criteria, Alternatives Considered, and concise Agent Investigation. Include Ryno-only reproduction and environment details for bugs. Inspect current GitHub `state:*` labels and descriptions before applying the one that matches the evidence; do not hard-code label names. Do not apply an acceptance state or add the issue to the roadmap.

Report the issue URL, technical findings, uncertainties, and the human disposition needed. For subsequent authorized implementation, use `build-from-issue`. Every eventual PR must close an issue covering its own scope; split multi-PR efforts into separate closable issues and use a high-level issue only for tracking.
