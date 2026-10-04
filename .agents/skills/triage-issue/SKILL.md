---
name: triage-issue
description: Assess community issues, validate technical claims, request missing evidence, and prepare valid work for human disposition.
metadata:
  internal: true
---

# Triage Issue

Triage establishes whether a reported OpenShell problem is technically valid and sufficiently evidenced. A maintainer decides whether the project accepts valid work and where it belongs on the roadmap. Inspect current GitHub label names and descriptions; the general issue lifecycle uses `state:*` labels, but their exact names may change.

## Scope and authorization

For a specific issue, assess it when requested. For batch triage, first show the issue count and a sample of titles and obtain explicit authorization before posting comments or changing labels on multiple issues. Do not infer that a label alone authorizes bulk changes.

Do not apply an acceptance state, place issues on the roadmap, or make a product investment decision. Do not introduce `agent:*` workflow labels. Follow `SECURITY.md` if the report may disclose a vulnerability; do not copy sensitive details into a public comment.

## Assess one issue

1. Run `gh issue view <id> --json number,title,body,state,labels,author,comments`. Inspect the current `state:*` label definitions with `gh label list`. Check for previous triage, new human evidence, an existing owner, and duplicate issues.
2. Confirm the User Story attests that the human operator personally uses OpenShell and directly encountered the problem or needs the feature for a specific use case. If this is absent, request that first-hand context; do not invent it. Check the Problem Statement, impact, workaround and its limits, and observable acceptance criteria.
3. For bugs, verify reproduction steps using only OpenShell deployments. Do not install third-party tools solely to demonstrate reproducibility. Check the OpenShell version and relevant deployment details. For features, check the user-facing workflow and alternatives. Consider applicable middleware, interceptors, providers, and other extension points; prefer an applicable extension when it satisfies the use case, and do not dismiss it merely because it runs another service.
4. For proposed configuration, CLI, SDK, or other UX changes, request notional examples of the suggested interaction if missing. Keep the issue framed entirely in terms of OpenShell.
5. Reproduce or investigate enough to distinguish a confirmed bug, feasible feature, missing evidence, duplicate, already-fixed behavior, or expected behavior. State what was observed and what remains uncertain. Do not turn a failed reproduction attempt alone into a dismissal.
6. Post a concise comment beginning with `> **📋 triage-agent**`. Explain the evidence, any exact missing information, and the next human decision. Apply the appropriate current `state:*` label for the assessment outcome only after checking repository definitions. Leave acceptance and roadmap decisions to a maintainer.

If substantial technical uncertainty remains, recommend `create-spike` with specific questions to answer. A direct user request can separately authorize planning or implementation through `build-from-issue`; it does not change the issue's recorded disposition.
