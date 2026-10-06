---
name: review-security-issue
description: Review an authorized security issue for validity, severity, and a remediation plan.
metadata:
  internal: true
---

# Review Security Issue

Review a security concern through its authorized private workflow. Do not file or expand a vulnerability in a public issue; follow `SECURITY.md`. A direct request to review authorizes review only, not remediation. For unattended review, inspect current `state:*` label descriptions, maintainer assignments, and comments to verify that review is authorized.

## Assess

1. Fetch the issue and comments with `gh issue view <id> --json title,body,state,labels,comments`. Follow Label Discovery in `CONTRIBUTING.md` rather than assuming exact label names; resolve unclear meanings before interpreting authorization. Verify that this is an authorized security issue and that a prior review does not already answer the request.
2. Inspect affected code and verify the claim. Assess impact, exploitability, prerequisites, affected surface, and a concrete attack scenario. Separate evidence from assumptions and give a severity with rationale.
3. If actionable, propose a remediation plan with code areas, safe rollout, and focused tests. If not actionable, explain the evidence and recommended disposition. Do not decide product acceptance or silently close the issue.
4. Post the review only when the request authorizes posting. Begin the comment with `> **🔒 security-review-agent**` so later reviews can detect it. Keep sensitive details in the authorized private venue.

A human decides whether to authorize remediation. Route an authorized fix to `fix-security-issue`. Do not introduce `agent:*` workflow labels.
