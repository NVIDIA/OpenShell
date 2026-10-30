---
name: review-security-issue
description: Review an authorized security issue or private GitHub advisory for validity, severity, and a remediation plan.
metadata:
  internal: true
---

# Review Security Issue

Review a security concern through its authorized private workflow. Do not file or expand a vulnerability in a public issue; follow `SECURITY.md`. A direct request to review authorizes review only, not remediation. For unattended review, verify authorization from maintainer direction and accessible discussion; for issues, also inspect current `state:*` label descriptions and assignments.

## Assess

1. Fetch the requested source. For a GHSA, use `gh api --method GET repos/OWNER/REPO/security-advisories/GHSA-ID` and read any supplied private discussion or fix links. The advisory payload does not include its discussion; report inaccessible prior discussion as unverified. For an issue, use `gh issue view <id> --json title,body,state,labels,comments` and follow Label Discovery in `CONTRIBUTING.md`; GHSA lifecycle states are not issue labels. Verify authorization and check whether a prior review already answers the request.
2. Check the required [advisory report format](../create-security-advisory/assets/advisory-template.md) and supporting reproduction or concrete code evidence. If either is missing, return a concise request for the missing sections or evidence before technical triage. Do not fill gaps with assumptions or treat scanner output as proof.
3. Inspect affected code and verify the claim. Assess impact, exploitability, prerequisites, affected surface, and a concrete attack scenario. Separate reported claims, code inspection, and reproduced results; check the attacker's existing authority and give a severity with rationale.
4. If actionable, propose a remediation plan with code areas, safe rollout, and focused tests. If not actionable, explain the evidence and recommended disposition. Do not decide product acceptance or silently close the issue.
5. Post the review or revision request only when the request authorizes posting. Begin the comment with `> **🔒 security-review-agent**` so later reviews can detect it. Keep sensitive details in the authorized private venue.

A human decides whether to authorize remediation. Route an authorized fix to `fix-security-issue`. Do not introduce `agent:*` workflow labels.
