# Brainstorm: Results Document & OpenShell Recommendations

**Date:** 2026-07-09
**Status:** active
**Parent:** 01-warm-pool-feasibility

## Problem Framing

After the measurements are complete, we need to synthesize findings into a document that serves two audiences:

1. **The OpenShell core team**: What should OpenShell change to support warm pooling? Which approach from Issue #2157 is backed by data? What are the architectural constraints?
2. **The Red Hat integration team**: Is the upstream Agent Sandbox warm pooling viable for enterprise OpenShift deployments? What gaps exist in the Red Hat tech preview?

The document should be concrete enough to inform Issue #2157's design decisions.

## Approaches Considered

### A: Internal Technical Report

A detailed technical document with raw data, analysis, and recommendations. Shared internally and referenced in GitHub issue comments.

- Pros: Complete record, referenceable, can share selectively
- Cons: May be too dense for quick consumption

### B: GitHub Issue Comment + Summary Doc

Post key findings as a comment on Issue #2157 with a link to a detailed report. The comment is the "executive summary," the report is the appendix.

- Pros: Directly visible to the upstream community, invites discussion, keeps the issue alive
- Cons: GitHub comments are hard to update as understanding evolves

### C: Both (Report + Issue Comment)

Write the full report as a document, then distill key findings into a GitHub comment on #2157.

- Pros: Best of both, full technical depth plus community visibility
- Cons: Two artifacts to maintain

## Decision

**Approach C: Full report plus GitHub comment.** The report is published as a standalone RFC in `rfc/` (see clarification in spec.md). A distilled comment on #2157 can be posted as a follow-up step to share findings with the upstream community.

## Report Structure

### 1. Executive Summary
- One paragraph: can warm pooling hit sub-2s on OpenShift?
- Key finding: what is the dominant bottleneck?
- Recommendation: which integration path for OpenShell?

### 2. Experiment Setup
- Cluster configuration (OpenShift version, K8s version, node count, instance type)
- Agent Sandbox version and CRDs installed
- OpenShell version and deployment method
- Image pre-pull status

### 3. Results

#### Cold-Start Baseline
- Table: phase breakdown with p50/p90 latencies
- Chart: latency distribution

#### Warm Pool Results
- Table: configuration matrix with claim-to-ready latencies
- Comparison: default probes vs. aggressive probes vs. readiness gates vs. sidecar pattern
- Finding: which configuration achieves the target?

#### Health Check Analysis
- Readiness probe interval impact (10s vs. 1s)
- Pod Readiness Gates (KEP-580) performance
- Sidecar readiness pattern performance
- Knative-style comparison

#### Env Var Injection
- Does claim-time injection work without cold start?
- Which injection policy is needed?
- What can be injected (env vars) vs. what needs another mechanism (TLS certs, files)?

### 4. OpenShell Architecture Recommendations

Map findings to OpenShell's architecture:

- **Kubernetes driver changes:** What needs to change in `driver.rs` to support SandboxClaim creation?
- **Supervisor changes:** Should the supervisor become a native sidecar with late-bind identity?
- **Gateway store changes:** How should the gateway handle sandbox records for warm-pooled sandboxes?
- **Identity binding:** Which mechanism works (env var injection, volume projection, API call)?
- **Configuration surface:** Where should warm pool configuration live (driver config, workspace admin, operator)?
- **Issue #2157 recommendation:** Which of the four alternatives from the issue is best supported by data?
- **Issue #1447 comparison:** Native pool vs. upstream CRDs, with data backing

### 5. Gaps and Risks
- Missing features in the Agent Sandbox extension API (e.g., volumeClaimTemplates, Issue #453)
- Red Hat tech preview coverage gaps
- KEP-753 availability on the target OpenShift version
- Pool replenishment under burst load
- Identity isolation between warm slot reuse

### 6. Next Steps
- Concrete list of upstream contributions (issues, PRs, RFCs)
- Internal work items for the next sprint
- Follow-up actions for stakeholder discussions

## Key Requirements

1. **Report saved to the configured notes vault** with a date prefix
2. **RFC in `rfc/`** as the canonical, version-controlled results document
3. **No Google Drive links** in any public-facing artifacts
4. **Data tables with raw numbers**, not just qualitative assessments
5. **Clear recommendation** for the OpenShell core team, not just "it depends"

## Open Questions

- Should we also post findings to the upstream Agent Sandbox repo (e.g., as a discussion or issue comment on Issue #390)?
- Should the report include a proposed RFC outline for OpenShell warm pooling, or is that a separate step?
