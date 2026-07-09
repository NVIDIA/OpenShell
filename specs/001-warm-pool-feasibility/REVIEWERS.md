# Review Guide: Warm Pool Feasibility Study

**Generated**: 2026-07-09 | **Spec**: [spec.md](spec.md)

## Why This Change

OpenShell's Kubernetes driver creates a fresh Sandbox CR for every sandbox request, paying 8-12 seconds for pod scheduling, image pull, init container execution, supervisor startup, and gateway registration. For agent harnesses like OpenClaw that create sandboxes per tool call, this latency is unusable. The upstream Agent Sandbox project (v0.5.0) provides extension CRDs for warm pooling (SandboxTemplate, SandboxWarmPool, SandboxClaim), but OpenShell has no awareness of these. We need to know if warm pooling can deliver sub-2s sandbox startup on OpenShift before investing in integration work.

## What Changes

This study will create an `experiments/` directory with shell-based measurement scripts, Kubernetes manifests for warm pool configurations, and a minimal Go sidecar binary for readiness experiments. It will provision a short-lived ROSA HCP cluster, run 6 experiments measuring cold-start vs warm pool latency across readiness configurations, and produce an RFC in `rfc/` with data-backed architectural recommendations for OpenShell warm pool integration. No changes to OpenShell core code. This PR contains the specification artifacts only; implementation follows after spec approval.

## How It Works

The study uses a layered measurement approach across 4 execution phases:

1. **Cluster Setup**: ROSA HCP with 3x m5.2xlarge workers, Red Hat Agent Sandbox tech preview operator (upstream fallback), OpenShell via the OpenShell OpenShift deploy chart, and image pre-pulling via DaemonSet.

2. **Measurement Library**: Shared shell functions (`experiments/lib/common.sh`) for nanosecond timestamp capture, CSV output, pod event collection, and p50/p90 computation. Each experiment script wraps kubectl with these functions.

3. **Experiments**: Six experiments progressively build understanding:
   - Cold-start baseline (control measurement)
   - Warm pool claim-to-ready with default and aggressive readiness probes
   - Pod Readiness Gates (KEP-580) as probe-free alternative
   - Sidecar readiness pattern (Knative-style, using KEP-753 native sidecars)
   - Env var injection at claim time (identity binding feasibility)
   - Combined best-configuration measurement

4. **RFC**: Results compiled into a standalone RFC following the OpenShell RFC template, structured for later distillation into a GitHub Issue #2157 comment.

## When It Applies

**Applies when**:
- Evaluating whether OpenShell should adopt Agent Sandbox warm pooling
- Understanding sandbox startup latency bottlenecks on OpenShift
- Making architectural decisions about OpenShell's Kubernetes driver
- Informing Issue #2157 design discussions with measured data

**Does not apply when**:
- Podman/Docker single-player warm pooling (explicitly out of scope)
- Production OpenShell code changes (this is measurement-only, no core changes)
- Non-OpenShift Kubernetes distributions (results are OpenShift-specific)

## Key Decisions

1. **Layered measurement (no OpenShell code changes)**: Start with raw Agent Sandbox measurements, then layer OpenShell-specific concerns. Rejected "modify the Kubernetes driver first" because if the raw K8s layer is too slow, code changes would be wasted.

2. **Red Hat tech preview operator first, upstream fallback**: The tech preview may lack extension CRDs, but testing the downstream operator path is part of the study's value. Upstream manifests are applied on top only if needed.

3. **Shell scripts over Go benchmark harness**: N=10-20 per configuration is enough for a feasibility study. Shell scripts with `date +%s%N` and `kubectl wait` provide sufficient precision without over-engineering.

4. **Results as RFC (not Google Doc)**: The RFC template provides structured review and lives in the public repo. Google Docs are inaccessible to external contributors.

5. **3x m5.2xlarge workers**: Enough capacity for warm pool replicas and burst tests without hitting resource limits that would skew measurements. Short-lived cluster to control cost.

## Areas Needing Attention

- **Readiness probe interval assumption**: The brainstorm identifies the readiness probe interval as the dominant latency bottleneck. If this assumption is wrong (e.g., kubelet overhead dominates), the Readiness Gate and sidecar experiments may not show the expected improvement.
- **Env var injection behavior is undocumented**: The SandboxClaim `envVarsInjectionPolicy` behavior is based on reading the CRD spec, not tested behavior. The actual controller implementation may differ.
- **Sidecar readiness binary**: Building and pushing a custom container image adds complexity. If the sidecar experiment is not needed (readiness gates are sufficient), this work could be skipped.
- **RFC number assignment**: The OpenShell RFC process requires maintainer-assigned numbers from an originating issue. A placeholder number is used until assignment.

## Open Questions

- Does the Red Hat Agent Sandbox operator tech preview include extension CRDs, or only the core Sandbox CRD? (Answered by T002/T003 during setup.)
- What happens when the warm pool is exhausted? Does SandboxClaim stay Pending or fall back to cold start? (Answered by T024 during experiments.)
- Is the sidecar experiment necessary if Pod Readiness Gates already eliminate the probe interval bottleneck? (Decided after T033 results.)

## Review Checklist

- [ ] Key decisions are justified
- [ ] Measurement methodology is sound (N=10+, per-phase timestamps, CSV output)
- [ ] Scope boundaries are clear (no OpenShell core changes, K8s only)
- [ ] Success criteria are measurable (sub-2s target, p50/p90 computation)
- [ ] Cluster sizing is appropriate for experiment scope
- [ ] RFC structure follows the OpenShell RFC template
- [ ] No Google Drive links referenced in public-facing artifacts

## Revision History

### Rev 1 (2026-07-09) - Address Devin and CodeRabbit review feedback

**Trigger**: PR review feedback from [#2](https://github.com/rhuss/OpenShell/pull/2) (Devin, CodeRabbit)

**Spec changes**: None (all findings were in non-spec files)

**Non-spec fixes**:
- AGENTS.md: Restored original OpenShell agent instructions (was replaced entirely by spex plugin description)
- CLAUDE.md: Removed feature-specific SPECKIT block (should not be in committed version)
- quickstart.md: Removed hardcoded AWS account ID
- brainstorm/04: Replaced hardcoded Obsidian vault path with generic placeholder
- brainstorm/02: Added note about pinning deployment chart to a specific commit

**Quality gates**:
- review-spec: skipped (no spec changes)
- review-plan: skipped (no plan changes)

**Cascade impact**:
- plan.md: unchanged
- tasks.md: unchanged
- REVIEWERS.md: revision history appended

### Rev 2 (2026-07-09) - Address Copilot and Devin re-review feedback

**Trigger**: PR review feedback from [#2](https://github.com/rhuss/OpenShell/pull/2) (Copilot, Devin re-review)

**Spec changes**: None

**Non-spec fixes**:
- .gitignore: Narrowed `**/.claude/` to worktree-specific pattern to avoid blocking root `.claude/` tracked files
- quickstart.md: Fixed DaemonSet path to `experiments/manifests/`, clarified `rosa:create` as Claude Code skill wrapper with CLI equivalent
- tasks.md: Clarified T001 `rosa:create` wrapper reference
- checklists/requirements.md: Fixed self-assessment to accurately reflect technical spec content
- brainstorm/04: Aligned decision with RFC approach, removed individual names and meeting references
- REVIEWERS.md: Reworded "What Changes" to describe planned work (not present artifacts)

**Quality gates**:
- review-spec: skipped (no spec changes)
- review-plan: skipped (no plan changes)

**Cascade impact**:
- plan.md: unchanged
- tasks.md: T001 wording updated (no structural change)
- REVIEWERS.md: revision history appended, "What Changes" reworded

---

<!-- Code phase sections are appended below this line by the phase-manager command -->
