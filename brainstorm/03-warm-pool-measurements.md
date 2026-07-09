# Brainstorm: Baseline & Warm Pool Measurements

**Date:** 2026-07-09
**Status:** active
**Parent:** 01-warm-pool-feasibility

## Problem Framing

With the cluster running, we need a structured measurement plan that answers: how fast can we get a sandbox with warm pooling, and what are the bottlenecks? The measurements must cover cold-start baseline (control), raw Agent Sandbox warm pooling (no OpenShell), and progressively more realistic configurations that approximate what OpenShell would need.

The key unknowns are:
- What is the actual cold-start latency breakdown on OpenShift?
- Does warm pooling deliver sub-2s claim-to-ready?
- Is the readiness probe interval the dominant bottleneck, and can Pod Readiness Gates (KEP-580) or Knative-style readiness wrapping eliminate it?
- Can env vars be injected at claim time without triggering cold start?

## Approaches Considered

### A: Simple Before/After

Measure cold start, then warm pool, compare. Two data points.

- Pros: Fastest to execute
- Cons: No insight into what drives the latency, can't identify optimization levers

### B: Phase Breakdown with Configuration Matrix

Measure cold start with per-phase timestamps. Then measure warm pooling across a matrix of configurations (probe intervals, readiness gates, sidecar patterns, env var injection).

- Pros: Identifies specific bottlenecks, tests optimization hypotheses, actionable data
- Cons: More experiments to run, needs a measurement script

### C: Full Benchmark Suite with Statistical Rigor

N=50+ runs per configuration, p50/p90/p99, automated benchmark harness, CSV output for analysis.

- Pros: Publication-quality data, statistically meaningful
- Cons: Overkill for a feasibility study, takes days

## Decision

**Approach B: Phase breakdown with configuration matrix.** N=10-20 runs per configuration is enough to see the pattern. We need per-phase timestamps to identify bottlenecks, and we need the configuration matrix to test our optimization hypotheses (readiness gates, sidecar patterns). A simple shell script with `kubectl` timestamps is sufficient.

## Experiment Design

### Experiment 1: Cold-Start Baseline (Control)

Measure OpenShell sandbox creation latency without pooling. Captures the current state.

**What to measure:**
- Total time: `openshell sandbox create` to sandbox Ready
- Phase breakdown using `kubectl get events` and pod timestamps:
  - API call to pod Scheduled
  - Scheduled to image pulled (should be 0 with pre-pulled images)
  - Image pulled to init containers complete
  - Init containers complete to supervisor Ready
  - Supervisor Ready to SSH available

**Runs:** N=10 with pre-pulled images, N=5 without (to quantify image pull impact)

### Experiment 2: Vanilla Agent Sandbox Warm Pool (No OpenShell)

Measure raw Agent Sandbox warm pooling without OpenShell. This isolates Kubernetes overhead from OpenShell overhead.

**Setup:**
```yaml
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxTemplate
metadata:
  name: base-template
spec:
  sandbox:
    spec:
      containers:
      - name: agent
        image: ghcr.io/nvidia/openshell-community/sandboxes/base:latest
---
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxWarmPool
metadata:
  name: base-pool
spec:
  templateRef:
    name: base-template
  replicas: 5
```

**What to measure:**
- Pool fill time: SandboxWarmPool created to all 5 replicas Ready
- Claim-to-ready time: SandboxClaim created to adopted Sandbox transitioning to Ready
- Claim-to-ready with default readiness probe (10s periodSeconds)
- Claim-to-ready with aggressive readiness probe (1s periodSeconds)

**Runs:** N=10 per configuration

### Experiment 3: Pod Readiness Gates (KEP-580)

Test whether Pod Readiness Gates can replace polling-based readiness for faster claim-to-ready.

**How it works:**
- Add a custom ReadinessGate condition (e.g., `sandbox.openshell.io/claimed`) to the pod template
- Warm-pooled pods start with the condition missing (defaults to False, pod is NotReady)
- On claim, an external controller sets the condition to True via a pod status patch
- Pod transitions to Ready immediately (no probe interval wait)

**What to measure:**
- Time from condition patch to pod Ready status
- Compare with probe-based readiness at 1s and 10s intervals

**Runs:** N=10

**KEP-580 status:** GA since Kubernetes 1.14. Available on all OpenShift versions. No feature gate needed.

### Experiment 4: Sidecar Readiness Pattern

Test the Knative-style pattern where a sidecar controls pod readiness.

**How it works:**
- Define a supervisor-like sidecar (init container with `restartPolicy: Always`)
- Sidecar starts, runs a readiness HTTP endpoint that returns 503 (not ready)
- On claim, inject a signal (touch a file in a shared emptyDir, or set an env var)
- Sidecar detects the signal, flips readiness to 200
- Pod transitions to Ready

**What to measure:**
- Time from signal injection to sidecar readiness flip
- Time from sidecar readiness flip to pod Ready
- End-to-end claim-to-ready with sidecar pattern

**Runs:** N=10

**KEP-753 status (native sidecars):** GA since Kubernetes 1.33 (April 2025). Requires OpenShift 4.20+. Sidecar readiness probes contribute to pod readiness.

### Experiment 5: Env Var Injection at Claim Time

Test whether SandboxClaim env var injection works without forcing cold start.

**Setup:**
- SandboxTemplate with `envVarsInjectionPolicy: Allowed`
- SandboxClaim with env vars simulating OpenShell identity (OPENSHELL_SANDBOX_ID, OPENSHELL_ENDPOINT)

**What to measure:**
- Does the claim adopt a warm sandbox, or does it trigger cold start?
- If warm adoption works: claim-to-ready latency
- If cold start is triggered: document this as a constraint

**Runs:** N=5

### Experiment 6: Combined (Sidecar + Readiness Gates + Env Var Injection)

Combine the best-performing readiness pattern with env var injection. This approximates what a real OpenShell integration would look like.

**What to measure:**
- End-to-end claim-to-ready with the full stack
- Compare with cold-start baseline

**Runs:** N=10

## Measurement Script

A shell script that:
1. Creates a SandboxClaim with `kubectl apply`
2. Records the creation timestamp
3. Watches the pod status until Ready (or timeout)
4. Records the Ready timestamp
5. Calculates the delta
6. Collects pod events for phase breakdown
7. Outputs CSV: run_number, config, create_ts, ready_ts, delta_ms, phases

## Open Questions

- Can we use `kubectl wait --for=condition=Ready` with millisecond precision, or do we need a custom watcher?
- For the sidecar experiment, what's the simplest possible sidecar binary? A Go binary that listens on :8080 and watches for a file in /tmp/signal/?
- How does pool replenishment affect back-to-back claim latency? Should we measure burst patterns (claim 5 sandboxes simultaneously)?
- What happens when the pool is exhausted? Does SandboxClaim fall back to cold start or stay Pending?
