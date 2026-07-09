# Brainstorm: Warm Pool Feasibility Study for OpenShell

**Date:** 2026-07-09
**Status:** active

## Problem Framing

OpenShell's Kubernetes driver creates a fresh `agents.x-k8s.io` Sandbox CR for every sandbox request. This cold-start path pays for pod scheduling, image pull, init container execution, supervisor startup, and gateway registration on every create. Measured latency is 8-12 seconds. For agent harnesses like OpenClaw that create sandboxes per tool call or per sub-agent, this is unusable.

The upstream Agent Sandbox project (kubernetes-sigs/agent-sandbox, v0.5.0, v1beta1 API) provides extension CRDs for warm pooling: SandboxTemplate, SandboxWarmPool, and SandboxClaim. OpenShell does not use any of these today. The Kubernetes driver has no awareness of the extension API group `extensions.agents.x-k8s.io`.

This feasibility study measures whether warm pooling can reduce sandbox startup latency to under 2 seconds on OpenShift, and produces a recommendation for how OpenShell should integrate warm pooling into its architecture.

## Approaches Considered

### A: Measure Raw Agent Sandbox Warm Pooling (Without OpenShell)

Deploy the Agent Sandbox extension CRDs on OpenShift, create warm pools with vanilla containers, and measure claim-to-ready latency. This isolates the Kubernetes layer from OpenShell overhead.

- Pros: Fast to set up, answers the fundamental feasibility question, no code changes required
- Cons: Does not account for OpenShell supervisor, identity binding, or policy injection

### B: Measure OpenShell End-to-End with Code Changes

Modify the OpenShell Kubernetes driver to create SandboxClaims instead of direct Sandbox CRs, then measure end-to-end latency.

- Pros: Realistic numbers that include all OpenShell overhead
- Cons: Requires significant code changes before any measurement, high risk of wasted effort if the raw K8s layer is already too slow

### C: Layered Approach (A then B)

Start with raw Agent Sandbox measurements (no OpenShell code changes), then layer on OpenShell-specific concerns (supervisor sidecar, identity injection, readiness patterns) incrementally.

- Pros: Answers feasibility fast, builds understanding incrementally, each layer adds data
- Cons: More phases to execute

## Decision

**Approach C: Layered measurement.** Start with raw Agent Sandbox warm pooling on OpenShift to establish a baseline, then progressively add OpenShell-specific complexity. This avoids wasting effort on code changes if the underlying Kubernetes primitives can't deliver acceptable latency.

## Key Requirements

1. **Fresh ROSA HCP cluster** provisioned via the ROSA plugin for consistent, isolated measurements
2. **Red Hat build of Agent Sandbox operator** (tech preview) installed from OperatorHub for the extension CRDs
3. **OpenShell deployed via the OpenShift deploy chart** (github.com/2000krysztof/Openshell-Openshift-Deploy) for fast setup
4. **Baseline cold-start measurements** (vanilla sandbox creation, no pooling) as the control
5. **Warm pool measurements** with varying configurations (readiness probe intervals, Pod Readiness Gates, sidecar readiness patterns)
6. **Health check optimization experiments** including Knative-style readiness wrapping and KEP-580 Pod Readiness Gates
7. **Results document** with measured data, phase-by-phase breakdown, and architectural recommendations for OpenShell warm pool integration
8. **Scope: Kubernetes only.** Podman/Docker single-player warm pooling is out of scope.

## Experiment Phases

This study decomposes into three execution phases, each with its own brainstorm document:

| Phase | Brainstorm | What it covers |
|-------|------------|----------------|
| 1 | 02-cluster-setup | ROSA cluster provisioning, Agent Sandbox operator, OpenShell deployment |
| 2 | 03-warm-pool-measurements | Cold-start baseline, warm pool experiments, health check optimization |
| 3 | 04-results-and-recommendations | Data synthesis, OpenShell architecture recommendations |

## Open Questions

- Does the Red Hat Agent Sandbox operator tech preview include the extension CRDs (SandboxWarmPool, SandboxClaim, SandboxTemplate), or only the core Sandbox CRD?
- Does env var injection at SandboxClaim time trigger a cold start, or can the `envVarsInjectionPolicy` on SandboxTemplate enable true warm adoption with claim-time injection?
- Is KEP-753 (native sidecar containers) available on the target OpenShift version (needs K8s 1.33+ / OpenShift 4.20+)?
- What is the minimum OpenShift version that supports both the Agent Sandbox operator tech preview and native sidecar containers?
