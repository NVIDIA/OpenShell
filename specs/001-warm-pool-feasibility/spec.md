# Feature Specification: Warm Pool Feasibility Study

**Feature Branch**: `6111-warm-pool-feasibility`
**Created**: 2026-07-09
**Status**: Draft
**Input**: Evaluate Kubernetes Agent Sandbox warm pooling on OpenShift to determine whether sandbox startup latency can be reduced from 8-12 seconds to under 2 seconds, and produce architectural recommendations for OpenShell integration.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Measure Cold-Start Baseline on OpenShift (Priority: P1)

An engineer provisions a ROSA HCP cluster, deploys OpenShell with the Agent Sandbox operator, and measures the current cold-start sandbox creation latency with per-phase timestamps. This establishes the control measurement against which all warm pool experiments are compared.

**Why this priority**: Without a reliable baseline, no warm pool improvement can be quantified. This is the foundation for every subsequent experiment.

**Independent Test**: Can be tested by creating 10+ sandboxes on a clean cluster and recording timestamps from API call to SSH availability. Delivers a latency breakdown table.

**Acceptance Scenarios**:

1. **Given** a ROSA HCP cluster with OpenShell deployed via the OpenShell OpenShift deploy chart, **When** the engineer runs `openshell sandbox create --from base` 10 times with pre-pulled images, **Then** per-phase timestamps are captured (scheduled, image pulled, init complete, supervisor ready, SSH available) and p50/p90 latencies are computed.
2. **Given** the same cluster, **When** the engineer runs 5 sandbox creates without pre-pulled images, **Then** the image pull contribution to total latency is quantified separately.
3. **Given** the same cluster, **When** the engineer creates a vanilla Agent Sandbox (no OpenShell) 10 times, **Then** the OpenShell overhead vs. raw Kubernetes overhead is isolated.

---

### User Story 2 - Measure Warm Pool Claim Latency (Priority: P1)

An engineer creates a SandboxWarmPool with pre-provisioned pods, then measures the time from SandboxClaim creation to the claimed sandbox becoming Ready. Tests multiple readiness configurations to identify the dominant bottleneck.

**Why this priority**: This is the core feasibility question. If raw warm pool claim-to-ready latency exceeds the target, no amount of OpenShell optimization will help.

**Independent Test**: Can be tested by creating SandboxTemplate + SandboxWarmPool, then issuing SandboxClaims and measuring claim-to-ready timestamps. Delivers a configuration matrix with latency data.

**Acceptance Scenarios**:

1. **Given** a SandboxWarmPool with 5 pre-provisioned replicas using the base sandbox image, **When** a SandboxClaim is created, **Then** the claim-to-ready latency is measured with default readiness probe settings (10s periodSeconds).
2. **Given** the same pool, **When** a SandboxClaim is created with aggressive readiness probes (1s periodSeconds), **Then** the latency improvement over default probes is quantified.
3. **Given** the same pool, **When** 5 SandboxClaims are created simultaneously, **Then** burst claim behavior and pool replenishment time are measured.

---

### User Story 3 - Test Health Check Optimization Patterns (Priority: P2)

An engineer tests Pod Readiness Gates (KEP-580) and a Knative-style sidecar readiness pattern as alternatives to polling-based readiness probes, measuring whether they eliminate the probe interval bottleneck.

**Why this priority**: Our research identified the readiness probe interval as the dominant latency bottleneck. These optimization patterns could eliminate the bottleneck entirely, but need validation on OpenShift.

**Independent Test**: Can be tested by deploying pods with custom ReadinessGate conditions and sidecar containers, then measuring the time from condition/signal flip to pod Ready status.

**Acceptance Scenarios**:

1. **Given** a warm-pooled pod with a custom ReadinessGate condition (`sandbox.openshell.io/claimed`) set to False, **When** an external controller patches the condition to True, **Then** the time from patch to pod Ready is measured and recorded.
2. **Given** a warm-pooled pod with a sidecar container that controls readiness via an HTTP endpoint, **When** a signal file is created in a shared emptyDir volume, **Then** the sidecar flips its readiness response and the pod transitions to Ready within measured latency.
3. **Given** both patterns tested, **When** results are compared with probe-based readiness (1s and 10s), **Then** the relative improvement is quantified.

---

### User Story 4 - Test Claim-Time Environment Injection (Priority: P2)

An engineer tests whether SandboxClaim env var injection works without forcing a cold start, validating the mechanism OpenShell would use to bind identity to a pre-provisioned pod.

**Why this priority**: OpenShell needs to inject sandbox identity (ID, endpoint, credentials) at claim time. If env var injection triggers cold start, the warm pool advantage is lost and a different identity binding mechanism is needed.

**Independent Test**: Can be tested by creating a SandboxTemplate with `envVarsInjectionPolicy: Allowed` and a SandboxClaim with env vars, then observing whether the claim adopts a warm sandbox or creates a new one.

**Acceptance Scenarios**:

1. **Given** a SandboxTemplate with `envVarsInjectionPolicy: Allowed` and a SandboxWarmPool with 3 replicas, **When** a SandboxClaim is created with env vars (`OPENSHELL_SANDBOX_ID=test-123`), **Then** the claim adopts an existing warm sandbox (not cold start).
2. **Given** the same setup, **When** a SandboxClaim is created with env vars and `envVarsInjectionPolicy: Disallowed` on the template, **Then** the behavior (rejection or cold fallback) is documented.

---

### User Story 5 - Produce Results Document with Recommendations (Priority: P1)

An engineer compiles all measurement data into a structured report comparing cold-start vs. warm pool latencies across configurations, and produces architectural recommendations for how OpenShell should integrate warm pooling.

**Why this priority**: The deliverable. Without this document, the experiments have no impact on the OpenShell project direction.

**Independent Test**: Can be validated by checking that the document contains: raw data tables, per-configuration comparisons, a clear recommendation for Issue #2157, and concrete next steps for the OpenShell core team.

**Acceptance Scenarios**:

1. **Given** all experiments are complete, **When** the results RFC is written, **Then** it contains latency tables with p50/p90 for each configuration, a comparison chart, and a recommendation for the OpenShell integration approach.
2. **Given** the results RFC is complete, **Then** it is structured so a distilled summary can later be posted to GitHub Issue #2157 as a separate follow-up step.

---

### Edge Cases

- What happens when the warm pool is exhausted (all replicas claimed)? Does SandboxClaim fall back to cold start or stay Pending?
- What happens when a warm-pooled pod is on a node that goes NotReady during the experiment?
- How does pool replenishment interact with cluster autoscaler if nodes are at capacity?
- What if the Red Hat Agent Sandbox operator tech preview does not include extension CRDs? (Fallback: install upstream extensions.yaml manually)

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Engineer MUST be able to provision a ROSA HCP cluster with a Kubernetes version supporting native sidecar containers (K8s 1.33+)
- **FR-002**: Engineer MUST be able to install the Agent Sandbox operator with both core and extension CRDs on the cluster
- **FR-003**: Engineer MUST be able to deploy OpenShell on the cluster using the OpenShell OpenShift deploy wrapper and create cold-start sandboxes
- **FR-004**: Measurement scripts MUST capture per-phase timestamps (API call, scheduled, image pulled, init complete, and for OpenShell experiments: supervisor ready, SSH available)
- **FR-005**: Shell-based measurement scripts MUST produce CSV output with run number, configuration label, and per-phase timestamps
- **FR-006**: Engineer MUST be able to create SandboxTemplate, SandboxWarmPool, and SandboxClaim resources for warm pool experiments
- **FR-007**: Engineer MUST be able to configure Pod Readiness Gates on warm-pooled pods and flip them via kubectl patch
- **FR-008**: Engineer MUST be able to deploy a sidecar container with a controllable readiness endpoint for sidecar readiness experiments
- **FR-009**: Results MUST be published as a standalone RFC in `rfc/` containing raw latency data, configuration matrix, and architectural recommendations
- **FR-010**: The RFC MUST be self-contained so it can later be distilled into a GitHub Issue #2157 comment (posting is a separate follow-up step, not part of this study)

### Key Entities

- **ROSA HCP Cluster**: The test environment. Provisioned via ROSA plugin, us-east-2 region, AAET profile.
- **Agent Sandbox CRDs**: Sandbox (core), SandboxTemplate, SandboxWarmPool, SandboxClaim (extensions). The primitives being evaluated.
- **Measurement Run**: A single sandbox creation or claim with captured timestamps. N=10-20 per configuration.
- **Configuration**: A specific combination of settings (probe interval, readiness gate, sidecar pattern, env var injection) being tested.
- **Results RFC**: The final deliverable in `rfc/`, synthesizing all measurements into architectural recommendations.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Cold-start baseline latency is measured with per-phase breakdown for at least 10 runs with pre-pulled images and 5 runs without
- **SC-002**: Warm pool claim-to-ready latency is measured across at least 4 configurations (default probes, aggressive probes, readiness gates, sidecar pattern)
- **SC-003**: Each configuration has at least 10 measurement runs with p50 and p90 latencies computed
- **SC-004**: The env var injection experiment conclusively determines whether claim-time injection triggers cold start or not
- **SC-005**: The results document contains a clear, data-backed recommendation for which warm pool integration approach OpenShell should pursue
- **SC-006**: The results RFC contains all required sections (data tables, configuration comparisons, architectural recommendation, next steps) and is structured for later distillation into a GitHub Issue #2157 comment

## Clarifications

### Session 2026-07-09

- Q: What ROSA HCP cluster sizing should be used for the experiments? → A: 3 worker nodes, m5.2xlarge (8 vCPU, 32 GB each). Cluster is short-lived (tear down after experiments).
- Q: Where should the full results document be stored? → A: Standalone RFC in `rfc/` directory of the OpenShell repo.
- Q: What level of measurement automation is expected? → A: Shell scripts per experiment that wrap kubectl with timestamp capture (CSV output).
- Q: Should the study prioritize the Red Hat Agent Sandbox tech preview or upstream manifests? → A: Red Hat tech preview first, upstream manifests only as fallback.

## Assumptions

- A ROSA HCP cluster with OpenShift 4.20+ (K8s 1.33+) is available for provisioning via the AAET AWS profile
- The cluster uses 3 worker nodes of type m5.2xlarge (8 vCPU, 32 GB each) in us-east-2, provisioned as a short-lived experiment cluster
- The Red Hat Agent Sandbox operator tech preview is installable from OperatorHub (if not, upstream manifests are used as fallback)
- the OpenShell OpenShift deploy wrapper works with the target OpenShift version (may need minor adjustments)
- Pre-pulling images on worker nodes is sufficient to eliminate image pull latency from measurements
- The upstream Agent Sandbox v0.5.0 extension CRDs (v1beta1) are compatible with the Red Hat operator build
- Pod Readiness Gates (KEP-580, GA since K8s 1.14) work on OpenShift without additional configuration
- Native sidecar containers (KEP-753, GA since K8s 1.33) are available on the target OpenShift version
- This study is scoped to Kubernetes-backed sandboxes only; Podman/Docker single-player warm pooling is out of scope
