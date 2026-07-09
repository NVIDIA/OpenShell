# Tasks: Warm Pool Feasibility Study

**Input**: Design documents from `specs/001-warm-pool-feasibility/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, quickstart.md

**Tests**: Not applicable (feasibility study with manual experiment validation).

**Organization**: Tasks are grouped by user story from spec.md. US1 and US2 are P1 (core feasibility), US3-US4 are P2 (optimization experiments), US5 is P1 (deliverable).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Cluster provisioning, operator installation, and shared tooling

- [ ] T001 Provision ROSA HCP cluster with 3x m5.2xlarge workers using AAET profile (via `rosa create cluster` CLI or the `rosa:create` Claude Code skill)
- [ ] T002 Install Red Hat Agent Sandbox operator from OperatorHub (fallback: apply upstream `manifest.yaml` + `extensions.yaml` from kubernetes-sigs/agent-sandbox v0.5.0)
- [ ] T003 Verify all four CRDs are registered: Sandbox, SandboxTemplate, SandboxWarmPool, SandboxClaim via `kubectl api-resources | grep agents`
- [ ] T004 Deploy OpenShell on the cluster using the OpenShift deploy wrapper (github.com/2000krysztof/Openshell-Openshift-Deploy)
- [ ] T005 Validate cold-start sandbox creation works end-to-end via `openshell sandbox create --from base`
- [X] T006 Create image pre-pull DaemonSet to pre-pull sandbox images on all worker nodes in `experiments/manifests/image-prepull-daemonset.yaml`
- [ ] T007 Apply pre-pull DaemonSet and verify images are cached on all 3 nodes

**Checkpoint**: Cluster running, operator installed, OpenShell functional, images pre-pulled

---

## Phase 2: Foundational (Measurement Library)

**Purpose**: Shared measurement infrastructure that all experiments depend on

- [X] T008 Create `experiments/` directory structure per plan.md project structure
- [X] T009 Implement shared measurement functions (timestamp capture, CSV output, pod event collection) in `experiments/lib/common.sh`
- [X] T010 Implement pod readiness wait with configurable timeout in `experiments/lib/wait-ready.sh`
- [X] T011 [P] Create SandboxTemplate manifest for warm pool experiments in `experiments/manifests/sandbox-template.yaml`
- [X] T012 [P] Create SandboxWarmPool manifest (5 replicas, configurable readiness) in `experiments/manifests/warm-pool.yaml`
- [X] T013 [P] Create SandboxClaim manifest template (with/without env vars) in `experiments/manifests/sandbox-claim.yaml`

**Checkpoint**: Measurement library ready, manifests templated. Experiment scripts can now be built.

---

## Phase 3: User Story 1 - Measure Cold-Start Baseline (Priority: P1) MVP

**Goal**: Establish cold-start sandbox creation latency with per-phase breakdown as the control measurement.

**Independent Test**: Run 10+ sandboxes on the cluster and verify CSV output contains per-phase timestamps with computed p50/p90.

- [X] T014 [US1] Implement cold-start measurement script that creates sandboxes via `openshell sandbox create --from base`, captures per-phase timestamps (scheduled, image pulled, init complete, supervisor ready, SSH available), and outputs CSV in `experiments/measure-cold-start.sh`
- [ ] T015 [US1] Run Experiment 1a: 10 cold-start runs with pre-pulled images, save results to `experiments/results/cold-start-prepulled.csv`
- [ ] T016 [US1] Run Experiment 1b: 5 cold-start runs without pre-pulled images, save results to `experiments/results/cold-start-noprepull.csv`
- [ ] T017 [US1] Run Experiment 1c: 10 vanilla Agent Sandbox creates (no OpenShell) to isolate OpenShell overhead, save results to `experiments/results/cold-start-vanilla.csv`
- [ ] T018 [US1] Compute p50/p90 latencies for all three cold-start configurations and create summary table

**Checkpoint**: Cold-start baseline established with per-phase breakdown.

---

## Phase 4: User Story 2 - Measure Warm Pool Claim Latency (Priority: P1)

**Goal**: Measure raw warm pool claim-to-ready latency across probe configurations. Core feasibility answer.

**Independent Test**: Create SandboxTemplate + SandboxWarmPool, issue SandboxClaims, verify claim-to-ready CSV output with latency data.

- [X] T019 [US2] Implement warm pool measurement script that creates SandboxClaims against a running warm pool, captures claim-to-ready timestamps, and outputs CSV in `experiments/measure-warm-pool.sh`
- [ ] T020 [US2] Deploy SandboxWarmPool with 5 replicas and verify all replicas reach provisioned state
- [ ] T021 [US2] Run Experiment 2a: 10 claims with default readiness probes (10s periodSeconds), save results to `experiments/results/warm-pool-default.csv`
- [ ] T022 [US2] Run Experiment 2b: 10 claims with aggressive readiness probes (1s periodSeconds), save results to `experiments/results/warm-pool-aggressive.csv`
- [ ] T023 [US2] Run Experiment 2c: 5 simultaneous claims to measure burst behavior and pool replenishment, save results to `experiments/results/warm-pool-burst.csv`
- [ ] T024 [US2] Document pool exhaustion behavior: what happens when all replicas are claimed
- [ ] T025 [US2] Compute p50/p90 for all warm pool configurations and create comparison table vs cold-start

**Checkpoint**: Core feasibility question answered. Warm pool claim-to-ready latency measured.

---

## Phase 5: User Story 3 - Test Health Check Optimization Patterns (Priority: P2)

**Goal**: Test Pod Readiness Gates and sidecar readiness as alternatives to polling-based probes.

**Independent Test**: Deploy pods with ReadinessGate conditions and sidecar containers, measure condition-flip-to-Ready latency.

- [X] T026 [P] [US3] Create pod manifest with custom ReadinessGate condition (`sandbox.openshell.io/claimed`) in `experiments/manifests/readiness-gate-pod.yaml`
- [X] T027 [P] [US3] Implement sidecar readiness binary (Go, HTTP 503/200, signal file watch) in `experiments/sidecar/main.go`
- [X] T028 [P] [US3] Create Dockerfile for sidecar binary (multi-stage, scratch base) in `experiments/sidecar/Dockerfile`
- [ ] T029 [US3] Build and push sidecar readiness image to ghcr.io via `experiments/sidecar/Makefile`
- [X] T030 [US3] Create sidecar readiness pod manifest (init container with restartPolicy: Always, shared emptyDir) in `experiments/manifests/sidecar-readiness.yaml`
- [X] T031 [US3] Implement readiness gate measurement script that patches ReadinessGate condition and measures flip-to-Ready latency in `experiments/measure-readiness-gates.sh`
- [X] T032 [US3] Implement sidecar readiness measurement script that triggers signal file and measures flip-to-Ready latency in `experiments/measure-sidecar-readiness.sh`
- [ ] T033 [US3] Run Experiment 3a: 10 readiness gate measurements, save to `experiments/results/readiness-gates.csv`
- [ ] T034 [US3] Run Experiment 3b: 10 sidecar readiness measurements, save to `experiments/results/sidecar-readiness.csv`
- [ ] T035 [US3] Create comparison table: default probes vs aggressive probes vs readiness gates vs sidecar pattern

**Checkpoint**: Health check optimization patterns validated with latency data.

---

## Phase 6: User Story 4 - Test Claim-Time Environment Injection (Priority: P2)

**Goal**: Determine whether SandboxClaim env var injection triggers cold start or adopts warm sandbox.

**Independent Test**: Create SandboxTemplate with `envVarsInjectionPolicy: Allowed`, issue SandboxClaim with env vars, observe warm adoption.

- [X] T036 [US4] Update SandboxTemplate manifest with `envVarsInjectionPolicy: Allowed` variant in `experiments/manifests/sandbox-template.yaml`
- [X] T037 [US4] Implement env var injection measurement script in `experiments/measure-env-injection.sh`
- [ ] T038 [US4] Run Experiment 5a: 5 claims with env vars and Allowed policy, verify warm adoption, save to `experiments/results/env-injection-allowed.csv`
- [ ] T039 [US4] Run Experiment 5b: Document behavior with Disallowed policy (rejection vs cold fallback)
- [X] T040 [US4] Implement combined measurement script (best readiness pattern + env injection) in `experiments/measure-combined.sh`
- [ ] T041 [US4] Run Experiment 6: 10 combined measurements, save to `experiments/results/combined.csv`

**Checkpoint**: Env var injection behavior conclusively documented. Combined best-case latency measured.

---

## Phase 7: User Story 5 - Produce Results RFC (Priority: P1)

**Goal**: Compile all measurement data into a structured RFC with architectural recommendations.

**Independent Test**: RFC contains raw data tables, per-configuration comparisons, and a clear recommendation for OpenShell warm pool integration.

- [X] T042 [US5] Create RFC directory structure `rfc/NNNN-warm-pool-feasibility/README.md` (number TBD by maintainers, use placeholder)
- [ ] T043 [US5] Write RFC Executive Summary section: can warm pooling hit sub-2s? What is the dominant bottleneck?
- [ ] T044 [US5] Write RFC Experiment Setup section: cluster config, operator version, OpenShell version, image pre-pull status
- [ ] T045 [US5] Write RFC Results section: compile all CSV data into p50/p90 tables per configuration with comparison charts
- [ ] T046 [US5] Write RFC Health Check Analysis section: probe interval impact, readiness gates performance, sidecar pattern performance
- [ ] T047 [US5] Write RFC Env Var Injection section: injection behavior, policy requirements, identity binding constraints
- [ ] T048 [US5] Write RFC Architecture Recommendations section: Kubernetes driver changes, supervisor changes, gateway store changes, identity binding mechanism, Issue #2157 recommendation
- [ ] T049 [US5] Write RFC Gaps and Risks section: missing Agent Sandbox extension features, Red Hat TP coverage gaps, pool replenishment under burst
- [ ] T050 [US5] Write RFC Next Steps section: upstream contributions, internal work items, concrete action items

**Checkpoint**: RFC complete, ready for review.

---

## Phase 8: Polish & Teardown

**Purpose**: Cleanup, validation, and cluster teardown

- [ ] T051 Validate all CSV result files exist and contain expected number of runs
- [ ] T052 Review RFC for completeness: all required sections present, data tables populated, recommendation clear
- [ ] T053 Tear down ROSA HCP cluster via `rosa:delete warm-pool-study`

---

## Dependencies

```text
Phase 1 (Setup)
  └── Phase 2 (Measurement Library)
        ├── Phase 3 (US1: Cold-Start Baseline) ─── MVP
        │     └── Phase 4 (US2: Warm Pool Claims)
        │           ├── Phase 5 (US3: Health Check Optimization) ──┐
        │           └── Phase 6 (US4: Env Var Injection) ──────────┤
        │                                                          └── Phase 7 (US5: Results RFC)
        │                                                                └── Phase 8 (Teardown)
```

**Critical path**: Setup → Library → Cold-Start → Warm Pool → Health Check Optimization → RFC → Teardown

**Parallel opportunities**:
- US3 and US4 can run in parallel after US2 completes
- Within US3: readiness gate manifest (T026), sidecar binary (T027), and sidecar Dockerfile (T028) can be built in parallel
- Within US2: warm pool deployment (T020) can begin while measurement script (T019) is being written

## Implementation Strategy

**MVP**: Phases 1-4 (Setup + Library + Cold-Start Baseline + Warm Pool Claims). This answers the core feasibility question: can warm pooling deliver sub-2s latency on OpenShift?

**Full scope**: All 8 phases. The health check optimization and env var injection experiments refine the recommendation, and the RFC captures everything for the upstream community.

**Incremental delivery**: Each phase produces independently verifiable output (CSV data files). If the warm pool latency exceeds target in Phase 4, Phases 5-6 may pivot to investigating why rather than optimizing further.
