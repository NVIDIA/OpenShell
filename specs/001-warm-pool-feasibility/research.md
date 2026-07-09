# Research: Warm Pool Feasibility Study

## R1: ROSA HCP OpenShift Version Availability (K8s 1.33+)

**Decision**: Target OpenShift 4.20+ which ships K8s 1.33+, providing native sidecar containers (KEP-753 GA) and Pod Readiness Gates (KEP-580 GA since K8s 1.14).

**Rationale**: K8s 1.33 is required for native sidecar containers (init containers with `restartPolicy: Always`), which is needed for Experiment 4 (sidecar readiness pattern). OpenShift 4.20 maps to K8s 1.33. ROSA HCP versions are checked at provisioning time via `rosa list versions`.

**Alternatives considered**:
- OpenShift 4.19 (K8s 1.32): Missing native sidecar GA. Rejected because it would block Experiment 4.
- Kind/k3d local cluster: Faster but not representative of enterprise OpenShift. Rejected because the study specifically targets OpenShift compatibility.

## R2: Red Hat Agent Sandbox Operator (Tech Preview) Availability

**Decision**: Install the Red Hat Agent Sandbox tech preview from OperatorHub first. If extension CRDs (SandboxTemplate, SandboxWarmPool, SandboxClaim) are not included, apply upstream `extensions.yaml` from kubernetes-sigs/agent-sandbox v0.5.0.

**Rationale**: The tech preview may only include the core Sandbox CRD. The extension CRDs are in a separate API group (`extensions.agents.x-k8s.io/v1beta1`). Verification: `kubectl api-resources | grep agents` should list all four CRD types.

**Alternatives considered**:
- Upstream manifests only: Skips the operator path entirely. Rejected because testing the Red Hat operator is part of the study's value.
- Wait for Red Hat TP to include extensions: Unknown timeline, would block the study. Rejected.

## R3: Measurement Script Design

**Decision**: Shell scripts per experiment using `kubectl` with `date +%s%N` for nanosecond timestamps. Output to CSV with columns: `run,config,create_ts,ready_ts,delta_ms,phases`.

**Rationale**: Shell scripts are sufficient for N=10-20 per config. `kubectl wait --for=condition=Ready` provides clean blocking semantics. Phase timestamps are extracted from `kubectl get events --field-selector involvedObject.name=$POD` post-hoc.

**Alternatives considered**:
- Go benchmark harness with client-go watch: More precise but overkill for feasibility study. Rejected.
- Manual copy-paste: Error-prone with 10+ runs. Rejected.

## R4: RFC Format and Number Assignment

**Decision**: The results RFC will follow the OpenShell RFC template (`rfc/0000-template/README.md`). The RFC number must be assigned by maintainers from the originating GitHub issue. For this study, the RFC is created in `rfc/NNNN-warm-pool-feasibility/README.md` once a number is assigned.

**Rationale**: Per `rfc/README.md`, RFCs require an originating GitHub issue and maintainer-assigned number. The study results naturally fit the RFC structure (Summary, Motivation, Design, Alternatives).

**Alternatives considered**:
- Informal markdown report: Lacks the structured review process. Rejected because warm pool integration is a cross-cutting architectural decision.
- Google Doc: Prohibited from public repo references per CLAUDE.md. Rejected.

## R5: Sidecar Readiness Binary

**Decision**: Use a minimal Go binary for the sidecar readiness experiment. The binary serves HTTP on :8080, returns 503 until a signal file (`/tmp/signal/ready`) exists, then returns 200. Build as a static binary in a scratch container.

**Rationale**: Go produces small static binaries. The signal file mechanism (shared emptyDir volume) is simple to test. This mirrors the Knative queue-proxy pattern.

**Alternatives considered**:
- Python/bash sidecar: Requires larger base image (python/bash), slower startup. Rejected.
- gRPC readiness: More complex than needed for a readiness probe. Rejected.

## R6: Pool Exhaustion Behavior

**Decision**: Document the behavior when all warm pool replicas are claimed. Expected: SandboxClaim stays Pending until pool replenishes (based on upstream Agent Sandbox controller logic).

**Rationale**: This is an open question in the spec. The experiment will observe actual behavior. If fallback to cold start is available, it would be a useful feature for production.

**Alternatives considered**:
- Active testing with configured fallback: The v0.5.0 SandboxWarmPool spec may not support fallback configuration. Observation-only is the safe approach.
