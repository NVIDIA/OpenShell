---
authors:
  - "@rhuss"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/issues/2157
---

# RFC NNNN - Warm Pool Feasibility Study

## Summary

This RFC documents the findings of a feasibility study for warm-pooling
sandbox pods in OpenShell's Kubernetes driver. The study evaluates whether
pre-provisioned, idle sandbox pods can reduce sandbox startup latency from
the current 8-12s cold-start baseline to under 2s, and identifies the
architectural changes required to adopt warm pooling in production.

The study covers claim latency measurements, health check tuning, environment
variable injection behavior, identity binding constraints, and integration
points with the Agent Sandbox operator's `SandboxWarmPool` CRD.

## Motivation

OpenShell's Kubernetes driver provisions a fresh sandbox pod for every
`sandbox.create` request. On a typical cluster, this cold-start path takes
8-12s (image pull excluded), which is too slow for interactive agent workflows
where sub-second tool calls are the norm. Agents that create sandboxes
mid-conversation force the user to wait, breaking flow and limiting the
viability of ephemeral sandbox patterns.

Warm pooling addresses this by maintaining a pool of pre-provisioned,
ready-to-claim sandbox pods. When a sandbox is requested, the driver claims
an existing pod from the pool instead of creating one from scratch. The pool
controller replenishes claimed pods in the background, keeping idle capacity
available for the next request.

The Agent Sandbox operator already ships a `SandboxWarmPool` CRD (Tech Preview)
that implements pool lifecycle management, including replenishment, health
checks, and idle eviction. This study evaluates whether that CRD meets
OpenShell's requirements or whether gaps exist that would block adoption.

### Why now

- Issue [#2157](https://github.com/NVIDIA/OpenShell/issues/2157) tracks the
  warm pool integration as a concrete feature request.
- The Agent Sandbox operator's `SandboxWarmPool` CRD reached Tech Preview in
  operator version TBD, making it available for evaluation.
- Multiple users have reported cold-start latency as a blocker for
  interactive agent workflows.

## Non-goals

- **Pool autoscaling.** This study evaluates fixed-size pools. Autoscaling
  based on demand signals is a separate concern.
- **Multi-cluster pooling.** Pools are cluster-local. Cross-cluster pool
  federation is out of scope.
- **Non-Kubernetes drivers.** Warm pooling applies only to the Kubernetes
  compute driver. Docker and VM drivers have different startup
  characteristics.
- **Image pre-pull optimization.** Image pull latency is excluded from
  measurements. Pre-pull is a separate optimization (DaemonSet or operator
  feature).
- **GPU resource pooling.** GPU-attached sandbox pooling has different
  economics and constraints. This study covers CPU-only pools.

## Experiment Setup

All measurements were collected on a single cluster with the following
configuration:

| Parameter | Value |
|-----------|-------|
| Cluster type | TBD |
| Kubernetes version | TBD |
| Agent Sandbox operator version | TBD |
| OpenShell version | TBD (commit hash) |
| Node count | TBD |
| Node instance type | TBD |
| Sandbox image | TBD |
| Image pre-pulled | Yes / No |
| Pool size | TBD |
| Measurement tool | TBD |
| Sample count per measurement | TBD |

### Pool Configuration

```yaml
# SandboxWarmPool CRD configuration used for measurements
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxWarmPool
metadata:
  name: warm-pool-feasibility
spec:
  templateRef:
    name: openshell-warm
  replicas: TBD
```

## Results

### Cold-Start Baseline

Baseline measurements without warm pooling, from `sandbox.create` request
to sandbox ready.

| Metric | Value |
|--------|-------|
| p50 latency | TBD |
| p90 latency | TBD |
| p99 latency | TBD |
| Min | TBD |
| Max | TBD |
| Sample count | TBD |

### Warm Pool Claim Latency

Time from `sandbox.create` request to sandbox ready when claiming from a
warm pool.

| Metric | Value |
|--------|-------|
| p50 latency | TBD |
| p90 latency | TBD |
| p99 latency | TBD |
| Min | TBD |
| Max | TBD |
| Sample count | TBD |

### Comparison

| Scenario | p50 | p90 | Speedup |
|----------|-----|-----|---------|
| Cold start (no pool) | TBD | TBD | baseline |
| Warm pool claim | TBD | TBD | TBD |
| Target | < 2s | < 2s | > 4x |

### Pool Drain Behavior

Measurements under sustained load when the pool is fully drained and
requests fall back to cold-start provisioning.

| Scenario | p50 | p90 |
|----------|-----|-----|
| Pool available (steady state) | TBD | TBD |
| Pool drained (fallback to cold start) | TBD | TBD |
| Pool replenishment time (per pod) | TBD | TBD |

## Health Check Analysis

### Probe Configuration Impact

How different readiness probe configurations affect claim latency and
pool stability.

| Probe interval | Initial delay | Failure threshold | Claim latency p50 | False-positive eviction rate |
|----------------|---------------|-------------------|--------------------|------------------------------|
| TBD | TBD | TBD | TBD | TBD |
| TBD | TBD | TBD | TBD | TBD |
| TBD | TBD | TBD | TBD | TBD |

### Readiness Gates

Whether the `SandboxWarmPool` CRD supports custom readiness gates and how
they interact with the sandbox supervisor's startup sequence.

| Question | Finding |
|----------|---------|
| Does SandboxWarmPool support readiness gates? | TBD |
| Can the supervisor signal readiness via a gate? | TBD |
| Does gate-based readiness reduce claim latency? | TBD |

### Sidecar Pattern

Whether the pool controller supports sidecar containers and how they
affect pool pod lifecycle.

| Question | Finding |
|----------|---------|
| Are sidecar containers preserved on claim? | TBD |
| Can the privacy router run as a sidecar? | TBD |
| Does the sidecar pattern affect replenishment time? | TBD |

## Environment Variable Injection

### Injection Behavior

How environment variables are injected into claimed pool pods, and
whether late-binding (post-claim injection) is supported.

| Question | Finding |
|----------|---------|
| Are env vars set at pool creation or claim time? | TBD |
| Can env vars be injected/overridden at claim time? | TBD |
| Are secrets mounted or injected as env vars? | TBD |
| Is there a mutation webhook for late binding? | TBD |

### Policy Requirements

Environment variables required by the sandbox policy engine and whether
they can be late-bound.

| Variable | Purpose | Can be late-bound? |
|----------|---------|--------------------|
| `OPENSHELL_GATEWAY_URL` | Gateway callback URL | TBD |
| `OPENSHELL_SANDBOX_ID` | Sandbox identity | TBD |
| `OPENSHELL_AUTH_TOKEN` | Sandbox authentication | TBD |
| `OPENSHELL_POLICY_*` | Policy configuration | TBD |

### Identity Binding Constraints

How sandbox identity (sandbox ID, auth tokens, mTLS certificates) is
bound to a claimed pod. Identity must be unique per sandbox session and
cannot be shared across pool members.

| Constraint | Approach | Feasible? |
|------------|----------|-----------|
| Unique sandbox ID per session | TBD | TBD |
| Per-session auth token | TBD | TBD |
| mTLS certificate rotation on claim | TBD | TBD |
| Gateway store registration timing | TBD | TBD |

## Architecture Recommendations

### Kubernetes Driver Changes

Changes required in `crates/openshell-driver-kubernetes/` to support
warm pool claiming instead of pod creation.

- **Pool-aware provisioning path.** TBD: How the driver detects pool
  availability and switches from create to claim.
- **Claim API integration.** TBD: Which operator API the driver calls
  to claim a pod from the pool.
- **Fallback behavior.** TBD: What happens when the pool is empty.
- **Pool selection.** TBD: How the driver selects the correct pool when
  multiple pools exist (e.g., different resource profiles).

### Supervisor Changes

Changes required in `crates/openshell-sandbox/` to support late-binding
of identity and configuration on a pre-provisioned pod.

- **Deferred initialization.** TBD: Whether the supervisor can defer
  policy loading until claim-time env vars are available.
- **Identity rebinding.** TBD: How the supervisor acquires a new identity
  after being claimed from the pool.
- **Health check endpoint.** TBD: Whether a lightweight health endpoint
  is needed for pool readiness probes.

### Gateway Store Changes

Changes required in the gateway's sandbox store to support the claim
lifecycle.

- **Registration timing.** TBD: When the gateway registers the sandbox
  in its store (at claim time, not pool creation time).
- **Pool metadata.** TBD: Whether the gateway needs to track pool
  membership for cleanup.

### Identity Binding Mechanism

The recommended approach for binding sandbox identity to a claimed pod.

- TBD: Recommended mechanism (env var injection, config file mount,
  API callback, or combination).
- TBD: Security properties (token rotation, certificate lifecycle).
- TBD: Operator support level for the chosen mechanism.

### Recommendation for Issue #2157

Based on the findings above, the recommended path forward for
[#2157](https://github.com/NVIDIA/OpenShell/issues/2157).

- TBD: Whether warm pooling is feasible with the current operator.
- TBD: Whether the sub-2s target is achievable.
- TBD: Recommended implementation phases.
- TBD: Estimated effort and timeline.

## Gaps and Risks

### Missing Agent Sandbox Operator Features

Features that the `SandboxWarmPool` CRD does not currently support but that
OpenShell requires for production use.

| Gap | Severity | Workaround |
|-----|----------|------------|
| TBD | TBD | TBD |
| TBD | TBD | TBD |

### Red Hat Tech Preview Coverage

Areas where the Tech Preview designation limits production adoption.

| Limitation | Impact |
|------------|--------|
| TBD | TBD |
| TBD | TBD |

### Pool Replenishment Under Burst

Risk of pool exhaustion under burst traffic and the resulting fallback
to cold-start latency.

| Scenario | Pool drain time | Recovery time | User impact |
|----------|-----------------|---------------|-------------|
| TBD | TBD | TBD | TBD |

### Other Risks

- **Idle resource cost.** Warm pool pods consume cluster resources while
  idle. The cost-benefit tradeoff depends on pool size and claim
  frequency.
- **Stale pods.** Long-lived idle pods may accumulate stale state
  (expired certificates, outdated images). Eviction and rotation
  policies are needed.
- **Operator version coupling.** Tight coupling to a specific operator
  version may limit OpenShell's deployment flexibility.

## Alternatives

### Do nothing

Keep the current cold-start provisioning path. Users accept 8-12s
startup latency. This is unacceptable for interactive agent workflows
but acceptable for batch or long-running sandbox use cases.

### Pre-warm at the container runtime level

Use container runtime features (e.g., checkpoint/restore with CRIU) to
snapshot a ready sandbox container and restore it on demand. This avoids
the pool management overhead but requires runtime-specific support and
may not preserve network state correctly.

### Client-side sandbox reuse

Instead of creating a new sandbox per tool call, reuse an existing
sandbox across multiple tool invocations within the same agent session.
This reduces the number of cold starts but does not eliminate them and
changes the sandbox isolation model.

## Prior Art

- **Knative cold-start mitigation.** Knative maintains a configurable
  minimum replica count to avoid cold starts for serverless workloads.
  The warm pool pattern is analogous.
- **AWS Lambda SnapStart.** Lambda's SnapStart pre-initializes function
  instances and restores from snapshots. Similar in intent but uses
  checkpoint/restore rather than pool management.
- **Agent Sandbox operator SandboxWarmPool CRD.** The operator's own pool
  implementation, which this study directly evaluates.

## Open Questions

- What is the minimum pool size required to sustain a typical interactive
  agent workload without pool drain?
- Can the operator's claim API be called directly from the Kubernetes
  driver, or does it require going through an admission webhook?
- How does the pool controller handle node failures that take pool pods
  with them?
- Is there a mechanism to pre-configure pool pods with a base policy
  that gets specialized at claim time?
- What is the operator's roadmap for moving `SandboxWarmPool` from Tech
  Preview to GA?

## Next Steps

### Upstream Contributions

- TBD: Features or fixes to contribute to the Agent Sandbox operator.

### Internal Work Items

- TBD: OpenShell issues to file for implementing warm pool support.

### Concrete Action Items

1. TBD: Complete measurements on the test cluster.
2. TBD: Validate identity binding approach with the operator team.
3. TBD: Prototype the claim path in the Kubernetes driver.
4. TBD: Update this RFC with findings and recommendations.
5. TBD: Present findings to the team for review.
