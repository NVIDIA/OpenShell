---
authors:
  - "@rmalani-nv"
state: review
links:
  - https://github.com/NVIDIA/OpenShell/pull/1813
  - https://github.com/kubernetes-sigs/agent-sandbox/releases/tag/v0.4.6
  - https://github.com/kubernetes-sigs/agent-sandbox
  - https://agent-sandbox.sigs.k8s.io/docs/
---

# RFC 0005 - Warm-Pooled Sandboxes

## Summary

Add support for **warm-pooled sandboxes** on the Kubernetes compute driver by
adopting the upstream [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
warm-pool extension CRDs — `SandboxTemplate`, `SandboxWarmPool`, and
`SandboxClaim` (`extensions.agents.x-k8s.io/v1alpha1`). Instead of cold-starting
a `Sandbox` CR + Pod per request, the gateway claims a pre-provisioned, ready Pod
from a pool, cutting time-to-ready from seconds to milliseconds. The extensions
ship in the same `v0.4.6` release OpenShell already pins for the core `Sandbox`
CRD; OpenShell simply does not install or use them today.

## Motivation

Creating a Kubernetes sandbox today is a cold start: the gateway creates a
`Sandbox` CR, the agent-sandbox controller creates a Pod, the image is pulled (or
read from cache), the supervisor boots, and only then does the sandbox become
`Ready`. Measured locally this is ~4s+ even with the image preloaded. For
interactive agent workloads and high-churn "fresh sandbox per task" usage, that
latency dominates. A warm pool keeps N ready Pods standing by so a claim binds in
**~0.1s** (measured on a local spike).

## Non-goals

- Changing the default (cold) sandbox-create path. Warm pooling is additive and
  opt-in; sandboxes that don't match a pool fall back to a cold create.
- GPU warm pools in the initial rollout (idle accelerators are expensive — opt-in
  later, per pool).
- Migrating OpenShell's core `Sandbox` usage from `v1alpha1` to `v1beta1`. The
  pinned `v0.4.6` release serves `v1alpha1` for both core and extensions;
  upstream `main` (`v1beta1`, mutually-exclusive claim fields) is out of scope
  until OpenShell bumps the pinned version.
- Multiplayer/non-Kubernetes drivers (Docker, Podman, VM) — warm pooling is a
  Kubernetes-driver capability in this RFC.

## Proposal

### Extension CRDs (verified against v0.4.6)

| CRD (`extensions.agents.x-k8s.io/v1alpha1`) | Role |
|---|---|
| `SandboxTemplate` | Reusable blueprint: `spec.podTemplate`, `spec.volumeClaimTemplates`, `spec.networkPolicy` |
| `SandboxWarmPool` | Keeps N Pods warm: `spec.replicas`, `spec.sandboxTemplateRef`; `status.{readyReplicas,replicas,selector}` (HPA-scalable) |
| `SandboxClaim` | Binds a warm Pod: `spec.sandboxTemplateRef` (required), `spec.warmpool`, `spec.additionalPodMetadata.{annotations,labels}`, `spec.env[]`, `spec.lifecycle`; `status.sandbox.{name,podIPs}` |

A `SandboxWarmPool` pre-creates real `Sandbox` CRs from a `SandboxTemplate`; each
warm Pod is owned by a *controlling* `Sandbox` ownerReference. A `SandboxClaim`
binds one of those warm `Sandbox`/Pods and reports the bound `Sandbox` in
`status.sandbox.name`. The claimed Pod's owning `Sandbox` CR is in turn owned by
the `SandboxClaim` (controlling ownerReference) and labeled
`agents.x-k8s.io/claim-uid`.

### Claim-based create flow

The gateway pre-declares one or more `SandboxWarmPool`s (+ their
`SandboxTemplate`s), each carrying the **shared** OpenShell Pod configuration
(image, mTLS secret mount, projected SA-token volume, supervisor sideload, Linux
capabilities, host aliases, runtimeClass, resources, workspace
`volumeClaimTemplates`). On `CreateSandbox`, when the requested shape matches a
pool, the Kubernetes driver creates a `SandboxClaim` (instead of a `Sandbox`)
that injects the per-sandbox identity via
`additionalPodMetadata.annotations[openshell.io/sandbox-id]`, then watches the
claim and maps `status.sandbox.{name,podIPs}` + conditions to `SandboxPhase`.

What bakes vs. late-binds:

- **Baked into the shared `SandboxTemplate`:** everything generic across pooled
  Pods (TLS, SA token, supervisor, caps, workspace VCT).
- **Injected per-claim (annotation only):** `openshell.io/sandbox-id`. Per-claim
  `env[]` is **rejected on the warm path** (Pod env is immutable once running), so
  identity must not ride Pod env.
- **Late-bound at runtime over the supervisor relay (already works):** policy,
  providers. Sandbox identity is established by the existing token exchange — the
  supervisor presents its projected SA token to `IssueSandboxToken`, and the
  gateway resolves identity server-side. The supervisor's `--sandbox-id` is
  optional (log-push/policy labeling only).

### Identity re-anchoring (the one security-sensitive change)

Today `validate_sandbox_owner_reference()` in
`crates/openshell-server/src/auth/k8s_sa.rs` authenticates a sandbox by
cross-checking the owning `Sandbox` CR's `openshell.ai/sandbox-id` label against
the Pod's `openshell.io/sandbox-id` annotation. On the warm path the pool
controller creates the `Sandbox` CR generically, so it carries
`agents.x-k8s.io/claim-uid` (+ a controlling `SandboxClaim` ownerReference)
instead of OpenShell's label.

The check must therefore **re-anchor to the gateway-created `SandboxClaim`**:
resolve Pod → owning `Sandbox` CR → controlling `SandboxClaim` (name + uid) →
the sandbox-id the gateway recorded for that claim (gateway Store, keyed by
claim-uid), and verify the claim is bound (`status.sandbox.name` equals the
owning CR) and that its recorded sandbox-id equals the Pod annotation. This
preserves the existing invariant — *the sandbox-id a Pod can obtain equals a
value only the gateway wrote, on an object the sandbox workload cannot mutate*.
The sandbox ServiceAccount has no write access to `sandboxclaims` or Pods today
(confirmed on a live cluster), and the phase-2/phase-3 RBAC must preserve that.
The TokenReview, pod-UID, and ownerReference legs are unchanged.

## Implementation plan

Rollout is incremental; each phase is a separate, reviewable PR. The
security-sensitive auth change (phase 3) is gated behind `state:agent-ready`.

1. **Install the extensions (this PR).** Apply `extensions.yaml` in the local
   k3d dev script and the e2e kube harness so clusters are ready for warm
   pooling. No gateway behavior change yet.
2. **Driver warm path (flagged).** When a sandbox maps to a configured pool, the
   Kubernetes driver creates a `SandboxClaim` (template + warmpool +
   `additionalPodMetadata.annotations[openshell.io/sandbox-id]`) instead of a
   `Sandbox`; watch the claim and map `status` → `SandboxPhase`. Keep the
   direct-`Sandbox` path as the cold fallback. Add gateway RBAC for
   `extensions.agents.x-k8s.io` (`sandboxclaims`, `sandboxtemplates`,
   `sandboxwarmpools`) in the Helm chart.
3. **Auth re-anchoring.** Adapt `validate_sandbox_owner_reference()` for the
   claim-based identity check above; fail closed; extend the table-driven tests
   in `k8s_sa.rs` with the spoof case (Pod annotation ≠ claim record → reject).
4. **Pool management.** Gateway declares/reconciles `SandboxTemplate` +
   `SandboxWarmPool` from gateway config (one per template/image shape); sizing,
   `replicas`, GC of drained pools.
5. **Surface + docs.** `gateway.toml` pool config (`docs/reference/gateway-config.mdx`),
   CLI/TUI visibility, OCSF events, e2e coverage, published Kubernetes docs.

## Risks

- **Identity binding is security-sensitive.** Mishandled, a sandbox could
  impersonate another sandbox-id. Mitigated by re-anchoring to the
  gateway-created claim, failing closed, threat-model unit tests, an RBAC
  assertion test, an adversarial security review, and OCSF detection findings on
  mismatch. See phase 3.
- **Pool shape rigidity.** A pool is one (image, resources, runtimeClass, gpu)
  shape; heterogeneous sandboxes need a pool each, and unmatched requests fall
  back to cold. Warm pooling pays off most for the high-churn default image.
- **Idle cost.** Warm Pods consume resources while idle; GPU pools especially.
  Sizing must be operator-controlled and default conservative.
- **Upstream API drift.** `v0.4.6` extensions are `v1alpha1`; `main` is `v1beta1`
  with different claim semantics. Pin and bump deliberately.

## Alternatives

- **Patch identity onto the claimed Pod/`Sandbox` after bind** (keep the existing
  label cross-check). Rejected: requires granting the gateway `patch pods`
  (currently denied for immutability) and is racy.
- **Bare-Pod warm pools** (if upstream changes the pool to create Pods, not
  `Sandbox` CRs — see upstream issue #390). Would break the ownerReference auth
  chain and force a larger rework. The pinned `v0.4.6` creates `Sandbox` CRs.
- **Do nothing.** Accept cold-start latency. Viable for low-churn usage but poor
  for interactive agents.

## Prior art

Upstream agent-sandbox documents warm pooling end to end, including an
HPA-driven autoscaling example keyed on `agent_sandbox_claim_creation_total` and
the `SandboxWarmPool` `status.selector`. OpenShell already builds on the core
`Sandbox` CRD from the same project.

## Open questions

- Sandbox-id delivery to the supervisor on the warm path: rely solely on the
  gateway JWT, or add a Downward API volume projecting the claim-injected
  annotation for log-push/policy labeling?
- Workspace PVC semantics for pooled `Sandbox`es (each warm `Sandbox` seeds its
  own PVC from the image — confirm under the `volumeClaimTemplates` path).
- Pool sizing / autoscaling policy and config surface in `gateway.toml`.
