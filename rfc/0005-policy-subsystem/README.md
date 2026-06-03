---
authors:
  - "@dvavili"
state: review
links:
  - Scoping issue: [NVIDIA/OpenShell#1713](https://github.com/NVIDIA/OpenShell/issues/1713)
  - [RFC 0001 — Core Architecture](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0001-core-architecture/README.md)
  - [RFC 0002 — Agent-Driven Policy Management](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0002-agent-driven-policy-management/README.md)
  - [1703 — out-of-tree compute drivers via --compute-driver-socket](https://github.com/NVIDIA/OpenShell/pull/1703)
---

# RFC 0005 - Policy Subsystem

## Summary

Promote policy to a first-class **Policy subsystem** on the gateway, following the subsystem-and-driver model [RFC 0001](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0001-core-architecture/README.md) defines for the gateway — the model OpenShell implements today for compute. Like compute, Policy owns the semantics — composition, enforcement, audit — and delegates *where policy comes from* to a **driver**: a first-party `builtin` driver (the default — today's store-backed path, unchanged, in-process), or a third-party driver that sources policy from a separate process over the `PolicyDriver` gRPC contract. What a driver can do varies — where it gets policy and how it shapes it onto the schema, whether it attests it — while the subsystem stays neutral about driver capabilities. The change is additive and opt-in per deployment.

## Motivation

Policy in OpenShell is store-backed and gateway-owned: user-authored, validated, persisted, and composed inside the gateway. That works when one party owns both OpenShell and policy. Some policy ecosystems do not fit that shape — **enterprise deployment models in particular require strict attestation and independent auditability**:

- Policy is authored and signed by a central authority in a separate trust domain.
- What a sandbox enforces must be tamper-evident even against a compromised gateway.
- Auditors must be able to verify which policy was active, independently, against a signed artifact.

OpenShell's built-in path **structurally cannot** provide this — it lives inside the gateway's own trust domain. So such ecosystems need a way to supply policy from *outside* it.

OpenShell already applies this shape to compute — the sandbox backend is sourced through a swappable driver, and RFC 0001 defines the same model for credentials and identity. Policy is the one gateway concern not yet behind a driver; this RFC brings it under the same subsystem-and-driver model.

## Non-goals

- **Replacing the built-in policy path.** The `builtin` driver remains the default; the subsystem is opt-in.
- **Specifying a driver's internals.** This RFC defines the `PolicyDriver` contract; everything behind it — how a driver sources, formats, validates, and (where it attests) signs policy, and how policy reaches it and trust in it is established and rotated — is driver- and deployment-specific. The wire contract is in scope; the realization behind it is not — OpenShell consumes only the projected result.
- **Per-sandbox or runtime-switchable drivers.** Per RFC 0001's driver model, a gateway runs one policy driver, selected at startup. Choosing different drivers per sandbox or tenant, or swapping the driver while the gateway runs, is out of scope (future work).
- **Gateway-launched drivers.** The external/third-party driver, per this proposal, is an operator-managed process the gateway connects to, not one it spawns. One reason to source policy externally is to let it live in a separate trust domain with its own store, trust model, and lifecycle; if the gateway launched and supervised the driver, the driver's process, config, and credentials would fall back under the gateway's control, collapsing that boundary. Where the driver runs and who owns its lifecycle are deliberately the operator's.

## Proposal

Introduce a **Policy subsystem** on the gateway. Like compute, credentials, and identity ([RFC 0001](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0001-core-architecture/README.md)), the subsystem owns the policy semantics and delegates *where policy comes from* to a **driver**:

- A **first-party `builtin` driver** *(the default, used when no driver socket is configured)* — today's store-backed path, unchanged: ships with the gateway and is satisfied in-process.
- A **third-party driver** implements the `PolicyDriver` gRPC contract and runs as an **operator-managed process**; the gateway connects to a UDS the operator provides. The gateway does not launch or supervise it — the same out-of-tree model proposed for compute drivers in [#1703](https://github.com/NVIDIA/OpenShell/pull/1703) (the `--compute-driver-socket` flag). How the driver is packaged, where it sources policy (including fronting a remote backend), and how its socket is secured are all the operator's, invisible to the gateway.

Everything downstream of policy retrieval is untouched: the gateway composes the result into the schema it already enforces and hands it to the supervisor; Landlock/seccomp (filesystem, process) and the proxy/OPA (network) enforce it exactly as today.

### Terminology

- **Subsystem / driver.** The **Policy subsystem** is the gateway-side coordinator. A **driver** is what implements the policy contract and the gateway talks to — the first-party `builtin` driver, or a third-party process over `PolicyDriver` gRPC. 
- **Projection.** The policy a driver returns for a sandbox, rendered into the schema OpenShell enforces — the `SandboxPolicy` covering filesystem, process, and network rules (signed, if the driver attests). A driver holds policy in its own internal form and *projects* it onto that schema.
- **Runtime context.** The gateway-asserted facts about a sandbox — who it is for — minted at admission and bound to policy by the driver. Minimum: `sandbox_id` and the authenticated `user_subject`; deployments may extend it (`tenant_id`, `session_id`, `device_id`, …) for richer scoping, and the driver evaluates whichever fields are present.
- **Handle.** The opaque token a driver returns when it binds a runtime context; the per-sandbox reference for fetching the projection, releasing state, and audit correlation.
- **Surface (`surface_id`).** The policy schema a projection targets, e.g. `openshell.sandbox.v1`.

### The `PolicyDriver` contract

A third-party driver implements one gRPC service — `PolicyDriver` (versioned `openshell.policy.driver.v1`), the same kind of contract compute, credentials, and identity drivers already define ([RFC 0001](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0001-core-architecture/README.md)). Four RPCs:

- `GetCapabilities() -> { supported_surfaces, permits_mutation, … }` — the readiness handshake every OpenShell driver exposes (RFC 0001). Called once at startup; reports the surfaces the driver can vend, whether it permits mutation, and its version/optional features. The gateway reconciles `supported_surfaces` against the surfaces it enforces, fails closed on no overlap, and confirms readiness.
- `AcquireHandle(runtime_context) -> handle` — binds the runtime context to an opaque handle: the per-sandbox correlation anchor, and the token for release, audit, and restart.
- `GetProjection(handle, surface_id) -> projection | no_verified_policy` — returns the projection for that sandbox (below).
- `ReleaseHandle(handle) -> ack` — idempotent cleanup at sandbox deletion.

The first-party `builtin` driver does not use this gRPC contract — it ships with the gateway and is satisfied in-process, with no handles. The contract is for third-party drivers, where policy is sourced across a process boundary and the per-sandbox handle anchors release, audit, and restart.

The projection is a small envelope:

```
projection {
    surface_id       // schema `body` conforms to (e.g. openshell.sandbox.v1)
    policy_digest    // hex SHA-256 over `body`
    body             // serialized SandboxPolicy — what the supervisor enforces

    signature        // optional — covers the envelope (signing drivers only)
    signing_key_id   // optional — names the trust-store key to verify under

    audit_context    // optional — opaque key→value pairs the gateway records
                     // verbatim for correlation (e.g. a source-artifact digest)
}
```

The `signature` fields are optional and capability-driven; when present, the gateway verifies `signature` against the trust-store key named by `signing_key_id` and refuses admission on any failure.

### What the gateway enforces

Whatever a driver supplies, the gateway guarantees the enforced policy is **authentic**, **complete**, and **unaltered**:

- **Authentic.** When a trust store is configured, the gateway verifies the signature on every projection against it (multiple keys allowed, for rotation), refuses admission on any failure, and records the signing key for audit. This is enforced by the gateway, not declared by the driver — a driver can neither fake attestation nor opt out of it. The result is tamper-evident in transit and independently re-verifiable by an auditor holding the trust store. (What a driver does to *earn* the signature is its own business — see Non-goals.)
- **Complete.** A sandbox is admitted only if the *entire* projection body is enforced. The gateway relays the body as-issued (no edit/filter/merge); the supervisor loads it as a unit and refuses admission if any rule cannot be realized. Enforcing a subset would silently narrow what the driver supplied — and, for an attesting driver, break the trust chain.
- **Unaltered.** When the driver does not permit mutation (`capabilities().permits_mutation` is false, as a read-only third-party driver's is), the gateway refuses its entire policy-mutation surface — the `openshell policy set | update | delete` verbs and the agent-driven draft-chunk loop ([RFC 0002](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0002-agent-driven-policy-management/README.md)). A single coarse gate covers the whole surface, so paths added later are refused by default; the only way to change what a sandbox enforces is for the driver to source new policy. (Preserving the agent-driven loop under a non-mutating driver — by re-routing an approved proposal back to the authority for re-issue — is future work; see Open questions.)

### Configuration

Policy gets an `[openshell.gateway.policy]` sub-table. A single socket-path key selects the driver: unset → the in-process `builtin` driver; set → the gateway connects to the operator-run driver at that UDS.

```toml
[openshell.gateway.policy]
accepted_surfaces = ["openshell.sandbox.v1"]   # schemas THIS gateway enforces
trust_store = "/etc/openshell/policy.trust"    # keys the gateway verifies signed projections against
# driver_socket unset → the in-process "builtin" driver (default).
# Set it to an operator-run driver's UDS to source policy externally:
driver_socket = "/run/openshell/policy.sock"
```

Those three keys are the gateway's entire policy surface. How the driver is packaged, where it sources policy, and how it reaches any remote backend are all the operator's — configured in the driver itself, never surfaced to OpenShell. The two security-relevant pieces split cleanly:

- **Trust store — the gateway's.** The gateway verifies signatures, so it holds the keys; a driver cannot supply the keys it is checked against.
- **Socket access control — the operator's.** Set through filesystem permissions, matching the `--compute-driver-socket` posture.

### Lifecycle

- **Per-sandbox.** At admission the gateway acquires a handle, fetches the projection and — when a trust store is configured — verifies its signature, then relays the body. At deletion it releases the handle.
- **Handles** persist across restarts on both sides; cleanup on release.
- **Audit.** Every admission and lifecycle event carries OpenShell's baseline keys — `sandbox_id` and the enforced `policy_digest` — for any driver. The projection may also carry an `audit_context`: opaque key-value pairs the gateway records verbatim. A driver fills it with whatever ties back to its own records (a source-artifact digest, a request id, …); a SIEM joins on the keys both sides emit. The contract names none of these — it just passes them through.

Service-level concerns — startup readiness, liveness probing, graceful drain — are standard for any driver process and out of scope here. If the driver is unavailable, new admissions fail closed while admitted sandboxes keep running.

## Implementation plan

**Phase 1 — the seam, no behavior change.**

- Introduce the Policy subsystem; re-express today's store-backed, in-gateway path behind it as the `builtin` driver.
- Same composition, enforcement, and output — the only change is that policy now flows through the subsystem.
- Proves the seam is transparent before any cross-process code exists.

**Phase 2 — the third-party path.**

- Define the `PolicyDriver` gRPC contract; wire it through [#1703](https://github.com/NVIDIA/OpenShell/pull/1703)'s out-of-tree model (the gateway connects to an operator-provided UDS via `[openshell.gateway.policy].driver_socket`).
- Add the projection envelope, trust-store signature verification, and handle lifecycle (acquire/release, restart persistence).
- Add the `[openshell.gateway.policy]` config (`accepted_surfaces` / `trust_store` / `driver_socket`).
- Ship an in-tree **null driver** (a minimal conforming `PolicyDriver`) so the path runs end-to-end without a real backend.

**Phase 3 — stabilize the contract.**

- Version and publish the `PolicyDriver` schemas as an open spec.
- Document the conforming-driver contract.
- Validate the contract by running a driver built outside the OpenShell tree against the gateway — proving the published spec is implementable without in-tree code.
- *(Optionally)* ship a conformance harness — a test client exercising the four RPCs — so third-party authors can self-check a driver.

## Risks

- **Schema/version drift.** Gateway and a third-party driver release independently; an unsupported surface fails admission closed. v0 deploys compatible versions as a unit.
- **Auth-mode incompatibility.** An attesting driver binds decisions to the authenticated user; dev-mode auth shortcuts must not run alongside it (the gateway rejects dev-fallback principals when such a driver is active).

## Alternatives

**A. Driver in-process or per-sandbox.** A linked-in driver shares the gateway's address space; a per-sandbox one sits inside the domain it constrains — both collapse the trust split, and a compiled-in driver forecloses bring-your-own. The separate-process driver model keeps it swappable, matching RFC 0001's other subsystems.

**B. A single combined endpoint (no handle).** Folding `AcquireHandle` into `GetProjection` is simpler for v0 but loses the handle's durable per-sandbox binding: it pins a running sandbox to the policy it was admitted with, and anchors release, audit, and restart survival.

## Open questions

1. **The mutation capability.** When a driver does not permit mutation, leave OpenShell's agent-driven loop disabled, or define a re-issue path that preserves it by routing an approved proposal back to the driver (coordinating with [RFC 0002](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0002-agent-driven-policy-management/README.md))?

