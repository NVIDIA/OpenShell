---
authors:
  - "@dvavili"
state: review
links:
  - "Scoping issue: [NVIDIA/OpenShell#1713](https://github.com/NVIDIA/OpenShell/issues/1713)"
  - "[RFC 0001 — Core Architecture](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0001-core-architecture/README.md)"
  - "[RFC 0002 — Agent-Driven Policy Management](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0002-agent-driven-policy-management/README.md)"
---

# RFC 0005 - Policy Provider Subsystem

## Summary

Promote policy sourcing to a first-class, pluggable **Policy Provider** subsystem on the gateway, following the same driver model OpenShell already uses for compute, credentials, and identity ([RFC 0001](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0001-core-architecture/README.md)). Two drivers sit behind the subsystem: `local` (the default — today's store-backed path, unchanged, satisfied in-process) and `external` (the gateway sources policy from a separate provider process over the gRPC contract). What a driver can do varies — where policy is sourced (a local store, a remote or central service, a signed-bundle verifier), how it's scoped (e.g. per tenant), whether it's attested and independently auditable, and whether it may be mutated in place — while the subsystem stays neutral about all of them. The change is additive and opt-in per deployment.

## Motivation

Policy in OpenShell is store-backed and gateway-owned: user-authored, validated, persisted, and composed inside the gateway. That works when one party owns both OpenShell and policy. Some policy ecosystems do not fit that shape — **enterprise deployment models in particular require strict attestation and independent auditability**:

- Policy is authored and signed by a central authority in a separate trust domain.
- What a sandbox enforces must be tamper-evident even against a compromised gateway.
- Auditors must be able to verify which policy was active, independently, against a signed artifact.

OpenShell's built-in (`local`) path **structurally cannot** provide this — it lives inside the gateway's own trust domain. So such ecosystems need a way to supply policy from *outside* it.

OpenShell already applies this shape elsewhere — compute, credentials, and identity are each sourced through a swappable driver. Policy is the one gateway concern that still isn't pluggable; this RFC brings it under the same driver model.

## Non-goals

- **Replacing the built-in policy path.** `local` remains the default; the subsystem is opt-in.
- **Specifying a driver's internal implementation.** This RFC defines the driver contract and the `external` wire; what runs behind it — an attesting verifier, a central/remote policy service, a git- or bundle-server-backed provider — is separate. The wire contract is in scope; the realization behind it is not.
- **A provider's internals and provisioning.** How a provider sources, formats, validates, and (where it attests) signs policy — and how policy reaches it and trust in it is established and rotated — is provider- and deployment-specific. OpenShell consumes only the projected result.
- **Multiple or runtime-switchable providers.** A gateway is configured with exactly one policy provider at startup and uses it for every sandbox it creates. The provider cannot be changed while the gateway runs, and a single gateway sourcing different sandboxes from different providers is out of scope (future work).

## Proposal

Introduce a `PolicyProvider` subsystem on the gateway — a swappable **driver** spoken over a gRPC contract, mirroring OpenShell's existing compute-driver model ([RFC 0001](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0001-core-architecture/README.md)) — that decides where the gateway sources policy. Two drivers:

- `local` *(default)* — today's store-backed path, unchanged: the gateway's built-in default, with no external driver and no wire.
- `external` — a separate provider process the gateway reaches over the gRPC contract (UDS, or later a network transport).

Everything downstream of policy retrieval is untouched: the gateway composes the result into the schema it already enforces and hands it to the supervisor; Landlock/seccomp (filesystem, process) and the proxy/OPA (network) enforce it exactly as today.

### Terminology

- **Subsystem / driver.** The **subsystem** is the gateway-side coordinator that selects and talks to a policy backend; a **driver** is a backend that implements the policy-driver gRPC contract. `local` and `external` are the two drivers.
- **Projection.** The policy a provider returns for a sandbox, rendered into the schema OpenShell enforces — the `SandboxPolicy` covering filesystem, process, and network rules (signed, if the provider attests). A provider holds policy in its own internal form and *projects* it onto that schema.
- **Runtime context.** The gateway-asserted facts about a sandbox — who it is for — minted at admission and bound to policy by the provider. Minimum: `sandbox_id` and the authenticated `user_subject`; deployments may extend it (`tenant_id`, `session_id`, `device_id`, …) for richer scoping, and the provider evaluates whichever fields are present.
- **Handle.** The opaque token a provider returns when it binds a runtime context; the per-sandbox reference for fetching the projection, releasing state, and audit correlation.
- **Surface (`surface_id`).** The policy schema a projection targets, e.g. `openshell.sandbox.v1`.

### The policy-driver contract

An `external` driver speaks one gRPC service contract — the same kind of contract OpenShell's compute, credentials, and identity subsystems already define for their drivers. Four RPCs:

- `GetCapabilities() -> { supported_surfaces, permits_mutation }` — called once at startup: the surfaces the driver can vend and whether it permits mutation. The gateway reconciles `supported_surfaces` against the surfaces it enforces, fails closed on no overlap, and confirms readiness.
- `AcquireHandle(runtime_context) -> handle` — binds the runtime context to an opaque handle: the per-sandbox correlation anchor, and the token for release, audit, and restart.
- `GetProjection(handle, surface_id) -> projection | no_verified_policy` — returns the projection for that sandbox (below).
- `ReleaseHandle(handle) -> ack` — idempotent cleanup at sandbox deletion.

`local` does not use this contract: it is the gateway's built-in default — the existing store-backed path, unchanged, with no wire and no handles. The contract above exists for `external` drivers, where policy is sourced across a process boundary and the per-sandbox handle anchors release, audit, and restart.

The projection is a small envelope:

```
projection {
    surface_id       // schema `body` conforms to (e.g. openshell.sandbox.v1)
    policy_digest    // hex SHA-256 over `body`
    body             // serialized SandboxPolicy — what the supervisor enforces

    signature        // optional — covers the envelope (signing providers only)
    signing_key_id   // optional — names the trust-store key to verify under

    audit_context    // optional — opaque key→value pairs the gateway records
                     // verbatim for correlation (e.g. a source-artifact digest)
}
```

The `signature` fields are optional and capability-driven; when present, the gateway verifies `signature` against the trust-store key named by `signing_key_id` and refuses admission on any failure.

### What the gateway enforces

Whatever a provider supplies, the gateway guarantees the enforced policy is **authentic**, **complete**, and **unaltered**:

- **Authentic.** When a trust store is configured, the gateway verifies the signature on every projection against it (multiple keys allowed, for rotation), refuses admission on any failure, and records the signing key for audit. This is enforced by the gateway, not declared by the provider — a provider can neither fake attestation nor opt out of it. The result is tamper-evident in transit and independently re-verifiable by an auditor holding the trust store. (What a provider does to *earn* the signature is its own business — see Non-goals.)
- **Complete.** A sandbox is admitted only if the *entire* projection body is enforced. The gateway relays the body as-issued (no edit/filter/merge); the supervisor loads it as a unit and refuses admission if any rule cannot be realized. Enforcing a subset would silently narrow what the provider supplied — and, for an attesting provider, break the trust chain.
- **Unaltered.** When the provider does not permit mutation (`capabilities().permits_mutation` is false, as a read-only `external` provider's is), the gateway refuses its entire policy-mutation surface — the `openshell policy set | update | delete` verbs and the agent-driven draft-chunk loop ([RFC 0002](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0002-agent-driven-policy-management/README.md)). A single coarse gate covers the whole surface, so paths added later are refused by default; the only way to change what a sandbox enforces is for the provider to source new policy. (Preserving the agent-driven loop under a non-mutating provider — by re-routing an approved proposal back to the authority for re-issue — is future work; see Open questions.)

### Configuration

Mirrors OpenShell's driver-config idiom (RFC 0003) — a `type =` selector plus a per-driver sub-table — splitting subsystem-level keys from driver-level keys:

```toml
[openshell.policy]
type = "external"                       # "local" (default) | "external"
accepted_surfaces = ["openshell.sandbox.v1"]   # schemas THIS gateway can enforce

[openshell.policy.external]
transport = "uds"                       # "uds" | "https"
endpoint = "/run/openshell/policy.sock" # uds path | https URL
trust_store_path = "/etc/openshell/policy.trust"
# transport = "https" adds the coupled bundle: client cert/key, server CA, …
```

`accepted_surfaces` is subsystem-level (a property of this gateway's enforcement capability). Transport, endpoint, and trust material are driver-level. The gateway refuses to start on an incoherent driver config (e.g. `external` without an endpoint, or an attesting setup with no trust store).

### Lifecycle

- **Per-sandbox.** At admission the gateway acquires a handle, fetches the projection and — when a trust store is configured — verifies its signature, then relays the body. At deletion it releases the handle.
- **Handles** persist across restarts on both sides; cleanup on release.
- **Audit.** Every admission and lifecycle event carries OpenShell's baseline keys — `sandbox_id` and the enforced `policy_digest` — for any provider. The projection may also carry an `audit_context`: opaque key-value pairs the gateway records verbatim. A provider fills it with whatever ties back to its own records (a source-artifact digest, a request id, …); a SIEM joins on the keys both sides emit. The contract names none of these — it just passes them through.

Service-level concerns — startup readiness, liveness probing, graceful drain — are standard for any remote service and out of scope here. If the provider is unavailable, new admissions fail closed while admitted sandboxes keep running.

## Implementation plan

**Phase 1 — the subsystem.** Build the `PolicyProvider` subsystem and its two drivers, with an in-tree **null provider** (a minimal conforming wire implementation) to exercise the `external` path without a real provider behind it.

**Phase 2 — the open contract.** Publish the wire schemas, document the conforming-provider contract, and validate it by running a third-party provider against the in-tree harness.

## Risks

- **Schema/version drift.** Gateway and an `external` provider release independently; an unsupported surface fails admission closed. v0 deploys compatible versions as a unit.
- **Auth-mode incompatibility.** An attesting provider binds decisions to the authenticated user; dev-mode auth shortcuts must not run alongside it (the gateway rejects dev-fallback principals when such a provider is active).
- **Local-to-remote is a security change, not a config flip.** A remote provider must authenticate its callers over the network (e.g. mutual TLS); a local socket gets that guarantee from the OS for free. Plan for the auth setup, not just a new URL.

## Alternatives

**A. Provider in-process or per-sandbox.** A linked-in provider shares the gateway's address space; a per-sandbox one sits inside the domain it constrains — both collapse the trust split, and a compiled-in provider forecloses bring-your-own. The `external` driver keeps the provider a separate, swappable process.

**B. A single combined endpoint (no handle).** Folding `AcquireHandle` into `GetProjection` is simpler for v0 but loses the handle's durable per-sandbox binding: it pins a running sandbox to the policy it was admitted with, and anchors release, audit, and restart survival.

## Open questions

1. **The mutation capability.** When a provider does not permit mutation, leave OpenShell's agent-driven loop disabled, or define a re-issue path that preserves it by routing an approved proposal back to the provider (coordinating with [RFC 0002](https://github.com/NVIDIA/OpenShell/blob/8bf667f377d567e4c7638db8ca70ce13ecdeb0da/rfc/0002-agent-driven-policy-management/README.md))?
