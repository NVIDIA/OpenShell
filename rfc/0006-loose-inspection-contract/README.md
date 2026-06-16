---
authors:
  - "@afournier"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/pull/1738
  - https://github.com/NVIDIA/NeMo-Relay/issues/277
---

# RFC 0006 - Loose Inspection Contract For External Interoperability

## Summary

This RFC proposes a narrower alternative to RFC 0005's OpenShell-owned egress middleware model. Instead of making OpenShell the owner of a general outbound middleware framework, OpenShell should define a minimal, opt-in inspection boundary at the sandbox runtime and leave semantic inspection logic to external systems such as NeMo Relay.

The goal is to make loose interoperability possible without introducing a direct dependency between OpenShell and any specific guardrails or middleware SDK. OpenShell would own where a hook runs and how its result is enforced. External runtimes or platform integrations would own inspection logic, policy evaluation, and adapter wiring.

This RFC is paired with a NeMo Relay issue draft in a separate Relay worktree. The split is deliberate: RFC work belongs in OpenShell, while the implementation-scoping issue for Relay belongs in the Relay repo.

## Motivation

RFC 0005 correctly identifies a real gap in OpenShell today: the sandbox can control where outbound traffic goes, but it has no first-class way to make request-content decisions before a request leaves the sandbox. That gap matters for prompt payloads, tool arguments, file uploads, and other agent-generated content.

At the same time, RFC 0005 assumes the right answer is an OpenShell-owned middleware subsystem with gateway registration, middleware capability validation, policy chaining, and a dedicated middleware configuration model. That is one plausible answer, but it is not the only one, and it is a broad expansion of OpenShell's ownership boundary.

There is now a meaningful adjacent system to consider: NeMo Relay. Relay already owns semantic request intercepts, guardrails, execution intercepts, and observability around LLM and tool calls. OpenShell does not. OpenShell instead owns the deny-by-default sandbox, network boundary, proxy path, and credential-injection path. Those are complementary strengths.

Because of that, the architectural question is not only "how do we add request inspection to OpenShell?" It is also "what is the smallest OpenShell role that still enables external semantic systems to participate at the sandbox boundary?" For OpenShell, that narrower question is a better fit.

If OpenShell adopts the wrong ownership boundary here, it will either:

- duplicate semantic middleware work already better owned elsewhere
- introduce a large new subsystem that is hard to generalize and hard to land

## Non-goals

- Replacing RFC 0005 wholesale. This RFC is an alternative boundary proposal for interoperability work, not a claim that RFC 0005 is invalid in every context.
- Designing a general-purpose OpenShell plugin framework.
- Making NeMo Relay an OpenShell plugin or making OpenShell a NeMo Relay runtime component.
- Standardizing a cross-project neutral crate home in this RFC.
- Defining full policy authoring UX, gateway registration UX, or an operator-facing middleware catalog.
- Owning semantic LLM/tool policy logic inside OpenShell.
- Introducing response inspection, post-credential signing hooks, or broad streaming semantics in the first phase.

## Proposal

### Boundary

OpenShell should own a minimal outbound inspection boundary at the sandbox runtime.

That means OpenShell owns:

- the invocation point in the data plane
- the request context made available to an inspector
- enforcement of `allow`, `deny`, or `mutate`
- coarse runtime audit of what happened at the boundary

That means OpenShell does not own:

- semantic inspection logic
- request classification logic
- provider- or framework-specific guardrail behavior
- a broad middleware registration and capability ecosystem in phase 1

External systems such as NeMo Relay should own the semantic layer:

- request intercepts
- guardrails
- model/tool-aware mutation logic
- higher-level provenance and policy semantics

The platform, harness, or vendor integration layer should own:

- whether the two are wired together at all
- the concrete inspector implementation
- policy logic and deployment model

### OpenShell hook shape

The OpenShell side should be a thin adapter seam, not a full middleware subsystem.

The most important seam is already visible in `openshell-sandbox`:

- `crates/openshell-sandbox/src/proxy.rs`
  - terminated TLS and plaintext HTTP relay paths
  - before OpenShell-managed credential injection
- `crates/openshell-sandbox/src/l7/provider.rs`
  - parsed request representation

The hook should run only on traffic OpenShell already parses. In practice, that means the phase 1 hook lives on the parsed HTTP request path after network admission and before credential injection.

The hook input should include:

- sandbox identity
- actor process identity already used for policy and OCSF
- destination host and port
- protocol or route name when available
- HTTP method and path
- safe header subset
- bounded body bytes

The hook result should be intentionally narrow:

- `allow`
- `deny`
- `mutate`
- structured findings or annotations

OpenShell should apply the result directly and continue to own the upstream connection.

### Shared decision model

This RFC does not standardize a permanent crate layout, but it does assume a small shared decision vocabulary is the right long-term shape if interoperability proves useful.

At minimum, the shared vocabulary should cover:

- target type
- request context
- finding
- decision

An illustrative shape is:

```rust
pub enum InspectionDecision {
    Allow,
    Deny { reason: String, findings: Vec<Finding> },
    Mutate { target: InspectionTarget, findings: Vec<Finding> },
}
```

The important property is not the exact Rust syntax. The important property is that the contract remains small enough that:

- OpenShell can invoke it at the runtime boundary
- Relay can map existing semantic intercepts into it
- a third-party integrator can implement it without adopting either SDK wholesale

### NeMo Relay interoperability

NeMo Relay already has stronger semantic surfaces than OpenShell for LLM and tool inspection:

- `llm_request_intercepts`
- `tool_request_intercepts`
- conditional execution guardrails
- sanitize request/response guardrails
- execution intercepts

That means the Relay side of the integration should be an adapter problem, not a core-architecture rewrite. Relay can map its existing intercept and guardrail model into the shared decision vocabulary without giving OpenShell ownership of Relay semantics.

### Configuration and control-plane scope

This RFC intentionally does not adopt RFC 0005's full control-plane model.

Phase 1 should avoid:

- gateway middleware registries
- middleware capability negotiation
- policy-native middleware chains
- OpenShell-owned service-specific config validation

If the boundary proves valuable and repeated, those capabilities can be reconsidered later. Adding them now would effectively recreate RFC 0005's OpenShell-owned subsystem under a different name.

### Relationship to RFC 0005 and the Relay issue

RFC 0005 and this RFC overlap on one key point: both identify the pre-credential parsed HTTP path in the sandbox proxy as the meaningful enforcement seam.

They differ on ownership:

- RFC 0005 proposes an OpenShell-owned egress middleware framework.
- RFC 0006 proposes a minimal OpenShell enforcement seam designed for loose external interoperability.

The companion Relay issue draft carries the Relay-side implementation detail and mirrors this boundary from the Relay perspective. This RFC should stay focused on OpenShell scope, not absorb the Relay execution plan.

## Implementation plan

1. Post the companion NeMo Relay enhancement issue describing the Relay-side adapter surface and explicit repo boundary.
2. Circulate this RFC as the OpenShell-side boundary proposal and explicitly reference RFC 0005 as prior art rather than the implementation target.
3. Prototype a small decision contract in an integration spike without introducing an OpenShell-to-Relay dependency.
4. Add a thin OpenShell sandbox-side adapter seam at the parsed HTTP pre-credential hook point.
5. Add a thin NeMo Relay-side adapter that maps its existing LLM/tool intercept surfaces into the same decision model.
6. Keep inspector implementation and policy wiring outside both SDKs.
7. Re-evaluate only after a real integration shows repeated cross-backend or cross-runtime value.

The implementation should be incremental and opt-in. Sandboxes with no configured adapter should pay no per-request cost.

## Risks

- **The seam may still be too small.** A minimal decision vocabulary may not be enough to support streaming, capability negotiation, or richer metadata needs. That is acceptable in phase 1, but it may limit reuse.
- **The seam may still be too large.** Even a thin adapter point adds hot-path complexity to `openshell-sandbox`. If real users only need application-side enforcement, this could still be unnecessary surface area.
- **Ownership of the shared contract may become contentious.** If both OpenShell and Relay depend on a shared crate, the home and change process for that crate becomes a governance question.
- **Integrators may want the broader RFC 0005 feature set immediately.** Teams that need OpenShell-owned registration, chaining, and config validation may see this proposal as too narrow.
- **Semantic/runtime split may confuse operators.** Operators may expect one system to own both semantic policy and runtime enforcement. This proposal explicitly splits those concerns.

## Alternatives

### Adopt RFC 0005 as the default path

This gives OpenShell a complete egress middleware framework, but it also makes OpenShell the owner of registration, validation, chaining, and service contracts. That is broader than necessary for the interoperability goal that motivates this RFC.

### Keep everything inside NeMo Relay

This is the cleanest boundary when all relevant traffic already flows through Relay-managed LLM and tool execution. It is weaker when operators want an independent sandbox-boundary enforcement point or when traffic can leave the sandbox outside Relay-managed paths.

### Introduce direct SDK-to-SDK coupling

Making OpenShell depend on Relay or Relay depend on OpenShell would create support and release coupling between two systems that should remain independently useful. It would also make third-party reuse harder.

### Do nothing

Leaving the design unchanged keeps boundaries simple but gives up the opportunity to combine OpenShell's runtime boundary with external semantic guardrails in a structured way.

## Prior art

- **RFC 0005 - Sandbox Egress Middleware**
  This is the most relevant prior OpenShell design. It identifies the right enforcement seam but chooses a wider OpenShell ownership model.

- **OpenShell `policy.local`**
  OpenShell already has precedent for a sandbox-local control surface when it needs one, but `policy.local` does not imply a general plugin or middleware framework.

- **OpenShell inference routing**
  OpenShell already treats inference as a special governed external backend. That shows OpenShell can own a narrow runtime boundary without needing to own all higher-level semantics.

- **NeMo Relay request intercepts and guardrails**
  Relay demonstrates that semantic inspection is already a first-class runtime concern elsewhere. OpenShell does not need to re-own that layer to benefit from it.

## Open questions

- Should phase 1 remain an internal seam and spike, or should OpenShell expose any user-facing configuration for the hook immediately?
- If a shared decision contract is adopted, where should it live so neither OpenShell nor Relay becomes the accidental owner of the other?
- Is the pre-credential parsed HTTP path sufficient, or does `inference.local` need a separate explicit seam?
- What is the minimum audit model OpenShell should emit when a hook denies or mutates a request?
