# RFC 0005 Tracker - Sandbox Egress Middleware

This tracker is the working document for drafting RFC 0005. Keep the main `README.md` focused on the selected design path; use this file to track research sources, appendix structure, decisions, alternatives, and unresolved sections as the RFC evolves.

## Current Status

- RFC folder created: `rfc/0005-sandbox-egress-middleware/`
- Main RFC draft: `rfc/0005-sandbox-egress-middleware/README.md`
- State: high-level draft scaffold
- GitHub roadmap issue: https://github.com/NVIDIA/OpenShell/issues/1043
- GitHub RFC tracking issue: https://github.com/NVIDIA/OpenShell/issues/1733
- Related model routing RFC issue: https://github.com/NVIDIA/OpenShell/issues/1734

## Research Content

- Active research notes live in `rfc/0005-privacy-guard/research-notes/`.
- Archived material lives in `rfc/0005-privacy-guard/do-not-read-unless-requested/`.
- Treat the archived material as opt-in context only. Do not pull from it unless a specific question requires it.
- As research gets incorporated, add a short note here that identifies which source informed which section or appendix.

## Intended RFC Shape

The main `README.md` should stay relatively high-level. It should explain the problem, the chosen design, and the path we want reviewers to evaluate. Detailed alternatives, tradeoff analysis, protocol sketches, and future extension notes should live in appendices and be linked from the main document where relevant.

## Main README Sections

- Summary: concise description of sandbox proxy egress middleware, where it fits, and the initial experimental stage of the feature.
- Motivation: why destination-level egress policy is not enough for content-aware controls.
- Initial use cases: user stories that introduce Privacy Guard as a motivating example without making the RFC a Privacy Guard product spec.
- Non-goals: model routing, full generic middleware framework, OpenShell-owned detection engine, and deferred deployment models.
- Proposal: chosen architecture and the minimal contract between supervisor, policy, and external middleware service.
- Implementation plan: phased implementation once the proposal is stable.
- Risks: latency, availability, policy ambiguity, transformation semantics, metadata stability, and audit expectations.
- Alternatives: brief summary with links to appendices.
- Prior art: short summary with links to supporting notes.
- Open questions: unresolved design decisions that need reviewer input.

## Planned Appendices

- `appendices/deployment-options.md`: external service decision and future options such as WASM, OpenShell-managed image middleware, and bundled first-party guards.
- `appendices/request-response-contract.md`: proposed middleware request/response schema, decision model, metadata fields, and transformation semantics.
- `appendices/policy-integration.md`: how sandbox policy selects middleware, expresses required versus optional behavior, and composes with existing L4/L7 rules.
- `appendices/pipeline-placement.md`: exact placement in the supervisor relay path, including relationship to network policy, L7 policy, credential injection, upstream forwarding, and model routing metadata.
- `appendices/failure-and-audit.md`: fail-open/fail-closed choices, timeout behavior, retry guidance, OCSF audit events, and handling of sensitive values in logs.
- `appendices/future-extensions.md`: deferred ideas, including response scanning, multi-middleware composition, local model enforcement, managed deployment, and richer model-routing integration.
- `appendices/prior-art.md`: relevant external patterns and what OpenShell should or should not copy.

## Visuals To Include

- Current proxy flow: show how sandbox egress moves through the supervisor relay today, including policy checks, route selection, credential injection, and upstream forwarding.
- Proposed hook placement: show where the egress middleware call plugs into the existing flow, especially relative to network/L7 policy and credential injection.
- Configuration flow: show gateway configuration feeding sandbox bundle generation, the supervisor receiving middleware registration data, and policy selecting the registered middleware for specific egress rules.

Prefer Mermaid diagrams in the main RFC when they clarify the core proposal. Move lower-level or alternative diagrams into appendices.

## Required RFC Pieces

- Terminology: define `middleware`, `hook`, `egress`, `finding`, `metadata`, `transformation`, `registered middleware`, and `middleware config`. Decide whether `egress` needs an OpenShell-specific definition or can use the ordinary network meaning.
- Gateway configuration: describe how operators register external middleware services with the gateway, including endpoint, identity/auth material if needed, timeout defaults, and expected capabilities.
- Supervisor configuration delivery: document how the supervisor receives middleware registration and policy binding data. Investigate whether `GetSandboxBundle` is the right existing path to extend.
- Middleware capability discovery: define an initial gRPC shape for capability negotiation. The actual proto should be included or sketched in the RFC, but simplified enough for review.
- Capability response fields: include version, description, supported hook types, supported payload/content types, supported decision types, config schema or validation mechanism, and any limits needed by policy validation.
- Middleware inspection RPC: define the request and response shape for an egress hook invocation, including request metadata, body handling, decision, transformed content, findings, and audit-safe messages.
- Policy shape: describe how policies reference registered middleware from gateway configuration, how middleware-specific config is attached, and how that config is validated by the service.
- Middleware section in policy: decide whether policies have a top-level `middlewares` section, rule-level middleware references, or both. Capture the chosen shape and rejected alternatives.
- Failure behavior: define required versus optional middleware behavior, timeout handling, service errors, unsupported capability responses, and default fail-closed semantics.
- Audit/logging: describe the OCSF events or event categories for allow, block, transform, service unavailable, config validation failure, and capability mismatch.
- Model routing handoff: state which metadata is intended for future model routing without designing the router in this RFC.

## Initial Decisions

- The summary should describe the initial experimental stage in plain language without version labels.
- Middleware deployment uses an external service managed by the user.
- Future deployment models remain explicitly open for evaluation instead of being designed into the initial contract.
- The main RFC describes the chosen path; appendices preserve alternatives and tradeoffs.
- Middleware findings should become structured metadata that future model routing can consume.
- Model routing is out of scope for this RFC and tracked separately in https://github.com/NVIDIA/OpenShell/issues/1734.

## Open Drafting Questions

- What is the smallest useful middleware request/response contract?
- Should the first iteration target all HTTP egress, only model-bound HTTP egress, or any relay-supported protocol with protocol-specific payloads?
- How should OpenShell validate middleware capabilities before a sandbox starts?
- Should optional middleware exist, or should the first version only support required fail-closed middleware?
- What metadata must be stable for composition with model routing?
- Which audit events belong in the RFC versus later architecture documentation?
- Is `GetSandboxBundle` the right supervisor delivery path for middleware configuration, or should middleware registration travel through a separate API?
- Should middleware config validation happen at gateway startup, policy load time, sandbox creation time, or all of the above?
- Should middleware capability discovery be mandatory before accepting policy that references a middleware service?

## Drafting Queue

- Fill the pipeline placement section from the real supervisor relay path.
- Define the deployment contract for external middleware services.
- Sketch the request/response contract.
- Define policy attachment syntax at the concept level before choosing exact TOML/YAML fields.
- Add the deployment-options appendix first, since it captures the deployment decision and future paths.

## Potential ideas to explore

- For the hook that runs post-credential injection (e.g. the sigv4), only allow first-party build in hooks, so the credentials don't leave the sandbox.