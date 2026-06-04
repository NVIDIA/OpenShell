# RFC 0005 Tracker - Sandbox Egress Middleware

This tracker is the working document for drafting RFC 0005. Keep the main `README.md` focused on the selected design path; use this file to track research sources, appendix structure, decisions, alternatives, and unresolved sections as the RFC evolves.

## Current Status

- RFC folder: `rfc/0005-sandbox-egress-middleware/`
- Branch: `rfc-0005-sandbox-egress-middleware`
- Draft PR: https://github.com/NVIDIA/OpenShell/pull/1738
- State: Proposal section drafted end to end. Done: Summary, Motivation, Use-case (Privacy Guard), Non-goals, Proposal (Architecture, Hooks and placement, Contract + proto sketch, Registration and delivery, Policy integration, Middleware ordering, Metadata, Audit and logging), Prior art.
- Not yet written: Terminology, Implementation plan, Risks, Alternatives, Open questions (still placeholders), plus several appendices (see Planned Appendices).
- GitHub roadmap issue: https://github.com/NVIDIA/OpenShell/issues/1043
- GitHub RFC tracking issue: https://github.com/NVIDIA/OpenShell/issues/1733
- Related model routing RFC issue: https://github.com/NVIDIA/OpenShell/issues/1734
- Note: RFC number `0005` collides with `rfc/0005-privacy-guard/` (and `0002` is also duplicated). PR proposes reserving numbers / allowing gaps. Renumber if that lands.

## Research Content

- Active research notes live in `rfc/0005-privacy-guard/research-notes/`.
- Archived material lives in `rfc/0005-privacy-guard/do-not-read-unless-requested/`.
- Treat the archived material as opt-in context only. Do not pull from it unless a specific question requires it.

Sources incorporated so far:

- `context.md` -> Motivation, operator/user trust split, registration-vs-policy split.
- `e2e-example.md` -> gateway TOML (`[[openshell.proxy.middleware]]`), `network_middlewares` policy example, chain ordering.
- `pre-rfc-interface.md` -> hook placement (`request.before_upstream`), contract shape, capability fields, failure semantics, OCSF inputs.
- `pre-rfc-registration.md` -> registration model, gRPC/TLS transport choice, validation timing.
- `pre-rfc-policy-configuration.md` -> reusable middleware policy layer, `on_error`, operator/user control.
- `review-01.md` -> gRPC-vs-REST rationale, ext_proc/go-plugin/CSI prior art, streaming + Wasm alternatives.
- `thought-01.md` -> capability model and the (now superseded) single-middleware decision; chains are in v1.

## Intended RFC Shape

The main `README.md` should stay relatively high-level. It should explain the problem, the chosen design, and the path we want reviewers to evaluate. Detailed alternatives, tradeoff analysis, protocol sketches, and future extension notes should live in appendices and be linked from the main document where relevant.

## Main README Sections

- [done] Summary.
- [done] Motivation: why destination-level egress policy is not enough for content-aware controls.
- [done] Use-case: Privacy Guard (folded under Motivation as the motivating example, not a product spec).
- [done] Non-goals. Final set: model routing; general-purpose middleware framework; constraining/sandboxing the middleware itself; runtime management of middleware; guaranteeing detection correctness; support for multiple deployment modes.
- [done] Proposal: architecture, hooks/placement, contract (+ proto sketch), registration/delivery, policy integration, ordering, metadata, audit/logging.
- [done] Prior art (kept inline in the README, not a separate appendix).
- [done] Terminology.
- [done] Implementation plan.
- [todo] Risks.
- [todo] Alternatives.
- [todo] Open questions.

## Planned Appendices

- [done] `appendices/deployment-options.md`: external-service decision and future options (sandboxed middleware, WASM, managed image/sidecar).
- [done] `appendices/protocol-extensions.md`: streaming (transport vs processing, 4 MB limit, now-or-never oneof), additional hooks, semantic context, content preview, portable capabilities, header rules. (Subsumes much of the old `future-extensions.md` idea.)
- [todo] `appendices/request-response-contract.md`: full request/response schema, decision model, metadata fields, transformation semantics. (README has only a simplified sketch.)
- [todo] `appendices/policy-integration.md`: full policy schema and composition with existing OPA/Rego evaluation.
- [todo] `appendices/pipeline-placement.md`: exact placement in the supervisor relay path vs network/L7 policy and credential injection (credential handling is interleaved with L7 today; verify against real relay code).
- [todo] `appendices/failure-and-audit.md`: fail-open/closed, timeout/retry, OCSF field mappings, sensitive-value handling.
- Dropped: `appendices/prior-art.md` (prior art lives inline in the README). `appendices/future-extensions.md` folded into `protocol-extensions.md`.

## Visuals To Include

- Current proxy flow: show how sandbox egress moves through the supervisor relay today, including policy checks, route selection, credential injection, and upstream forwarding.
- Proposed hook placement: show where the egress middleware call plugs into the existing flow, especially relative to network/L7 policy and credential injection.
- Configuration flow: show gateway configuration feeding sandbox bundle generation, the supervisor receiving middleware registration data, and policy selecting the registered middleware for specific egress rules.

Prefer Mermaid diagrams in the main RFC when they clarify the core proposal. Move lower-level or alternative diagrams into appendices.

## Required RFC Pieces

- [done] Terminology: defines `egress` (OpenShell-specific: admitted, parsed request, not raw packets), `middleware`, `registered middleware`, `built-in middleware`, `hook`, `middleware config`, `capabilities`, `decision`, `transformation`, `finding`, `metadata`, `chain`. Placed between Non-goals and Proposal.
- [done] Gateway configuration: operators register middleware via `[[openshell.proxy.middleware]]` (name + endpoint). Auth material and timeout defaults not yet fully specified.
- [partial] Supervisor configuration delivery: README says it reuses the existing authenticated config path. Exact delivery shape still open - extend `GetSandboxConfig` / `SandboxPolicy` or add a `GetInferenceBundle`-style bundle RPC (see open question below).
- [done] Middleware capability discovery: `GetCapabilities` + simplified proto sketch in the contract section.
- [partial] Capability response fields: sketch covers name, version, hooks, max body, timeout, metadata namespaces. Full field list deferred to the request-response-contract appendix.
- [done] Middleware inspection RPC: `ProcessRequestBeforeUpstream` request/response sketched (bidi stream, single-message v1, `{context, body}` / `{verdict, body}`).
- [done] Policy shape + middleware section: top-level `network_middlewares` list referenced by `middleware: [...]` on network policies; chains; `on_error`.
- [done] Failure behavior: `on_error` per middleware, fail-closed by default; capability validation fails the config load.
- [done] Audit/logging: OCSF categories (HttpActivity, DetectionFinding, ConfigStateChange) + safety rules. Field mappings deferred to failure-and-audit appendix.
- [done] Model routing handoff: metadata section; router out of scope (#1734).

## Decisions

- Deployment: externally managed service; other modes deferred (deployment-options appendix).
- Decision vocabulary is `allow`/`deny` (consistent with the rest of the policy system).
- Single hook in v1: `request.before_upstream`; the design is extensible to more hooks.
- Hook runs only on L7-introspected (HTTP) traffic; opaque/L4 is out of scope.
- Middleware is opt-in via policy; existing usage is unaffected and pays no hot-path cost.
- Registration is operator-owned (gateway config, name + endpoint); policy references by name only (preserves trust boundary). Endpoint sees raw payloads.
- Built-in middleware ships in the supervisor, served in-process over the same gRPC contract; reserved `openshell-` name prefix.
- Multiple middleware run as an ordered chain (chains are in v1; supersedes thought-01's single-middleware decision). Order = policy `middleware: [...]` list; globally-included middleware run before, in `network_middlewares` order; each runs at most once.
- Top-level policy section is `network_middlewares` (chosen over `request_middlewares` for the umbrella/`network_policies` pairing).
- Hot-path RPC is declared as a bidi stream but exchanges a single message each way in v1 (cardinality cannot change compatibly; streaming added later). Messages stay flat with nested `RequestContext`/`Verdict` (no phase `oneof` - that is a now-or-never choice we declined).
- Capability validation runs at gateway config load, on policy reference, and at supervisor startup; failure fails the load.
- Findings become structured, namespaced metadata for a future model router; router out of scope (#1734).
- Model routing tracked separately: https://github.com/NVIDIA/OpenShell/issues/1734.

## Open Drafting Questions

Resolved this round:

- Smallest useful contract -> sketched (`GetCapabilities`, `ValidateConfig`, `ProcessRequestBeforeUpstream`).
- Optional vs required middleware -> per-middleware `on_error` (`allow`/`deny`), fail-closed default.
- Capability validation timing / "before sandbox starts" -> gateway load + policy reference + supervisor startup.
- Which audit events belong in the RFC -> event categories in the RFC, field mappings in an appendix.

Still open:

- Should v1 target all HTTP egress, only model-bound HTTP egress, or any relay-supported protocol? (Currently: all L7-introspected HTTP.)
- Delivery path: extend the existing sandbox config response (`GetSandboxConfig` / `SandboxPolicy`), or add a dedicated bundle RPC in the style of `GetInferenceBundle`? (Note: there is no `GetSandboxBundle` RPC today; earlier notes naming it were inaccurate.)
- Exact metadata namespacing scheme (leaning: derive from middleware name) - deferred until a consumer exists.
- Is the two-selector surface (`requests:` on a middleware entry vs the per-policy `middleware: [...]`) both needed, or should one win?
- Should middleware capability discovery be strictly mandatory before accepting referencing policy? (Leaning yes.)

## Drafting Queue (next)

- Write Risks, Alternatives, Open questions sections.
- Fill the pipeline-placement appendix from the real supervisor relay path.
- Expand the request-response-contract and policy-integration appendices beyond the README sketches.
- Write the failure-and-audit appendix (OCSF field mappings).
- Decide and document the "research preview" framing (see below).

## Limits, failure modes, and limitations (to cover)

These need a home in the RFC - likely a "Limits and limitations" section plus content in Risks and the failure-and-audit appendix.

- **Limits and timeouts.** Define how request size limits and call timeouts are enforced and by whom. Core tension to capture: rejecting an over-limit request can break sandbox workloads (e.g. inference calls whose context grows each turn until it exceeds the cap), but allowing it through unprocessed means content that should have been redacted egresses anyway. Decide the default and whether it is policy-configurable (ties into the `on_error` / over-cap skip behavior). Reconcile with the proxy's current 256 KiB buffering cap and the capability `max_body_bytes`.
- **Failure modes / rate limiting.** The middleware service is responsible for its own rate limiting; OpenShell does not rate limit middleware calls. Document this, plus behavior when the middleware is overloaded or unavailable (fail-closed by default).
- **Content encoding (gzip).** Define how gzip/compressed HTTP request bodies are handled: does OpenShell decode before the hook, or does the middleware receive the encoded bytes and decode itself? Pick one and state it (also affects size-limit accounting: encoded vs decoded size).
- **Chunked / slow-drip uploads.** How chunked transfer-encoding and slow "drip" uploads interact with buffering and timeouts. Note this is already a constraint for credential injection, which buffers the request today - document the existing behavior and whether middleware changes it.
- **Opaque payloads (limitation).** Payloads that are zipped, otherwise encoded, or encrypted cannot be introspected. State explicitly that middleware can only act on content it can parse; opaque bodies cannot be inspected, so policy must decide whether such traffic is allowed through or denied.
- **TLS-termination requirement (limitation).** Initially, middleware only runs on traffic OpenShell TLS-terminates and introspects at L7. If traffic is allowed at L4 and not TLS-terminated (e.g. opaque TCP/TLS passthrough), the hook is never invoked and the middleware is silently bypassed. State this explicitly and reconcile with the fail-closed stance: attaching middleware to an endpoint implies that endpoint must be L7-introspected, so policy cannot fall back to L4 to skip a required middleware.

## Framing

- Consider presenting this initial state of middleware as a **research preview**: set expectations that the contract, scope, and stability are provisional and may change. Decide where to say it (Summary and/or Current Status) and what it implies for support and compatibility guarantees.

## Potential ideas to explore

- For a hook that runs post-credential injection (e.g. SigV4), only allow first-party (built-in) implementations, so credentials never leave the sandbox.