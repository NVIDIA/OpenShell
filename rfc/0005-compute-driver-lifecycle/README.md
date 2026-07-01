---
authors:
  - "@priel"
state: draft
links:
  - (related PRs, discussions, or issues)
---

# RFC 0005 - Compute Driver Lifecycle Extensions

<!--
See rfc/README.md for the full RFC process and state definitions.
-->

## Summary

Add a single, driver-agnostic **lifecycle extension** surface inside the gateway's compute subsystem. Rust code linked into the gateway can hook into sandbox create, delete, and reconcile flows around any compute driver without modifying the compute subsystem or the driver. Extensions are declared per deployment, run in an ordered chain, and persist their own state alongside sandbox state.

The surface does not change the `ComputeDriver` contract and is not a replacement for it. It is a way to attach gateway-side behavior around it. The same extension chain works whether the active driver is in-band (a Rust crate linked into the gateway, e.g. Docker, Podman, Kubernetes) or out-of-band (a subprocess reached over gRPC, e.g. the VM driver).

## Motivation

The gateway's compute subsystem owns sandbox lifecycle and delegates platform-specific work to a compute driver through the `ComputeDriver` trait (`CreateSandbox`, `DeleteSandbox`, `WatchSandboxes`, `Reconcile`). Some drivers implement that trait directly in-process; others are subprocesses that the gateway reaches through a gRPC client that implements the same trait. Either way the boundary is intentionally narrow: it only covers what the driver itself must do.

In practice, deployments also want to attach **gateway-side** behavior to the sandbox lifecycle without modifying core code:

- Inject deployment-specific environment variables, labels, or volume mounts into the sandbox spec before the driver creates the sandbox.
- Acquire and release an external resource (a leased IP, a workload identity binding, a hardware reservation) around create and delete.
- Reconcile that external resource against persisted state on gateway restart.

Without a shared surface, every such integration either forks the gateway or grows its own one-off patch in the compute subsystem, each with its own hook shape, state persistence, and failure-handling story. A single surface gives all these integrations one stable place to plug in and keeps the compute subsystem free of integration-specific branches.

## Non-goals

- **The `ComputeDriver` contract.** Extensions wrap calls to a driver; they do not replace one. The trait (and its gRPC service form, used by out-of-band drivers) is unchanged.
- **Untrusted code.** Extensions are Rust code linked into the gateway at build time and run with full gateway privileges. Untrusted integrations belong behind the `ComputeDriver` boundary as an out-of-band driver, not here.
- **Dynamic loading.** No `dlopen`-style runtime loading. All extensions are statically linked.
- **Sandbox semantics.** Phase transitions, ownership, reconcile cadence, and watch semantics stay owned by the compute subsystem. Extensions observe and decorate them; they do not redefine them.
- **Sandboxing of extensions.** Trust is conferred by build inclusion. We do not propose a mechanism for isolating extensions from the rest of the gateway.

## Proposal

### Where the extension surface lives

Extensions sit inside the gateway's compute subsystem, **between** the subsystem's lifecycle logic and the per-call dispatch to the active `ComputeDriver`:

```text
gateway compute subsystem
   │
   ├── lifecycle logic (phases, retries, reconcile)
   │
   ├── extension chain      ← this RFC
   │
   └── ComputeDriver dispatch
         ├── in-band driver (e.g. Docker, Podman, Kubernetes)
         └── out-of-band driver (gRPC client → driver subprocess, e.g. VM)
```

This placement keeps extensions driver-agnostic. The chain wraps the `ComputeDriver` trait, so the same extensions run regardless of whether the call resolves to a Rust implementation in the gateway process or to a gRPC call into a driver subprocess.

### Phases

A `LifecycleExtension` trait defines a small, fixed vocabulary of phases the gateway invokes:

- `before_create` — the gateway is about to call `CreateSandbox`. The extension may add to the outgoing request (labels, env, annotations, volume mounts) and may produce state to be persisted.
- `after_create_success` — `CreateSandbox` returned success.
- `after_create_failed` — `CreateSandbox` failed, or an earlier extension in the chain failed. The extension rolls back what its own `before_create` did. Must be idempotent.
- `before_delete` — the gateway is about to call `DeleteSandbox`. The extension quiesces external resources.
- `after_delete` — `DeleteSandbox` completed. Last chance to release extension-owned resources.
- `reconcile` — on gateway startup and periodic reconcile, for every persisted `(sandbox, extension)` pair. Re-establishes in-memory state and reports any drift.

Every phase is async, runs under a deadline, receives a context (sandbox id, tracing span, cancellation), and returns a `Result<_, ExtensionError>`. Every phase except `before_create`, `after_create_failed`, `after_delete`, and `reconcile` has a default no-op so trivial extensions stay small.

### Request additions, not request rewrites

`before_create` receives the pending sandbox request as an **additive builder** (`add_env`, `add_label`, `add_mount`, `add_annotation`). Extensions can add fields but cannot remove driver-required fields and cannot override a value already set by the gateway or by an earlier extension in the chain. The builder enforces this; it is not a convention.

### Extension state

Each extension produces an opaque, versioned state blob in `before_create` (`{ schema_version: u32, payload }`) that the gateway persists alongside the sandbox record, namespaced by `(sandbox_id, extension_name)`. Later phases receive the most recent persisted blob and may return a replacement. The gateway owns serialization, atomicity, and cleanup; the extension owns the schema.

A schema-version the extension does not recognize is a hard failure that surfaces as a sandbox-level error and waits for operator intervention. State is deleted only after `after_delete` returns success.

### Chain composition

Each gateway is configured with an ordered list of extensions. Ordering rules:

- `before_create` runs in declared order. Each extension sees the request as modified by earlier extensions.
- `after_create_success`, `after_create_failed`, `before_delete`, and `after_delete` run in **reverse** order, so an extension's rollback always precedes the rollback of anything that ran before it.
- `reconcile` order is implementation-defined; reconcile is expected to be commutative.

If any `before_create` returns `Err`, the chain stops, `CreateSandbox` is not called, and `after_create_failed` is invoked on every extension that already ran `before_create`, in reverse order.

### Configuration

Extensions are linked into the gateway binary at build time and activated per deployment in the gateway configuration file:

```toml
[compute]
extensions = ["fleet-labels", "workload-identity"]
```

Order in the list is chain order. Unknown extension names are a startup error. An equivalent `OPENSHELL_COMPUTE_EXTENSIONS` environment variable is also accepted, consistent with the rest of the gateway CLI/env model.

## Implementation plan

1. Define `LifecycleExtension`, `LifecycleContext`, `ExtensionState`, `ExtensionError`, and `ReconcileOutcome` in a new `openshell-compute-ext` crate that the gateway and any in-tree extension crate depend on.
2. Wire the extension chain into the compute subsystem's create, delete, and reconcile paths. Empty and single-element chains are the default and exhibit no behavior change.
3. Extend the gateway sandbox-state store with a `(sandbox_id, extension_name) → ExtensionState` namespace and a startup reconcile pass over it.
4. Add the `compute.extensions` field to the gateway configuration file and the matching environment variable. Validate names against the compiled-in registry at startup.
5. Ship a reference no-op extension in `crates/openshell-extension-example` as a template for downstream authors.
6. Update `architecture/compute-runtimes.md` to describe the extension surface and add `architecture/extensions.md` for extension authors.
7. Tests: phase order, reverse-order rollback, partial-chain failure, reconcile invocation on restart, error and timeout propagation, schema-version mismatch.

## Risks

- **API coupling.** Once published, the extension surface becomes a hidden public contract for downstream gateways. Mitigation: keep the trait small, default methods where safe, and require additions to go through the RFC process.
- **Misbehaving extensions.** A poorly-written extension can deadlock, panic, or take too long. Mitigation: every phase runs under a configurable deadline (default 30 s) and is cancelled on timeout, surfaced as `ExtensionError::Timeout`. Panics are isolated to the extension and surfaced as errors.
- **State-store growth.** Per-sandbox-per-extension blobs add to gateway persistence. Mitigation: extensions garbage-collect state in `after_delete`; the gateway surfaces extension-state size and per-extension counts in metrics.
- **Chain semantics are subtle.** Reverse-order rollback and conditional rollback after partial chain failure are easy to misimplement. Mitigation: a reference extension, an integration test that covers the partial-failure path, and a short author guide.
- **Trust assumption.** Extensions run with full gateway privileges. Mitigation: this is explicit in the contract; untrusted integrations belong behind the `ComputeDriver` boundary as an out-of-band driver.

## Alternatives

- **Do nothing; accept per-integration patches.** Rejected: every integration grows its own hook shape, persistence path, and failure semantics. The cross-integration consistency story is the value.
- **Push the surface into each driver.** Rejected: out-of-band drivers may be written in other languages and reached over gRPC; an extension trait inside each driver would have to be reimplemented per language. Even for in-band Rust drivers it would duplicate the same code per driver. A single chain in the compute subsystem covers both shapes.
- **Dynamic plugin loading (`dlopen`).** Rejected: Rust ABI stability is fragile and the trust model does not require it.
- **Aspect-style single method with a phase enum.** Rejected: discrete trait methods are more discoverable, give better defaults, and are easier to type-check.

## Prior art

- **Kubernetes admission webhooks** (`MutatingAdmissionWebhook`, `ValidatingAdmissionWebhook`). Same plan-mutation and ordered-chain pattern, applied to untrusted webhooks rather than trusted extensions.
- **OCI runtime hooks** (`prestart`, `poststart`, `poststop`). Same lifecycle vocabulary.
- **Envoy filter chains.** Same chain-composition pattern of ordered pre-filters and reverse-order post-filters.
- **Terraform provider hooks and Nomad task-driver lifecycle.** Same shape for wrapping a remote provider with local logic.

## Open questions

- Should `reconcile` be authoritative (mutate external resources to match state) or advisory (log and alert), or extension-by-extension? Lean: extension decides via `ReconcileOutcome`, default advisory.
- Should out-of-tree extensions be a first-class supported model (a downstream builds its own gateway binary with extra extensions linked) or strictly internal? Lean first-class, with best-effort API stability.
- Should we add a `dry_run` phase for previewing planned mutations without committing? Useful for the policy advisor; out of scope for v1.
- Should extensions be able to attach their own tracing spans and OCSF events beyond what the framework supplies? Lean yes; `LifecycleContext` should carry a span that extensions extend.
