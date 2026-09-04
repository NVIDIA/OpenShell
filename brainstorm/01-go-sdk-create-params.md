# Brainstorm: Go SDK Create() params struct

**Date:** 2026-09-04
**Status:** active
**Issue:** [#2807](https://github.com/NVIDIA/OpenShell/issues/2807)

## Problem Framing

The Go SDK's `SandboxInterface.Create()` takes 7 positional parameters plus variadic opts after the sandbox templates refactor in PR #2781. Four consecutive nilable parameters of different types make call sites unreadable (`client.Sandboxes().Create(ctx, "default", "my-sandbox", nil, nil, nil, nil)`). The underlying cause is that Go reuses `SandboxSpec` for both creation input and resolved state, leaking gateway-only fields like `DriverConfig` into the caller surface. Rust and TypeScript already solved this with distinct creation-only types.

## Approaches Considered

### A: Creation params struct (Chosen)

Introduce `CreateSandboxParams` that bundles the optional positional args (workload, policy, providers, labels). Keep the existing `SandboxSpec` as-is for the resolved output. This matches the existing SDK convention where `ProviderInterface.Create` and `ConfigInterface.Update` already pass typed structs.

- Pros: Small diff, solves readability, prevents callers from setting `DriverConfig`, consistent with existing SDK patterns
- Cons: Doesn't rename or restructure the resolved `SandboxSpec`, so the "same name, different concept" issue across SDKs persists

### B: Full separation (creation and resolved types)

Introduce `CreateSandboxParams` AND restructure the output side so creation vs. resolved are clearly distinct types. Ensure `SandboxSpec` is documented as gateway-resolved-only.

- Pros: Clean semantic model matching Rust/TS, future-proof
- Cons: Larger diff, touches more call sites, scope creep risk

### C: Functional options pattern

Replace positional params with Go-idiomatic functional options (`WithWorkload()`, `WithPolicy()`, etc.).

- Pros: Most Go-idiomatic in general, infinitely extensible
- Cons: Would be the only creation method in the SDK using this pattern. All existing mutation/creation methods use either struct params or positional args. Functional options exist only on read/query paths (`LogOption`, `GetDraftOption`). Doesn't address the `SandboxSpec` dual-use problem.

### Reference: Kubernetes client-go pattern

K8s uses the same type for creation input and output (`*v1.Pod` goes in, `*v1.Pod` comes back), but it works because of the strict Spec/Status separation convention within every resource type. OpenShell's `SandboxSpec` doesn't have that split, so achieving the same clarity requires a separate creation type.

## Decision

Approach A: introduce `CreateSandboxParams` struct. This follows the established SDK convention (struct params for complex creation, matching `ProviderInterface.Create`) while solving the concrete readability and type-safety problems. The k8s functional options pattern was considered but rejected because no existing creation method in the SDK uses it, making it an outlier.

This is an independent improvement, not tied to PR #2781's timeline. The templates PR can adjust to this pattern if it lands first.

## Key Requirements

- Introduce `CreateSandboxParams` struct with workload, policy, providers, labels fields
- Change `SandboxInterface.Create()` signature: `Create(ctx, workspace, name string, params CreateSandboxParams, opts ...CreateOptions)`
- Apply the same pattern to `CreateFromTemplate()` if it has a similar positional parameter list
- Update all call sites (tests, examples, internal usage)
- Keep existing `SandboxSpec` unchanged for resolved output
- Ensure `CreateSandboxParams` excludes gateway-resolved fields (`DriverConfig`)

## Open Questions

- Exact field list for `CreateSandboxParams` needs verification against current `Create()` signature and the proto `CreateSandboxRequest`
- Should `name` and `workspace` be pulled into the params struct (like Rust/TS do) or stay as positional args (like k8s client-go)?
- Whether to file a separate issue for `ServiceInterface.Expose` which has a similar positional args smell
- Whether to file a separate issue for Python's missing curated creation type
