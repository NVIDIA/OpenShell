---
authors:
  - "@anewberry"
state: accepted
links:
  - https://github.com/NVIDIA/OpenShell/issues/1919
---

# RFC 0010 - Gateway Interceptors

## Summary

Operators and external integrators need a flexible way to customize gateway API
behavior to fit their own requirements — for example, enforcing tenancy,
quotas, naming conventions, or policy authority. Today any such customization
has to be hardcoded into gateway handlers or pushed into drivers, which mixes
responsibilities and does not scale to deployment-specific requirements.

This RFC proposes a first-class extension system that lets external services
observe, modify, validate, reject, or audit gateway operations at well-defined
phases. We call these **Gateway Interceptors**.

Gateway interceptors and drivers serve different extension needs. The gateway
interceptor role adds business logic around gateway operations. Drivers replace
or provide implementation for platform functionality, such as how sandboxes are
provisioned on Docker, Kubernetes, or VMs.

This RFC scopes gateway interceptors to gateway API operations. A gateway
interceptor can observe, modify, validate, reject, or audit a gateway operation
at well-defined phases. Future RFCs may extend gateway interceptors to other
gateway functionality, such as event-driven or workflow behavior, but that is
out of scope for this first implementation.

Drivers continue to own platform implementation — how gateway functionality is
actually provided. Gateway interceptors own gateway-level governance for
resource writes: tenancy, quotas, naming, policy authority, and driver
configuration restrictions.

The gateway database remains the system of record. Gateway interceptors add
governance around gateway operations; they do not replace gateway-owned state.

## Motivation

Operators running OpenShell in their own environments need to apply
deployment-specific rules to gateway operations that core OpenShell does not
encode. Examples include:

- Sync policies and providers from an external source of truth.
- Enforce one system-wide sandbox policy and reject custom sandbox policies.
- Verify policy writes against an external authority before accepting them.
- Restrict driver configuration payloads to an approved schema or fixed value.
- Limit each user to a maximum number of running sandboxes.

These are not core OpenShell semantics. They vary per deployment, and the set
changes over time, so they are not a good fit for a fixed set of built-in
options.

OpenShell already extends two of its subsystems. Drivers (RFC 0001) provide
implementations for the platform and infrastructure layer. Sandbox egress
middleware (RFC 0009) runs in the supervisor proxy and governs what an agent's
outbound requests may carry. Gateway interceptors complete this pattern for the
gateway control plane: an extension point for the API operations themselves,
where deployment-specific rules like tenant quotas, policy authority, and
naming belong.

Some of these may ship as built-in gateway defaults over time. Gateway interceptor
services do not replace that — they let a deployment extend or override built-in
defaults when its rules differ, without waiting on an upstream change.

Without a dedicated mechanism, operators carry these rules as gateway forks or
local patches.

## Non-goals

- Replacing compute drivers or adding a second compute provisioning interface.
- Letting gateway interceptors bypass gateway authentication, authorization,
  policy safety validation, or driver schema validation.
- Moving sandbox runtime enforcement out of the sandbox supervisor and proxy.
- Replacing the gateway database as the system of record.
- Adding new first-class gateway resource kinds for quotas, name policies,
  policy bundles, or driver config policy.

## Proposal

Add a gateway interceptor framework with explicit phases, RPC method selectors,
deterministic ordering, bounded execution, audit logging, and conservative
failure behavior.

Gateway interceptors do not replace gateway functionality. They add governance
and business logic around gateway operations: defaulting, validation, rejection,
and audit. Replacing how core functionality is implemented remains the role of
drivers and other provider-style interfaces.

The design keeps two boundaries intact:

- The gateway database remains the system of record for gateway-owned state.
- Existing gateway and driver validation still run after gateway interceptor
  modification.

### Gateway interceptors

A gateway interceptor runs during a gateway API operation, such as creating a
sandbox, importing provider profiles, updating policy, or applying sandbox
configuration. It may modify a gateway-prepared operation only in
`modify_operation`. It may reject in `modify_operation` or `validate`. It may
attach warnings and audit annotations in all phases.

Gateway interceptor services expose one or more bindings. A binding is a
service-declared rule that maps the service to phases, gateway RPC methods, and
selectors. The gateway uses bindings to decide when to call the service.

The public gRPC service and method identify the API operation. The v1 selector
vocabulary uses fully qualified RPC names, for example
`openshell.v1.OpenShell/CreateSandbox`. This keeps binding configuration tied
to the public API operators already know and avoids another compatibility
surface.

All interceptable gateway API RPCs run through the same standard phase pipeline.
The gateway rejects gateway interceptor bindings that reference unknown RPCs for
the running gateway version, unless the RPC selector is empty to match all
interceptable RPCs.

Gateway interceptors should work for all relevant gateway RPCs, not a
hand-maintained subset. New gateway RPCs should enter the gateway interceptor
pipeline by using the shared gateway API execution path, not by adding per-RPC
gateway interceptor hooks or updating a separate allowlist. RPCs may opt out
only when they are not gateway API operations in scope for this RFC, such as
low-level streaming or supervisor-internal calls, and the opt-out should be
explicit in code review.

This lets OpenShell add deployment-specific business logic around the gateway
operations it already supports while keeping runtime reads local and
deterministic.

### Operation phases

Operation phases are ordered. Later phases see the result of earlier phases. All
interceptable gateway API RPCs use the same phases in the same order so
gateway interceptor authors and operators do not need per-RPC phase rules.

| Phase | Modification allowed | Purpose | Examples |
|---|---:|---|---|
| `modify_operation` | yes | Apply deployment defaults or controlled changes after the gateway prepares the operation input. | Normalize labels, stamp a default sandbox policy, select a provider profile, or clamp resource limits to deployment defaults. |
| `validate` | no | Enforce deployment-specific rules before persistence, provisioning, or other side effects. | Enforce tenant quotas, reject policy updates that allow internet egress, or verify driver config against an approved schema. |
| `post_commit` | no | Emit audit or notify external systems after successful persistence or provisioning. | Send audit records, notify an inventory system, or trigger a reconciliation job after a successful write. |

The gateway rejects malformed raw API requests before gateway interceptor
execution. Gateway interceptors operate on valid gateway operations, not
low-level request decoding or shape repair.

Gateway invariants run after modification so gateway interceptors cannot leave
invalid objects in the system. Operation-specific built-in validation, including
driver validation where applicable, remains part of the gateway-owned execution
path so drivers stay the authority for driver-owned schemas.

### Gateway interceptor request contract

Each gateway interceptor is a registered service instance that implements the
`GatewayInterceptor` gRPC service:

```proto
service GatewayInterceptor {
  rpc Describe(DescribeRequest) returns (InterceptorManifest);
  rpc Evaluate(InterceptorEvaluation) returns (InterceptorResult);
}

// Empty today so Describe can grow additively later.
message DescribeRequest {}

enum GatewayInterceptorPhase {
  GATEWAY_INTERCEPTOR_PHASE_UNSPECIFIED = 0;
  GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION = 1;
  GATEWAY_INTERCEPTOR_PHASE_VALIDATE = 2;
  GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT = 3;
}
```

The gateway interceptor request must be stable and tied to public gateway
API, not to Rust handler internals.

```proto
message InterceptorEvaluation {
  // Gateway-configured gateway interceptor service name.
  string interceptor_name = 1;
  // Service-declared binding that selected this evaluation.
  string binding_id = 2;
  // Fully qualified public gateway gRPC service name.
  string rpc_service = 3;
  // Public gateway RPC method name.
  string rpc_method = 4;

  // Authenticated gateway principal for the API request.
  string principal = 5;
  // Additional gateway-provided request context.
  map<string, string> context = 6;

  oneof phase {
    // Evaluation that may modify the prepared gateway operation.
    ModifyOperationEvaluation modify_operation = 7;
    // Evaluation that may reject, but not mutate, the prepared operation.
    ValidateEvaluation validate = 8;
    // Evaluation after the gateway operation has committed.
    PostCommitEvaluation post_commit = 9;
  }
}

message ModifyOperationEvaluation {
  // Gateway-prepared operation the gateway proposes to execute.
  google.protobuf.Struct proposed_operation = 1;
  // Gateway-owned resource state loaded before applying the proposed operation.
  google.protobuf.Struct current_state = 2;
}

message ValidateEvaluation {
  // Gateway-prepared operation after defaulting and modification.
  google.protobuf.Struct proposed_operation = 1;
  // Gateway-owned resource state loaded before applying the proposed operation.
  google.protobuf.Struct current_state = 2;
}

message PostCommitEvaluation {
  // Gateway operation that was committed.
  google.protobuf.Struct proposed_operation = 1;
  // Gateway-owned resource state loaded before applying the committed operation.
  google.protobuf.Struct current_state = 2;
}
```

The `rpc_service` and `rpc_method` fields are the split form of the fully
qualified RPC selector used by bindings. For example,
`openshell.v1.OpenShell/CreateSandbox` becomes
`rpc_service = "openshell.v1.OpenShell"` and
`rpc_method = "CreateSandbox"`.

The gateway sets exactly one `phase` variant per evaluation. The active variant
identifies the selected phase and determines which payload is available.
`proposed_operation` is the gateway-prepared operation after state loading,
defaulting, and prior patches; it is present for `modify_operation`, `validate`,
and `post_commit`. `current_state` accompanies prepared-operation phases as
read-only context when the gateway loaded prior gateway-owned state.

The gateway interceptor response returns an allow/deny result, optional
patches, and diagnostic metadata for selected gateway operations.

```proto
message InterceptorResult {
  bool allowed = 1;
  string reason = 2;
  string status_code = 3;
  repeated JsonPatch patches = 4;
  repeated string warnings = 5;
  map<string, string> audit_annotations = 6;
}
```

The gateway projects a valid `InterceptorResult` onto the gateway operation.
`allowed = true` lets the operation continue. `allowed = false` rejects the
gateway API operation in `modify_operation` or `validate`, using `status_code`
and `reason`. Only `modify_operation` accepts patches, and those patches apply
to `modify_operation.proposed_operation`. `current_state` is read-only context
and is never patched. `warnings` and `audit_annotations` are projected into
gateway response metadata and logs where applicable. `post_commit` runs after
the gateway operation has committed, so it cannot reject or mutate the
operation. A `post_commit` result with `allowed = false` or patches is a gateway
interceptor contract violation.

The `binding_id` is owned by the gateway interceptor service. It identifies the
service-declared binding that selected the evaluation.

### Gateway interceptor endpoints

The framework uses one protobuf/gRPC service contract. Gateway interceptor
endpoints connect over gRPC, either to a remote endpoint or over a Unix domain
socket.

All gateway interceptor connections require authentication. The exact
authentication model is out of scope for this RFC, but implementations should
support mTLS and bearer-token authentication.

### Selection and ordering

Selection should be oriented around gateway interceptor services, not individual
phase/RPC routes. Operators should normally configure a small number of these
services and service-specific settings. The service tells the gateway which RPC
bindings it supports.

A `[[openshell.gateway.interceptors]]` table in the gateway config TOML
represents one gateway interceptor service instance. During gateway startup or
config reload, the gateway calls a `Describe` RPC on the service. The response
describes the service's default bindings:

```proto
message InterceptorManifest {
  repeated InterceptorBinding bindings = 1;
}

message InterceptorBinding {
  string id = 1;
  repeated GatewayInterceptorPhase phases = 2;
  repeated string rpcs = 3;
  int32 order = 4;
  string on_error = 5;
  InterceptorSelector selector = 6;
}

message InterceptorSelector {
  repeated string principals = 1;
  map<string, string> labels = 2;
}
```

By default, the gateway enables the bindings returned by the service manifest.
Operators can configure the service once, then optionally override specific
bindings when they need to disable, narrow, or reorder behavior. Overrides
should only narrow service-declared selectors unless a future RFC explicitly
allows expansion.

Empty selector fields match all values. A gateway override can narrow a
service-declared selector, such as limiting a binding to a specific RPC.
Patch capability is derived from the selected phase, not from a separate binding
flag. A binding in `modify_operation` may return zero or more patches. A
binding in `validate` or `post_commit` must not return patches.

Gateway config example for a remote policy provider:

```toml
[[openshell.gateway.interceptors]]
name = "policy-provider"
grpc_endpoint = "https://policy-provider.example.com:8443"
order = 100
failure_policy = "fail_closed"
timeout = "500ms"
```

The service manifest keeps common configuration terse. Operators do not need to
know which phase each behavior runs in; the service exposes those bindings.

The gateway builds an execution plan from enabled bindings. Selection evaluates
the service-declared RPC, phase, principal, and label selectors, then applies
gateway-configured narrowing overrides.

Gateway interceptors run in fixed phase order. Within a phase, matching
bindings run by this deterministic ordering:

1. configured gateway interceptor service `order`.
2. service-declared binding `order`, after gateway overrides.
3. gateway interceptor service name.
4. binding ID.

Patches are applied in binding execution order. Invalid patches, conflicting
patches, or patches returned from a non-modification phase are invalid gateway
interceptor results.

### Failure policy

Failure policy is gateway control-plane behavior for cases where the gateway
cannot obtain or apply a valid gateway interceptor result. Examples include
timeout, transport failure, service error, invalid response, response-size
violation, invalid phase behavior, or patch limit violation. A valid
`allowed = false` result in `modify_operation` or `validate` is not an
error-policy case; the gateway must project it as an operation rejection.

Each binding has an effective failure policy. The gateway starts with the
service-declared binding `on_error` value, applies the gateway interceptor
service-level gateway config, then applies any binding override.

| Failure policy | Behavior |
|---|---|
| `fail_closed` | The gateway rejects the API operation before committing side effects. |
| `fail_open` | The gateway continues without applying the failed gateway interceptor result and emits warning and audit events. |

Defaults:

- `modify_operation` and `validate` bindings default to `fail_closed`.
- `post_commit` bindings default to `fail_open`.

The gateway enforces a timeout and response size limit for every gateway
interceptor service call. Each binding also has a maximum patch count.

### Observability and audit

Every gateway interceptor result should emit structured gateway logs with:

- gateway interceptor name
- binding ID
- phase
- RPC service and method
- principal
- result
- reason
- latency
- failure policy
- patch count
- audit annotations

Security-relevant denials should be emitted as OCSF detection findings or
configuration/security events, depending on the event class. Non-security
operational failures can use plain tracing.

### Example: remote policy provider

A gateway interceptor should start from the invariant it wants to preserve, then
find every gateway API RPC that can establish or weaken that invariant. For
example, an operator may want a remote policy provider to be the authority for
sandbox policy decisions.

Two RPCs matter for this invariant:

- `openshell.v1.OpenShell/CreateSandbox` establishes the initial sandbox policy.
- `openshell.v1.OpenShell/UpdateConfig` changes sandbox or global policy.

The gateway interceptor service declares one binding to apply an approved
initial policy and another to guard later policy changes:

```proto
InterceptorManifest {
  bindings: [
    {
      id: "sandbox-policy-default"
      phases: [GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION]
      rpcs: ["openshell.v1.OpenShell/CreateSandbox"]
      on_error: "fail_closed"
    },
    {
      id: "policy-authority"
      phases: [GATEWAY_INTERCEPTOR_PHASE_VALIDATE]
      rpcs: ["openshell.v1.OpenShell/UpdateConfig"]
      on_error: "fail_closed"
    }
  ]
}
```

The handler can then focus on the active phase variant and RPC method that
selected the binding:

```rust
// Toy implementation of the GatewayInterceptor Evaluate RPC.
async fn evaluate(&self, req: InterceptorEvaluation) -> InterceptorResult {
    use interceptor_evaluation::Phase;

    match (req.rpc_method.as_str(), req.phase.as_ref()) {
        // CreateSandbox: ask the remote policy provider for the approved
        // initial policy and stamp it into the prepared operation input.
        ("CreateSandbox", Some(Phase::ModifyOperation(phase))) => {
            let approved_policy = self
                .policy_provider
                .initial_policy(&phase.proposed_operation)
                .await;

            InterceptorResult::allow().with_patch(JsonPatch::replace(
                "/policy",
                approved_policy,
            ))
        }

        // UpdateConfig: reject policy writes the remote provider does not approve.
        ("UpdateConfig", Some(Phase::Validate(phase))) => {
            let validation = self
                .policy_provider
                .validate_update(&phase.proposed_operation, &phase.current_state)
                .await;
            if !validation.allowed {
                return InterceptorResult::reject(
                    "PERMISSION_DENIED",
                    validation.reason,
                );
            }

            InterceptorResult::allow()
        }

        // The service should only receive bound RPCs, but defaulting to allow
        // keeps the handler safe if the manifest grows later.
        _ => InterceptorResult::allow(),
    }
}
```

The gateway config can stay small because the service manifest declares the
bindings:

```toml
[[openshell.gateway.interceptors]]
name = "policy-provider"
grpc_endpoint = "https://policy-provider.example.com:8443"
order = 100
failure_policy = "fail_closed"
timeout = "500ms"
```

This example illustrates the general gateway interceptor design loop:

- Start with the invariant, then identify every RPC that can establish or weaken
  it.
- Pick the phase by intent: `modify_operation` to apply an approved initial
  policy and `validate` to reject unauthorized later changes.
- Use `fail_closed` because policy authority is a control-plane security
  boundary.
- Keep gateway validation after the gateway interceptor so built-in policy
  safety checks still run.

## Implementation plan

1. Add a `crates/openshell-gateway-interceptors` crate with the shared manifest,
   request/response, selector matching, ordering, failure policy handling, patch
   application, and test helpers.
2. Add gateway interceptor configuration parsing to gateway config and validate
   it at startup.
3. Implement gRPC gateway interceptor clients that connect to configured
   gateway interceptor `grpc_endpoint` values and call `Describe` during startup
   or config reload.
4. Build an execution plan from service manifests plus gateway-configured
   overrides.
5. Wire gateway interceptor execution into the gateway API operation pipeline so
   all gateway operations can pass through `modify_operation`, `validate`, and
   `post_commit` where applicable.
6. Audit existing gateway operations and route each resource-affecting path
   through the shared gateway interceptor pipeline.
7. Add gateway interceptor result audit logging and metrics.
8. Document gateway interceptor configuration, endpoint requirements, failure
    modes, and security guidance.

## Risks

- Gateway interceptors can make request behavior harder to reason about if
  ordering and audit are weak.
- Synchronous gRPC gateway interceptor services can become availability
  dependencies for the gateway.
- Modifying gateway interceptors can hide user intent if they silently rewrite
  user-supplied values.
- Ownership can become confusing when external controllers and humans both edit
  the same provider profile, provider, or policy through existing APIs.
- Quota gateway interceptors need a stronger consistency design before they are
  safe in HA deployments.

Mitigations:

- Keep gateway interceptors disabled by default.
- Make ordering deterministic and visible.
- Default modifying and validating gateway interceptors to `fail_closed`.
- Run first-party invariant validation after modification.
- Make HA-unsafe gateway interceptors declare their scope explicitly.

## Alternatives

### Add more gateway config fields

OpenShell could add first-party config fields for each requirement, such as
`sandbox_name_prefix`, `max_sandboxes_per_user`, and
`allowed_driver_config_keys`.

This is simple for known cases but does not scale to organization-specific
policy or external sources. It also keeps growing the gateway config schema for
controls that are not core OpenShell semantics.

Built-in fields and gateway interceptors are not mutually exclusive. OpenShell
may still ship common defaults as first-party config; gateway interceptors let a
deployment extend or override those defaults when its rules differ.

### Build a specific policy driver

OpenShell could add a dedicated policy driver interface for deployments that want
policy decisions to come from an external authority.

This solves one important use case, but it creates a narrow extension point for
one resource type instead of a general gateway operation framework. The same
deployments may need adjacent controls for sandbox creation, provider
profiles, quotas, naming, and audit. It would also be difficult to evolve:
OpenShell would need to expose policy-specific hooks that are likely to track
individual deployment use cases rather than a stable gateway operation contract.
This is different from compute drivers, which implement backend behavior after
the gateway has accepted an operation. A policy authority participates in the
gateway's decision to accept, reject, or modify the operation before
persistence, so it fits better as a gateway interceptor than as a driver.

### Put this in compute drivers

Drivers already validate driver-owned config. They could also reject names,
quotas, and policy choices.

This mixes responsibilities. Drivers should own compute-platform feasibility.
The gateway should own API behavior, tenancy, policy authority, and provider
state. Gateway interceptors are appropriate for additional business logic around
gateway operations; drivers are appropriate when OpenShell needs a different
implementation of compute functionality.

### Use HTTP webhooks

OpenShell could model gateway interceptors as HTTP webhooks with JSON request
and response payloads.

This is familiar to Kubernetes users, but OpenShell already uses protobuf and
gRPC heavily. A protobuf gRPC contract avoids a second wire format for gateway
extension points, works over Unix domain sockets for local integrations, and
matches the gateway's existing service boundaries.
