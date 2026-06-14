---
authors:
  - "@elezar"
state: review
links:
  - https://github.com/NVIDIA/OpenShell/issues/1492
  - https://github.com/NVIDIA/OpenShell/pull/1589
---

# RFC 0005 - Driver Config Passthrough

## Summary

Add a caller-provided `driver_config` field to sandbox creation requests. The
field carries driver-specific configuration in a driver-keyed envelope. The
gateway selects the block for the active compute driver and forwards that block
to the driver without interpreting its nested schema.

Each compute driver owns the schema, validation, compatibility, and security
constraints for its own config block. The gateway owns only the stable envelope,
driver selection, and the separation between caller-provided `driver_config` and
gateway-computed `platform_config`.

Kubernetes is a primary proving driver for the nested config shape. The RFC does
not finalize every Kubernetes key up front. Instead, it requires collecting
representative Kubernetes use cases, such as pod scheduling controls, container
resources, sidecar resources, and extended resources, before defining the first
documented Kubernetes config shape.

## Motivation

This RFC addresses the driver-specific passthrough problem tracked in
https://github.com/NVIDIA/OpenShell/issues/1492.

The gateway currently acts as a strict gatekeeper between the public API and
compute drivers. Every driver-specific feature requires at least one of:

1. a typed field on `SandboxTemplate` or `SandboxSpec`;
2. gateway translation logic in `driver_sandbox_template_from_public()` or
   `build_platform_config()`; or
3. a coordinated gateway, driver, and client release.

This creates a bottleneck. Driver capabilities can only be exposed after the
gateway learns about them, even when the gateway does not need to understand,
validate, or transform those fields.

The problem is broader than resource sizing. Kubernetes, Docker, Podman, and VM
drivers expose different platform capabilities: scheduling controls, resource
limits, image pull behavior, networking mode, storage options, security
settings, and VM-specific shape. Forcing all of these through typed gateway
fields creates API bloat and encourages lowest-common-denominator abstractions.

One concrete proving use case is Kubernetes resource customization for GPU
sharing and scheduling. Some Kubernetes cluster stacks expose memory,
compute-share, placement, or device-plugin controls through Kubernetes resource
requests, resource limits, extended resources, or other pod/container
configuration that is specific to the installed cluster stack. OpenShell should
not need first-class public API fields for each of those options.

OpenShell needs a caller-provided, driver-owned configuration path that is
distinct from the existing gateway-computed `platform_config`.

This RFC scopes that path to sandbox compute drivers because sandbox creation
already has a clear driver selection step, a `DriverSandboxTemplate` handoff,
and driver-owned validation before any platform resource is created.

## Non-goals

- Do not add first-class support for any specific GPU stack.
- Do not define OpenShell-owned GPU memory or GPU core-share fields.
- Do not finalize every Kubernetes driver-specific key shape before collecting
  representative use cases.
- Do not implement every useful driver-specific key in the initial change.
- Do not allow driver config to override gateway-computed `platform_config`.
- Do not rename or namespace in-tree drivers as part of this RFC.
- Do not apply wildcard matching to driver config keys.
- Do not make `driver_config` a dynamic update mechanism for existing
  sandboxes.
- Do not define a generic extension mechanism for every top-level OpenShell
  resource. Provider secrets, gateways, policies, and other resources may need
  analogous extension points, but each should be designed around its own owner,
  lifecycle, authorization, and security invariants.

## Proposal

### Public API

Add a caller-provided `driver_config` field to `SandboxTemplate`.

```proto
message SandboxTemplate {
  // ... existing typed fields ...

  // Opaque driver-specific configuration provided by the caller.
  // The gateway selects the block matching the active driver name.
  // The selected compute driver owns nested schema validation.
  google.protobuf.Struct driver_config = <next_field_number>;
}
```

The public `driver_config` value is an envelope keyed by driver name. For the
initial implementation, built-in OpenShell driver names are the same stable
strings used to select and configure drivers today:

- `kubernetes`
- `docker`
- `podman`
- `vm`

Example:

```json
{
  "driver_config": {
    "kubernetes": {
      "resources": {
        "limits": {
          "vendor.example/gpu-memory": "8Gi"
        }
      }
    },
    "docker": {
      "network_mode": "bridge"
    }
  }
}
```

Driver name matching is exact. Wildcards such as `*`, `*/kubernetes`, or
`openshell.ai/*` have no special meaning.

This RFC does not introduce DNS-qualified driver namespaces. A future driver
identity cleanup may add namespaced aliases or rename in-tree drivers, but that
should not block the `driver_config` mechanism.

### Future driver identity

The built-in driver names listed above are reserved by OpenShell. Out-of-tree
drivers should not assume that short, unqualified names are collision-safe as the
driver ecosystem grows.

A future driver identity design should allow a driver to advertise a canonical
`driver_config` key and, if needed, compatibility aliases. For example, an
external driver may eventually prefer a DNS-qualified key such as
`vendor.example/driver` while an in-tree driver continues to use `kubernetes`,
`docker`, `podman`, or `vm`.

Any future identity design must preserve the ownership boundary in this RFC:

- matching remains exact against a known active driver identity or alias;
- wildcard matching does not gain special meaning;
- the gateway does not infer nested schema ownership from partial names; and
- the selected driver remains the only component that validates the selected
  inner config block.

### Driver API

Keep the existing gateway-computed `platform_config` separate from
caller-provided driver config.

```proto
message DriverSandboxTemplate {
  // ... existing fields ...

  google.protobuf.Struct platform_config = 11; // gateway-computed

  // Caller-provided config for the selected driver only.
  // This is the inner block from public SandboxTemplate.driver_config.
  google.protobuf.Struct driver_config = 12;
}
```

The driver receives only the selected driver's inner config block. It does not
receive the full public envelope.

Drivers may interpret the received `Struct` through driver-local typed schemas.
For example, the Kubernetes driver may define a Kubernetes-specific protobuf
message or Rust struct for its inner `driver_config` block and map the forwarded
`Struct` into that type before validation and pod construction. That local typed
decode is an implementation detail of the selected driver. It must not require
the gateway to import Kubernetes-, Docker-, Podman-, or VM-specific config
messages, and it must not change the public driver-keyed envelope contract.

Driver-local typed config should be distinct from gateway process configuration
such as `[openshell.drivers.<name>]` TOML structs. Gateway process configuration
contains operator-owned settings like namespaces, gateway endpoints, service
accounts, TLS material, default images, and runtime state paths. Caller-provided
per-sandbox `driver_config` must use a narrower create-time schema that exposes
only documented, caller-safe knobs for that driver.

### Gateway behavior

The gateway handles only the top-level envelope:

- Empty or unset `driver_config` is equivalent to no driver-specific config.
- Top-level keys are driver names.
- A request may contain config blocks for multiple drivers.
- The gateway selects the block whose key exactly matches the selected driver
  name.
- If no matching block exists, the gateway forwards no driver config.
- The matching block, when present, must be a Struct value.
- Non-selected driver blocks are ignored by the gateway and are not validated.

Future gateway implementations may emit a non-fatal warning when a non-empty
envelope contains no top-level key matching any active driver name. That warning
is a usability aid for likely typos. It must not change the portability rule:
non-selected driver blocks remain tolerated and unvalidated by the gateway.

After selecting the matching block, the gateway forwards only that inner Struct
to `DriverSandboxTemplate.driver_config`.

The gateway must not inspect, validate, merge, or rewrite fields inside the
selected driver config block.

For the initial implementation, the gateway does not need a separate driver
capability flag before forwarding a matching config block. Whether drivers
should advertise support for `driver_config` is an open question.

### Scope boundary

`driver_config` is attached to sandbox creation requests because a sandbox has a
single selected compute driver and a direct gateway-to-driver handoff. The
selected compute driver can validate the nested config before it creates or
modifies any underlying platform resources.

Other top-level OpenShell resources may also be backed by subsystem-specific or
platform-specific implementations, but they do not automatically share the same
ownership boundary. For example, provider secret handling involves credential
lifecycle and access-control rules rather than pod/container scheduling rules.
Those resources should not reuse `SandboxTemplate.driver_config` or the compute
driver key space by implication.

If another resource needs a passthrough mechanism later, it should get a
resource-specific design that answers:

- which component owns the nested schema and validation;
- which stable envelope identifies that owner;
- whether the config is create-time only or updateable;
- which fields are protected by the control plane; and
- how authorization, secret handling, auditing, and compatibility work for that
  resource.

### Driver validation

The selected driver validates the nested config it receives:

- accepted keys;
- value types and formats;
- unsupported or unknown keys;
- conflicts with typed OpenShell fields; and
- platform-specific semantic constraints.

If validation fails, sandbox creation fails before the sandbox is created.

Typed OpenShell fields are authoritative for settings that the public API
already models directly. Driver-specific config may add platform-specific
detail, but it must not silently override typed fields. Initial behavior is to
reject conflicts.

Examples:

- If typed OpenShell resources set CPU or memory and Kubernetes driver config
  also sets `resources.requests.cpu`, `resources.limits.cpu`,
  `resources.requests.memory`, or `resources.limits.memory`, validation fails.
- If the public GPU flag controls the driver's default GPU resource, driver
  config may add additional extended resources for GPU memory or compute-share
  style controls, but it must not override the typed GPU request.

This can be relaxed later to a documented merge rule if a real use case
requires it.

Prototype implementations may temporarily accept a narrower subset of this
behavior while the nested driver schema is being explored. For example, a POC may
ignore unknown Kubernetes keys so that representative scheduling and resource
examples can be demonstrated before the final schema is settled. Such behavior
must be documented as experimental and must not be treated as the final contract.

Before a driver config key is documented as stable, the selected driver should
define its validation behavior for unknown keys, malformed values, typed-field
conflicts, protected invariants, and unsafe platform controls. The default
expectation for stable documented schemas is to reject unknown or malformed
fields unless the driver explicitly documents an extension bag or pass-through
subtree.

### Protected fields and security constraints

`driver_config` must not allow callers to override gateway-owned or driver-owned
invariants.

Drivers must reject config that attempts to replace or weaken required sandbox
wiring, identity, authentication, policy enforcement, observability, or lifecycle
controls. For Kubernetes, examples may include gateway endpoints, sandbox
identity labels or annotations, owner references, supervisor wiring, required
volumes, auth material, and control-plane managed metadata.

Drivers may also reject platform-supported fields that are unsafe for
OpenShell's threat model. Examples include privileged execution, host
networking, host paths, arbitrary service accounts, unsafe security contexts, or
unrestricted image pull secrets. Support for any high-risk driver key must be
explicit, documented, and validated by the driver.

`driver_config` must not embed secrets, credentials, tokens, private keys, or
other sensitive values. Driver config may reference existing platform objects,
such as a Kubernetes Secret name, only when the driver considers that reference
safe and validates it.

### Lifecycle semantics

`driver_config` is creation-time configuration for a sandbox. Changing driver
config requires recreating the sandbox unless a future design defines explicit
update semantics for a specific driver and key.

Non-selected driver blocks are ignored by the gateway so configs can remain
portable across drivers. This means stale or misspelled blocks for non-selected
drivers may not be detected until that driver is selected. Future CLI, TUI, or
schema tooling may lint all blocks, but the gateway only validates and forwards
the selected driver's block.

### Relationship to existing resources and platform config

OpenShell already exposes typed and semi-typed configuration paths:

- Public `SandboxTemplate.resources` carries user-facing resource requirements.
- The gateway extracts typed CPU and memory into `DriverResourceRequirements`.
- The gateway currently passes remaining platform-specific resource fields
  through `platform_config.resources_raw`.
- `platform_config` also carries gateway-computed fields such as runtime class,
  annotations, volume claim templates, and user namespace settings.

`driver_config` is not a replacement for typed public fields or
gateway-computed `platform_config`. It is a new caller-provided, driver-owned
extension path.

As part of implementing this RFC, the Kubernetes resource passthrough path
should be clarified so there is one documented way to express driver-owned
resource customization going forward. Existing behavior should remain
compatible, but new driver-specific resource examples should prefer
`driver_config` once it exists.

### Driver schema evolution

Although `driver_config` is opaque to the gateway, documented driver config keys
are still public API for that driver. Users, templates, and automation will
depend on them.

Drivers should follow these compatibility rules:

- Prefer additive schema changes.
- Reject unknown or malformed fields with clear validation errors.
- Do not silently change the meaning of an existing key.
- Add a new key instead of changing semantics in place.
- Deprecate documented keys before removing them.
- Keep documented examples covered by tests.
- If a breaking change is unavoidable, introduce an explicit versioned shape
  rather than changing an existing shape in place.

Non-selected driver blocks are ignored by the gateway, so stale config for
another driver may not be noticed until that driver is selected. Driver
validation errors should identify the config path and include actionable
migration guidance where possible.

### Driver schema discovery

The initial implementation can rely on driver documentation plus validation
errors from `ValidateSandboxCreate`.

Longer term, driver config should have a machine-readable discovery surface so
CLIs, TUIs, templates, and gateways can help users earlier without hard-coding
driver-specific schemas. A discovery surface should let a driver report at
least:

- the canonical `driver_config` key and compatibility aliases it accepts;
- whether the driver supports caller-provided `driver_config`;
- the schema identifier, version, or URL for the selected config shape; and
- the driver's documented unknown-field behavior.

Possible discovery surfaces include:

- a schema URL in `GetCapabilitiesResponse`;
- an inline schema in `GetCapabilitiesResponse`;
- a dedicated `GetDriverConfigSchema` RPC;
- a schema identifier or version that maps to published documentation; or
- a driver-published protobuf descriptor or type identifier for drivers that
  use protobuf messages to model their local config.

Any schema discovery mechanism should preserve the ownership boundary:

- The driver remains the source of truth for validation.
- The gateway may surface schema information or perform generic preflight
  checks.
- The gateway must not encode driver-specific schema knowledge directly.
- Schema-based gateway checks must not replace driver-side validation.
- A protobuf-backed schema does not imply a central `oneof` of all in-tree and
  out-of-tree driver configs in the public API.

Schema discovery is not required for the first implementation of this RFC, but
the API design should not preclude adding it later.

### Initial Kubernetes driver use cases

Kubernetes should be a primary driver used to inform the nested `driver_config`
shape. For all drivers, the following constraints should guide the nested shape:

- `driver_config` must not bypass or override first-class resource requests
  exposed by the public API, such as typed GPU, CPU, and memory fields.
- Driver-specific resource config is still in scope when it represents
  driver-owned detail, such as sidecar resource sizing, extended resources, or
  platform-specific resource controls that the public API does not model.
- API design should be informed by more than non-standard resource requests.
  For Kubernetes, it should answer: which Kubernetes-specific properties could
  a user want to set?

The first step should collect a representative set of Kubernetes
driver-specific use cases, including:

- additional container resource requests and limits for the primary sandbox
  container that the public API does not model;
- resource requests and limits for driver-owned sidecars such as a proxy
  container;
- extended resources used by installed GPU stacks;
- node selectors;
- tolerations;
- service account selection;
- priority class selection;
- image pull secrets or image pull behavior; and
- runtime class and other pod-level scheduling/runtime settings.

Those use cases should inform the Kubernetes nested schema. Possible shapes
include a Kubernetes-native pod/container structure:

```json
{
  "driver_config": {
    "kubernetes": {
      "pod": {
        "node_selector": {
          "accelerator": "true"
        },
        "priority_class_name": "gpu-workload"
      },
      "containers": {
        "sandbox": {
          "resources": {
            "limits": {
              "vendor.example/gpu-memory": "8Gi"
            }
          }
        },
        "proxy": {
          "resources": {
            "requests": {
              "cpu": "100m",
              "memory": "128Mi"
            },
            "limits": {
              "cpu": "500m",
              "memory": "512Mi"
            }
          }
        }
      }
    }
  }
}
```

This example is illustrative, not the final required schema.

Note that the top-level `"kubernetes"` key represents a concrete driver name.
This is important because it defines which driver is responsible for validating
and interpreting the spec. This also allows multiple drivers to be supported --
but not required -- in the future.

Furthermore, keying the config by driver name and using a generic message
payload allows out-of-tree drivers to be supported in the future without
requiring coordinated deployment of gateway updates.

The Kubernetes driver should prefer raw Kubernetes resource names and
Kubernetes quantity strings where it exposes Kubernetes resource requests and
limits. It should not introduce OpenShell-owned aliases such as `gpu_memory_mb`
or `gpu_cores_pct` in this RFC.

This shape must be able to express GPU memory and GPU compute-share style
constraints when the installed Kubernetes stack exposes those controls as
extended resources. That is a generic resource customization requirement, not a
commitment to first-class support for any specific GPU stack.

When no Kubernetes resource customization is provided, current behavior is
preserved. A GPU sandbox continues to request the default GPU resource exactly
as it does today.

GPU stack installation, selection, and lifecycle remain cluster-level concerns
outside this RFC.

## Implementation plan

1. Add `driver_config` to public `SandboxTemplate`.
2. Add `driver_config` to `DriverSandboxTemplate`.
3. Update gateway translation so it selects the block matching the active
   driver name and forwards only that block to the driver.
4. Preserve existing behavior when `driver_config` is unset or when no matching
   driver block exists.
5. Collect representative Kubernetes driver config use cases before finalizing
   the nested Kubernetes schema.
6. Define and document the initial Kubernetes nested config shape using those
   use cases.
7. Implement driver-side validation for supported keys, malformed values,
   typed-field conflicts, protected invariants, and unsafe platform controls.
8. If a driver uses a local typed schema, map the selected inner `Struct` into
   that driver-local type inside the driver before validation. Do not add
   driver-specific config messages to the gateway translation layer.
9. Add examples and tests for documented Kubernetes `driver_config` keys,
   including GPU extended resources and sidecar resource requests.
10. Document built-in driver names, exact-match behavior, validation ownership,
   lifecycle semantics, protected-field rules, schema evolution expectations,
   POC-versus-stable validation behavior, and supported Kubernetes keys.
11. Track follow-up design work for canonical driver identity and aliases,
   machine-readable schema discovery, and non-fatal warnings when no envelope
   key matches an active driver.

## Risks

- `driver_config` becomes a hidden public API without enough compatibility
  discipline. This RFC treats documented driver config keys as driver-owned
  public API and requires additive evolution where possible.
- Non-selected driver blocks are ignored, so stale config may be discovered
  late. Future schema tooling can lint all blocks, but the gateway should only
  validate the selected block for portability.
- The Kubernetes nested schema may become too close to raw pod specs and expose
  unsafe override paths. Driver validation must protect gateway and driver
  invariants.
- The Kubernetes nested schema may become too abstract and fail to cover real
  cluster needs. Representative use-case collection is an explicit
  implementation step.
- Old gateways ignore the new public proto field at the wire level. Clients
  that require `driver_config` must target a gateway version that advertises or
  documents support for it.

## Alternatives

### Typed fields for every driver feature

Every driver-specific feature gets a typed public API field and explicit gateway
forwarding logic.

This keeps the public API strongly typed, but the gateway remains a bottleneck,
the public API grows around driver-specific details, and new driver capabilities
require coordinated releases.

### Central public `oneof` for per-driver config protos

The public API could replace the generic `Struct` envelope with a central
`oneof` containing typed messages for every supported driver, or the internal
driver API could require the gateway to translate the selected block into a
driver-specific protobuf message before calling the driver.

This gives generated types to clients and the gateway, but it moves schema
ownership back into the shared API surface. Every new driver config key, and
every out-of-tree driver config shape, would require gateway proto changes and
coordinated releases. It also makes portability harder because clients must
compile against all config message variants they want to carry.

Driver-local protobuf messages remain compatible with this RFC when the gateway
continues to forward only the selected inner `Struct` and the selected driver
performs the typed decode and validation locally.

### Merge caller config into `platform_config`

The gateway could merge caller-provided config into the existing
gateway-computed `platform_config`.

This creates confusing override semantics and risks allowing callers to
overwrite gateway-owned fields. Caller-provided `driver_config` should stay
separate from gateway-computed `platform_config`.

### DNS-qualified driver namespaces now

The public API could require keys such as `openshell.ai/kubernetes` or
`vendor.example/kubernetes`.

This provides stronger collision resistance, but it also turns this RFC into a
driver identity cleanup. The current in-tree drivers already have
selection/configuration names (`kubernetes`, `docker`, `podman`, `vm`).
Namespaced aliases can be added later without blocking the initial passthrough
mechanism.

### Reject non-selected driver blocks

The gateway could reject `driver_config` blocks that do not target the selected
driver.

This catches some typos earlier, but makes portable configs harder. A reusable
sandbox template should be able to carry Kubernetes, Docker, Podman, and VM
config blocks and let the active gateway apply only the block for its selected
driver.

### Wildcard driver keys

The public API could allow keys such as `*/kubernetes`.

Wildcard matching makes schema ownership ambiguous, complicates precedence, and
increases the chance that config is applied to the wrong driver implementation.
Exact driver-name matching keeps the rule simple while still allowing portable
multi-driver envelopes.

### Require machine-readable schemas or support capability now

Every driver could be required to publish a machine-readable schema or a
`supports_driver_config` capability as part of this RFC.

Discovery is valuable, but requiring it up front increases the first
implementation scope and needs community input. Forwarding a matching block plus
driver-side validation is sufficient for the initial passthrough mechanism. A
schema discovery RPC or capability field can be added later without changing the
core `driver_config` contract.

### Generic passthrough for all top-level resources

Every top-level OpenShell resource could receive a similarly shaped
implementation-owned config block.

This might make the model feel consistent across APIs, but it would obscure the
owner and validation boundary. Sandbox compute drivers have a concrete selected
driver and a creation-time driver template. Other resources may be owned by the
gateway, provider backends, policy engines, identity systems, or external
platform components. Their extension points need separate lifecycle,
authorization, secret-handling, audit, and compatibility rules.

This RFC should not block analogous resource-specific designs, but it should not
turn the sandbox compute-driver mechanism into a global extension contract.

### Allow secrets or privileged platform controls

The passthrough could allow arbitrary platform-native fields, including secret
data or privileged pod/container settings.

This would bypass OpenShell's security model. Driver config must remain
constrained by driver validation, protected invariants, and documented safe key
sets.

### Status quo

Operators wait for OpenShell to add each driver-specific feature as a typed
field, or they fork the gateway.

This preserves the current API, but keeps feature velocity low and maintains
unnecessary gateway coupling.

## Prior art

Kubernetes CSI `StorageClass.parameters` uses the same ownership pattern. The
Kubernetes control plane does not interpret each provisioner's parameter schema.
It passes the parameters to the CSI driver, and the CSI driver validates and
consumes them. That decouples core Kubernetes from provider-specific storage
features.

OpenShell should use the same split: the gateway owns the stable public API and
gateway-computed fields, while each compute driver owns its driver-specific
config schema.

RFC 0004 separates portable sandbox resource requirements from driver-specific
configuration. This RFC defines the driver-specific configuration surface that
RFC 0004 intentionally left out of scope.

## Open questions

- What driver identity format and alias rules should out-of-tree drivers use if
  OpenShell later introduces DNS-qualified driver names?
- Which schema discovery surface should carry the canonical config key,
  compatibility aliases, support signal, schema identity, and unknown-field
  behavior?
- Should no-match warnings be emitted by the gateway, CLI/TUI tooling, or both?
- What Kubernetes nested config shape best covers representative pod-level and
  container-level use cases without exposing unsafe override paths?
- Should Kubernetes config use driver-owned role names such as `sandbox` and
  `proxy`, raw container names, or another targeting model?
- Should existing `platform_config.resources_raw` behavior be retained
  indefinitely, migrated to `driver_config`, or documented as a compatibility
  path?
