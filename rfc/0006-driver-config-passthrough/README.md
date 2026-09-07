---
authors:
  - "@elezar"
state: implemented
links:
  - https://github.com/NVIDIA/OpenShell/issues/1492
  - https://github.com/NVIDIA/OpenShell/pull/1589
  - https://github.com/NVIDIA/OpenShell/pull/1744
  - https://github.com/NVIDIA/OpenShell/pull/1785
  - https://github.com/NVIDIA/OpenShell/pull/1815
  - https://github.com/NVIDIA/OpenShell/pull/1861
  - https://github.com/NVIDIA/OpenShell/pull/2086
  - https://github.com/NVIDIA/OpenShell/pull/2092
---

# RFC 0006 - Driver Config Passthrough

## Summary

OpenShell sandbox creation supports caller-provided `driver_config` for
compute-driver-specific settings that do not belong in the portable public API.
The public API carries a driver-keyed envelope on `SandboxTemplate`; the gateway
selects the block for the active compute driver and forwards only that inner
block to `DriverSandboxTemplate.driver_config`.

The selected driver owns the nested schema, validation, safety policy, and
compatibility behavior for its config block. The gateway owns only the stable
envelope, driver selection, and the separation between caller-provided
`driver_config` and gateway-computed `platform_config`.

## Motivation

Issue #1492 identified a recurring gap in the sandbox API: useful platform
features were blocked on adding first-class fields to `SandboxSpec`,
`SandboxTemplate`, gateway translation code, and every client. That coupling
was too expensive for features whose meaning is owned by one compute driver.

The problem showed up across drivers. Kubernetes needed pod scheduling and
runtime controls, and resource knobs for cluster-specific GPU stacks. Docker
and Podman needed per-sandbox mount configuration with local-engine safety
rules. GPU exact device selection needed driver-native identifiers: CDI names
for Docker and Podman, and PCI BDF or device IDs for the VM driver. None of
those details should force a portable OpenShell field.

At the same time, OpenShell still needs a control-plane boundary. Caller input
must not be merged into gateway-owned `platform_config`, bypass typed public
fields, replace auth or supervisor wiring, or silently weaken sandbox
isolation. A driver-owned config path gives drivers room to expose platform
features while preserving a clear owner for validation.

This RFC records the implemented baseline after PRs #1744, #1785, #1815, #1861, #2086, and #2092.
The remaining follow-up questions stay visible: driver identity aliases, schema
discovery, no-match warnings, and the future of legacy Kubernetes platform
resource passthrough.

## Non-goals

- Do not add first-class support for any specific GPU stack.
- Do not define OpenShell-owned GPU memory or GPU core-share fields.
- Do not make `driver_config` a dynamic update mechanism for existing
  sandboxes.
- Do not allow driver config to override gateway-computed `platform_config` or
  typed public fields.
- Do not apply wildcard matching to driver config keys.
- Do not make the gateway import driver-specific config schemas.
- Do not define a generic extension mechanism for every OpenShell resource.
  Provider secrets, gateways, policies, and other resources need separate
  owner, lifecycle, authorization, audit, and security analysis.

## Proposal

### Public API

`SandboxTemplate` has a caller-provided `driver_config` field:

```proto
message SandboxTemplate {
  // ... existing typed fields ...

  // Driver-keyed opaque config envelope supplied by the caller.
  // The gateway selects the block matching the active compute driver and
  // forwards only that inner Struct to DriverSandboxTemplate.driver_config.
  // The selected driver owns nested schema validation.
  google.protobuf.Struct driver_config = 11;
}
```

The public value is a JSON/protobuf `Struct` envelope keyed by exact driver
name. Built-in driver keys are:

- `kubernetes`
- `docker`
- `podman`
- `vm`

Example:

```json
{
  "driver_config": {
    "kubernetes": {
      "pod": {
        "runtime_class_name": "kata-containers",
        "node_selector": {
          "pool": "gpu"
        }
      }
    },
    "docker": {
      "cdi_devices": ["nvidia.com/gpu=0"]
    }
  }
}
```

Driver name matching is exact. Wildcards such as `*`, `*/kubernetes`, or
`openshell.ai/*` have no special meaning. Non-selected driver blocks are
ignored by the gateway and are not validated by the gateway or the selected
driver.

The CLI exposes the envelope with `--driver-config-json`. Nested keys inside
each driver block use snake_case. The top-level driver key, such as
`kubernetes`, is not part of the nested driver schema.

### Driver API

The gateway keeps caller-provided config separate from gateway-computed
platform config:

```proto
message DriverSandboxTemplate {
  // ... existing fields ...

  // Opaque, platform-specific configuration computed by the gateway.
  google.protobuf.Struct platform_config = 11;

  // Caller-provided config for the selected driver only.
  // This is the inner block selected from public SandboxTemplate.driver_config.
  // The selected driver owns nested schema validation.
  google.protobuf.Struct driver_config = 12;
}
```

The driver receives only its selected inner config block. It never receives the
full public envelope. Drivers may decode that `Struct` into local Rust structs
or driver-local protobuf messages before validation, but those schemas remain
inside the selected driver crate. The gateway must not import Kubernetes-,
Docker-, Podman-, VM-, or out-of-tree driver config types.

Driver-local per-sandbox config is distinct from gateway process configuration
such as `[openshell.drivers.<name>]` TOML tables. Process configuration is
operator-owned and contains values such as namespaces, default images, runtime
paths, TLS material, service accounts, and safety gates. Per-sandbox
`driver_config` exposes only documented caller-safe create-time knobs for the
selected driver.

### Gateway behavior

The gateway handles only the top-level envelope:

- Empty or unset `driver_config` is equivalent to no driver-specific config.
- A request may contain config blocks for multiple drivers.
- The gateway selects the block whose key exactly matches the selected compute
  driver name.
- If no matching block exists, the gateway forwards no driver config.
- The matching block, when present, must be a JSON object / protobuf Struct.
- Non-selected driver blocks are ignored and remain unvalidated.
- The gateway forwards only the matching inner Struct to the driver.
- The gateway does not inspect, validate, merge, or rewrite nested fields
  inside the selected driver config block.

Non-selected blocks are tolerated so one reusable sandbox template can carry
driver-specific config for more than one possible gateway. A future CLI, TUI,
or gateway warning may help detect likely typos when no envelope key matches an
active driver, but that warning must not turn non-selected blocks into an error.

### Implemented driver schemas

The RFC owns the envelope and validation boundary. Detailed field-level
reference belongs in the driver README files and published docs. The
implemented schema families are:

| Driver | Implemented config families |
|---|---|
| Kubernetes | `pod.node_selector`, `pod.tolerations`, `pod.runtime_class_name`, `pod.priority_class_name`, `containers.agent.resources.requests`, and `containers.agent.resources.limits`. |
| Docker | `cdi_devices` for exact GPU selection and `mounts` for `bind`, `volume`, and `tmpfs` mounts, with an optional `selinux_label` on `bind` mounts. |
| Podman | `cdi_devices` for exact GPU selection and `mounts` for `bind`, `volume`, `tmpfs`, and `image` mounts, with an optional `selinux_label` on `bind` mounts. |
| VM | `gpu_device_ids` for exact GPU selection, currently limited to one entry. |

Kubernetes rejects unknown nested driver config fields. Its runtime class
precedence is:

1. typed public `SandboxTemplate.runtime_class_name`;
2. `driver_config.kubernetes.pod.runtime_class_name`;
3. gateway configured `default_runtime_class_name`;
4. no runtime class.

Docker, Podman, and VM exact GPU selection requires the typed GPU request to be
present. Docker and Podman use CDI device IDs through `cdi_devices`. VM uses
`gpu_device_ids` and currently accepts at most one entry. Kubernetes does not
support exact GPU device selection through `driver_config` and rejects
unsupported exact-selection keys instead of silently falling back to a generic
GPU request.

Docker and Podman mount config is intentionally constrained:

- User-supplied mounts are read-only by default unless `read_only: false` is
  explicit.
- Named volumes must already exist. Drivers validate them before create and do
  not create or remove them.
- Host bind mounts require the operator to set
  `[openshell.drivers.<driver>].enable_bind_mounts = true`.
- Docker and Podman local-driver named volumes backed by `bind` or `rbind`
  options are treated as host bind mounts and require the same opt-in.
- Mount targets must not replace the workspace root, container root,
  supervisor files, `/etc/openshell`, `/etc/openshell-tls`, authentication
  material, or network namespace paths.
- Mount `source`, `target`, and `subpath` values are rejected when they contain
  surrounding whitespace, so ambiguous paths cannot slip through validation.
- `bind` mounts accept an optional `selinux_label` of `shared` (`:z`) or
  `private` (`:Z`) for SELinux-enforcing hosts. Volume, tmpfs, and image mounts
  do not take a SELinux label.

These constraints do not make host bind mounts safe. They make unsafe host
filesystem exposure explicit and operator-gated.

### Validation and protected invariants

The selected driver validates its nested config before it creates platform
resources. Stable documented schemas should reject:

- unknown fields, unless the driver explicitly documents an extension bag;
- malformed values;
- unsupported mount or resource types;
- conflicts with typed OpenShell fields;
- attempts to override gateway-computed `platform_config`;
- attempts to replace sandbox identity, auth, supervisor, policy, telemetry, or
  lifecycle wiring; and
- unsafe platform controls that OpenShell has not explicitly exposed.

Typed OpenShell fields are authoritative for settings that the public API
already models directly. Driver config may add driver-owned detail, but it must
not silently override typed fields. For example, typed CPU, memory, and GPU
requests remain the portable resource intent. Driver config may add
Kubernetes-specific extended resources or container resource details that the
public API does not model.

`driver_config` must not embed secrets, credentials, tokens, private keys, or
other sensitive values. A driver may allow references to existing platform
objects, such as a Kubernetes Secret name, only when that reference is
documented safe and the driver validates it.

### Lifecycle and compatibility

`driver_config` is create-time configuration. Changing driver config requires
recreating the sandbox unless a future RFC defines explicit update semantics
for a specific driver and key.

The `driver_config` envelope, exact driver-name selection, and the separation
from gateway-computed `platform_config` are the stable parts of this surface.
The nested per-driver config keys remain experimental: the CLI `--driver-config-json`
flag is documented as experimental, and validation behavior is not yet finalized.
Nested keys may change until a driver marks a specific schema stable.

When a driver does stabilize documented keys, it should evolve them
additively, reject malformed input with clear errors, and deprecate documented
keys before removing them. If a breaking change is unavoidable, prefer an
explicit versioned shape over changing an existing key in place. Until then,
callers should treat nested keys as subject to change and pin against a known
driver version.

Because non-selected driver blocks are ignored, stale config for another driver
may not be noticed until that driver is selected. Validation errors should
include the driver config path and actionable guidance where possible.

## Implementation plan

The core RFC is implemented:

1. PR #1744 added the public `SandboxTemplate.driver_config` field, the CLI
   `--driver-config-json` path, gateway exact-key selection, forwarding to
   `DriverSandboxTemplate.driver_config`, and the initial Kubernetes
   driver-local schema.
2. PR #1785 added Docker and Podman mount schemas, named-volume validation,
   read-only defaults, and bind-mount safety gates.
3. PR #1815 moved exact GPU device selection out of the public API and into
   driver-specific `cdi_devices` / `gpu_device_ids` fields. It also established
   that unsupported or unknown Kubernetes GPU selection keys must be rejected.
4. PR #1861 tightened Docker and Podman named-volume safety by treating local
   volumes with `bind` or `rbind` options as host bind mounts requiring the
   same operator opt-in.
5. PR #2086 rejected surrounding whitespace in mount `source`, `target`, and
   `subpath` fields across the Docker and Podman drivers.
6. PR #2092 added an optional `selinux_label` (`shared`/`private`) on Docker
   and Podman `bind` mounts for SELinux-enforcing hosts.

Follow-up work should be tracked separately:

- Add machine-readable driver config schema discovery when the driver config
  surface is stable enough for CLI/TUI assistance.
- Design canonical driver identity and alias rules for out-of-tree drivers.
- Decide whether no-match warnings belong in the gateway, CLI/TUI tooling, or
  both.
- Decide how long to keep legacy Kubernetes `platform_config.resources_raw`
  behavior and whether to migrate remaining examples to `driver_config`.
- Keep driver README and published reference docs as the field-level source of
  truth for each implemented driver schema.

## Risks

- **Driver config becomes a hidden public API.** The mitigation is to treat
  documented driver keys as driver-owned public API, keep validation explicit,
  and prefer additive schema evolution.
- **The gateway cannot validate non-selected blocks.** This is intentional for
  portable templates, but it means typos may surface late. Future schema
  tooling can lint all blocks without changing gateway semantics.
- **Driver schemas expose unsafe platform controls.** Each driver must protect
  gateway and sandbox invariants. Host bind mounts are the clearest example:
  they are disabled by default, require operator opt-in, and still carry a
  documented isolation warning.
- **The API may fragment across drivers.** This is acceptable when the behavior
  is genuinely driver-specific. Portable concepts such as CPU, memory, and
  generic GPU requests should continue to use typed OpenShell fields.
- **Schema discovery remains manual.** Current users rely on docs and driver
  validation errors. That is enough for the implemented baseline, but future
  tooling will need machine-readable schemas.

## Alternatives

### Typed fields for every driver feature

Every driver-specific feature could get a typed public API field and explicit
gateway forwarding logic.

This keeps the public API strongly typed, but the gateway remains a bottleneck,
the public API grows around driver-specific details, and new driver
capabilities require coordinated releases.

### Central public oneof for per-driver config

The public API could use a central `oneof` containing typed config messages for
every supported driver, or the gateway could translate the selected block into
a driver-specific protobuf message before calling the driver.

This gives generated types to clients and the gateway, but it moves schema
ownership back into the shared API. Every new driver config key, and every
out-of-tree driver shape, would require gateway proto changes and coordinated
releases. Driver-local typed decode keeps ownership with the selected driver.

### Merge caller config into platform_config

The gateway could merge caller-provided config into the existing
gateway-computed `platform_config`.

This creates confusing override semantics and risks allowing callers to replace
gateway-owned fields. Caller-provided `driver_config` stays separate from
gateway-computed `platform_config`.

### Reject non-selected driver blocks

The gateway could reject `driver_config` blocks that do not target the selected
driver.

This catches some typos earlier, but makes portable templates harder. A
reusable sandbox template should be able to carry Kubernetes, Docker, Podman,
and VM config blocks and let the active gateway apply only the selected block.

### Wildcard or namespaced driver keys now

The public API could require keys such as `openshell.ai/kubernetes` or allow
wildcards such as `*/kubernetes`.

Namespaced keys may be useful for out-of-tree drivers later, but requiring them
now would turn this RFC into a driver identity cleanup. Wildcards make schema
ownership and precedence ambiguous. Exact built-in names keep the current rule
simple.

### Generic passthrough for all top-level resources

Every OpenShell resource could receive an implementation-owned config block.

That would obscure ownership and validation boundaries. Sandbox compute drivers
have a concrete selected driver and a create-time driver template. Other
resources may be owned by provider backends, policy engines, identity systems,
or the gateway itself, and need separate designs.

## Prior art

Kubernetes CSI `StorageClass.parameters` uses the same ownership pattern. The
Kubernetes control plane does not interpret every provisioner's parameter
schema. It passes the parameters to the CSI driver, and the CSI driver validates
and consumes them.

Kubernetes pod specs also show the risk of raw passthrough. They are powerful,
but exposing arbitrary pod fields would let callers override identity, volume,
security, and lifecycle details that OpenShell must control. Driver config
therefore exposes narrow driver-owned schemas instead of raw platform objects.

RFC 0004 separates portable sandbox resource requirements from
driver-specific configuration. This RFC defines the driver-specific
configuration surface that RFC 0004 intentionally leaves out of scope.

The Docker and Podman mount work provides operational prior art inside
OpenShell: driver config can expose useful local runtime features, but host
filesystem exposure must be default-deny and operator-gated.

## Open questions

- What canonical driver identity format and alias rules should out-of-tree
  drivers use if OpenShell later supports namespaced driver keys?
- Which schema discovery surface should expose driver config support,
  canonical keys, schema versions, and unknown-field behavior?
- Should no-match warnings be emitted by the gateway, CLI/TUI tooling, or both?
- Should existing Kubernetes `platform_config.resources_raw` behavior be kept
  indefinitely, migrated to `driver_config`, or documented as a compatibility
  path only?
