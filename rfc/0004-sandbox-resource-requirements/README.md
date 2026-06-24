---
authors:
  - "@elezar"
state: accepted
links:
  - https://github.com/NVIDIA/OpenShell/issues/1338
  - https://github.com/NVIDIA/OpenShell/pull/1340
  - https://github.com/NVIDIA/OpenShell/pull/1360
  - https://github.com/NVIDIA/OpenShell/issues/1492
  - https://github.com/NVIDIA/OpenShell/pull/1675
  - https://github.com/NVIDIA/OpenShell/pull/1815
---

# RFC 0004 - Sandbox Resource Requirements

## Summary

This RFC proposes replacing GPU-specific sandbox request fields with typed
resource requirements on `SandboxSpec`. Resource requirements describe portable
workload needs that influence driver selection and provisioning:

- **compute** requirements for CPU and memory.
- **device** requirements for GPUs and other accelerator-like resources.
- future typed domains such as datasets when their semantics are defined.

The gateway uses resource requirements to prefilter configured compute drivers,
then relies on the selected driver to validate and provision the request.
`SandboxTemplate.resources` remains a platform-native realization layer and
escape hatch. It is not the portable driver-selection interface.

The current implementation lands the first GPU-focused phase of this model:
`resource_requirements.gpu` replaces the legacy GPU-specific request fields,
with an optional count. The broader generic compute/device/dataset model in
this RFC remains the target direction for later expansion.

## Motivation

OpenShell currently treats GPU placement as a special case. The public
`SandboxSpec` and internal `DriverSandboxSpec` both expose `gpu` and
`gpu_device`, while driver capability discovery reports only `supports_gpu` and
`gpu_count`. That is too narrow:

- GPU identifiers are driver-specific. Docker and Podman use CDI device names,
  while the VM driver supports device IDs by PCI BDF or index.
- Count-based placement and exact device selection are different allocation
  modes and should not be overloaded into one field.
- CPU and memory are common portable requirements, but today callers must use
  backend-shaped template resource passthrough for the public API path.
- The gateway needs a portable way to decide which configured driver can serve
  a sandbox request.
- Future resources, such as datasets, should not require another ad hoc field
  on `SandboxSpec`.

Issue #1338 identified a real user need: Kubernetes users need to request more
than one GPU. PR #1340 solves that immediate need by passing resource JSON into
`SandboxTemplate.resources` and making `--gpu-count` inject an
`nvidia.com/gpu` limit. This RFC intentionally supersedes that as the long-term
API direction. Kubernetes resource limits are a valid driver realization, but
portable GPU count belongs in typed resource requirements. JSON passthrough, if
exposed by the CLI, should be named and documented as driver-specific
configuration rather than portable resources.

The proposal is inspired by Kubernetes Dynamic Resource Allocation structured
parameters: scheduler-visible selection is structured, while driver-specific
configuration remains separate and is interpreted by the resource driver.
Exposing a general-purpose driver-specific configuration surface is related, but
tracked separately in issue #1492.

Since this RFC was first drafted, `SandboxTemplate.driver_config` has been
added as the driver-owned configuration surface. The gateway selects the block
for the active driver and forwards that inner object unchanged. Exact GPU
selection for Docker, Podman, and VM is now expressed there rather than in the
portable resource requirement.

## Non-goals

- Defining dataset allocation, mount, caching, or access-control semantics.
  Datasets are only a motivating future domain in this RFC.
- Building a gateway-level scheduler or reservation system.
- Exposing detailed per-device inventory from drivers.
- Exposing JSON-formatted portable resource requests in the CLI.
- Defining the general driver-specific configuration passthrough API. Issue
  #1492 tracks that related API surface.
- Publishing allocated resource identities in sandbox status.
- Preserving alpha-era compatibility for `gpu`, `gpu_device`, or a
  GPU-specific `gpu_count` request field. The legacy GPU-specific request
  fields are intentionally not carried forward into the API shape this RFC
  aims to stabilize.

## Proposal

### Public request model

Add resource requirements to `SandboxSpec` and remove the GPU-specific scalar
fields from the desired request model.

```proto
message SandboxSpec {
  string log_level = 1;
  map<string, string> environment = 5;
  SandboxTemplate template = 6;
  openshell.sandbox.v1.SandboxPolicy policy = 7;
  repeated string providers = 8;

  // Portable resource requirements used by the gateway for driver selection
  // and by drivers for provisioning.
  ResourceRequirements resource_requirements = 9;

  reserved 10;
  reserved "gpu_device";
}
```

The public sandbox API is still alpha. This migration intentionally replaces
the old `bool gpu = 9` field with the typed `resource_requirements = 9` message
instead of reserving the legacy field number. Old live requests and persisted
sandbox records that encode GPU intent through the legacy boolean are not
migrated; callers should use a matching OpenShell CLI/API version and recreate
GPU sandboxes after upgrade when they need the new typed shape. Avoiding
alpha-era reserved fields keeps the proto surface closer to the API intended
for stabilization.

`SandboxTemplate.resources` keeps its existing role as platform-native workload
configuration. It may contain Kubernetes-style CPU, memory, and extended
resource requests and limits, but it is not the portable resource contract.

The implemented first phase uses this narrower proto shape:

```proto
message ResourceRequirements {
  // GPU requirements for the sandbox. Presence indicates a GPU request.
  GpuResourceRequirements gpu = 1;
}

message GpuResourceRequirements {
  // Optional number of GPUs requested. When omitted, the request is for one
  // GPU using the selected driver's default assignment behavior.
  optional uint32 count = 1;
}
```

`gpu.count` must be greater than zero when present. When `gpu` is present and
`count` is omitted, the effective count is one. Drivers apply that same
effective-count rule when validating exact driver-config device lists.

The CLI should not expose a JSON flag for `resource_requirements`. Common
portable requests should use typed flags such as CPU, memory, and GPU-count
flags, and SDK/API callers should use the typed protobuf messages directly.
JSON-formatted driver-specific configuration remains separate from portable
resource requirements and is passed through `SandboxTemplate.driver_config`.

### Long-term resource requirements

Use typed requirement domains for stable first-party resource concepts instead
of making every request stringly typed through a `kind` field.

```proto
message SandboxResourceRequirements {
  // Fungible scalar workload requirements.
  ComputeResourceRequirements compute = 1;

  // Accelerator-like resources such as GPUs and MIG slices.
  repeated DeviceResourceRequirement devices = 2;

  // Future typed domain. Semantics are intentionally not defined in this RFC.
  repeated DatasetResourceRequirement datasets = 3;

  // Escape hatch for third-party or experimental resource domains.
  repeated GenericResourceRequirement extensions = 100;
}

message ComputeResourceRequirements {
  // Values use Kubernetes-style quantity strings because they are familiar and
  // already used by the driver resource model.
  string cpu_request = 1;
  string cpu_limit = 2;
  string memory_request = 3;
  string memory_limit = 4;
}

message DeviceResourceRequirement {
  // Optional local name for error messages and future status correlation.
  string name = 1;

  // Portable device class requested by the workload, such as "gpu",
  // "nvidia-gpu", or a future OpenShell-defined class name.
  string class_name = 2;

  // Number of devices in the class requested. Must be greater than zero.
  uint32 count = 3;

  // Portable labels or attributes the selected device must satisfy.
  ResourceSelector selector = 4;

  // Namespaced parameter blocks. The gateway may use namespace support for
  // prefiltering, but only drivers interpret the parameter values.
  repeated ResourceParameterBlock parameters = 5;
}

message ResourceSelector {
  // Exact-match portable attributes such as vendor=nvidia.
  map<string, string> match_attributes = 1;
}

message ResourceParameterBlock {
  // DNS-style parameter namespace, such as cdi.openshell.ai.
  string namespace = 1;
  google.protobuf.Struct parameters = 2;
}

message DatasetResourceRequirement {
  string name = 1;
  string class_name = 2;
  ResourceSelector selector = 3;
  repeated ResourceParameterBlock parameters = 4;
}

message GenericResourceRequirement {
  string kind = 1;
  string name = 2;
  uint32 count = 3;
  ResourceSelector selector = 4;
  repeated ResourceParameterBlock parameters = 5;
}
```

The gateway validates the portable envelope:

- compute quantities must be syntactically valid quantity strings.
- device `class_name` must be non-empty.
- device `count` must be greater than zero.
- parameter namespace keys must be DNS-style names.
- parameter values must fit existing request-size limits.

The gateway does not interpret parameter values. A driver must reject a request
that contains a parameter namespace it does not support, and the gateway may
prefilter candidates using the same namespace support.

### Compute requirements

Compute requirements are fungible CPU and memory requirements. They differ from
devices because they usually do not need exact identity or driver-specific
selection.

This RFC standardizes only CPU and memory as initial portable compute
requirements. Other compute-shaped constraints such as ephemeral storage, huge
pages, PID limits, shared memory, or similar cgroup-backed limits may be added
later, but only once their request/limit semantics are clear and they can map to
multiple drivers. Driver-specific support for such constraints should stay in
driver-specific configuration until it is portable enough for the first-party
API.

Example request:

```yaml
resourceRequirements:
  compute:
    cpuRequest: "2"
    cpuLimit: "4"
    memoryRequest: 4Gi
    memoryLimit: 8Gi
```

Example realizations:

| Driver | Realization |
|---|---|
| Kubernetes | Populate pod container `resources.requests.cpu`, `resources.limits.cpu`, `resources.requests.memory`, and `resources.limits.memory`. |
| Docker | Apply supported runtime limits such as CPU quota/NanoCPUs and memory limit. Requests are capacity checks when the driver can evaluate host capacity. |
| Podman | Apply supported runtime limits such as CPU quota and memory limit. Requests are capacity checks when the driver can evaluate host capacity. |
| VM | Map CPU and memory limits to VM vCPU count and guest memory allocation. The driver may require request and limit to be equal when it cannot represent separate request/limit semantics. |

Compute requirements describe the sandbox workload that the driver provisions,
not every runtime-managed helper process. If a driver later runs the proxy,
supervisor, or other control-plane helpers in separate containers, sidecars, or
pods, it may apply fixed overhead or expose helper-specific settings through
driver-specific configuration. Those helper resources are driver implementation
details unless a later RFC promotes them into portable resource requirements.

Drivers must reject compute requirements they cannot honor. They must not
silently accept a limit or request that has no effect.

### Device requirements

Device requirements cover GPUs and other accelerator-like resources. The first
standard device class is `gpu`.

Portable GPU semantics are limited to:

- `class_name`
- `count`
- exact-match attributes in `selector.match_attributes`

In the current GPU-focused implementation, only the `gpu.count` portion is
implemented in `ResourceRequirements`. Exact device IDs are not portable
selector attributes yet; they remain driver-owned config. Docker and Podman use
`driver_config.cdi_devices`, and VM uses `driver_config.gpu_device_ids`.

Driver-native GPU details are expressed through namespaced parameters. Example
parameter namespaces:

| Namespace | Intended drivers | Example fields |
|---|---|---|
| `cdi.openshell.ai` | Docker, Podman | `deviceId: "nvidia.com/gpu=all"` |
| `kubernetes.openshell.ai` | Kubernetes | `resourceName: "nvidia.com/gpu"`, `resourceClassName: "nvidia-gpu"` |
| `vm.openshell.ai` | VM | `deviceId: "0000:2d:00.0"`, `deviceIdType: "bdf"` |

Example request for any NVIDIA GPU:

```yaml
resourceRequirements:
  devices:
    - name: gpu
      className: gpu
      count: 1
      selector:
        matchAttributes:
          vendor: nvidia
```

Example request for four GPUs. A Kubernetes driver may realize this as
`limits["nvidia.com/gpu"] = "4"`, but the public request stays portable:

```yaml
resourceRequirements:
  devices:
    - name: training-gpus
      className: gpu
      count: 4
```

Example request for a CDI GPU supported by Docker or Podman:

```yaml
resourceRequirements:
  devices:
    - name: gpu
      className: gpu
      count: 1
      parameters:
        - namespace: cdi.openshell.ai
          parameters:
            deviceId: nvidia.com/gpu=all
```

Example request for a VM GPU by BDF:

```yaml
resourceRequirements:
  devices:
    - name: gpu
      className: gpu
      count: 1
      parameters:
        - namespace: vm.openshell.ai
          parameters:
            deviceId: "0000:2d:00.0"
            deviceIdType: bdf
```

Example realizations:

| Driver | Realization |
|---|---|
| Kubernetes | Convert `className=gpu,count=N` into a pod resource limit such as `limits["nvidia.com/gpu"] = "N"` unless Kubernetes-specific parameters select another resource name or class. |
| Docker | Use exact `driver_config.cdi_devices` values when present; otherwise select `count` default CDI GPU IDs from the discovered inventory. |
| Podman | Use exact `driver_config.cdi_devices` values when present; otherwise select `count` default CDI GPU IDs from the discovered inventory. |
| VM | Convert VM parameters into BDF or index-based device assignment. |

Docker and Podman default selection is round-robin over the normalized NVIDIA
CDI inventory. Indexed IDs are preferred and sorted numerically; named IDs are
used when no indexed IDs exist. On WSL2 all-only runtimes, `nvidia.com/gpu=all`
can be used as a fallback and counts as one selectable device. The selector
refreshes its inventory before validating and creating default GPU requests so
CDI devices added or removed after driver startup can affect later creates.

Explicit CDI IDs are opaque. The drivers do not parse aliases, normalize
`nvidia.com/gpu=all`, or treat it specially on the explicit path. Exact ID
lists must not contain duplicates and their length must match the effective GPU
count. A list of two explicit IDs with `--gpu` and no count fails because the
effective count is one.

Docker and Podman should not interpret VM BDF/index parameters. The VM driver
should not interpret CDI parameters. Gateway namespace prefiltering should avoid
sending clearly incompatible requests to those drivers.

### Combined examples

CPU, memory, and one GPU:

```yaml
resourceRequirements:
  compute:
    cpuRequest: "4"
    cpuLimit: "8"
    memoryRequest: 16Gi
    memoryLimit: 32Gi
  devices:
    - name: gpu
      className: gpu
      count: 1
      selector:
        matchAttributes:
          vendor: nvidia
```

Kubernetes realization:

```yaml
resources:
  requests:
    cpu: "4"
    memory: 16Gi
  limits:
    cpu: "8"
    memory: 32Gi
    nvidia.com/gpu: "1"
```

Docker or Podman realization:

```text
runtime CPU/memory limits derived from compute limits
CDI device injection derived from the selected gpu device requirement
```

VM realization:

```text
VM vCPU count and memory allocation derived from compute limits
GPU passthrough derived from vm.openshell.ai parameters when present
```

### Specific realizations

These examples show how the same portable request is compiled after a driver is
selected. The exact serialized platform payload remains driver-owned; these are
the intended effects.

#### Kubernetes CPU and memory

Input:

```yaml
resourceRequirements:
  compute:
    cpuRequest: "2"
    cpuLimit: "4"
    memoryRequest: 4Gi
    memoryLimit: 8Gi
```

Kubernetes pod container resources:

```yaml
resources:
  requests:
    cpu: "2"
    memory: 4Gi
  limits:
    cpu: "4"
    memory: 8Gi
```

#### Kubernetes multi-GPU

Input:

```yaml
resourceRequirements:
  devices:
    - name: training-gpus
      className: gpu
      count: 4
```

Kubernetes pod container resources:

```yaml
resources:
  limits:
    nvidia.com/gpu: "4"
```

If `kubernetes.openshell.ai.resourceName` is provided, the driver uses that
resource name instead of `nvidia.com/gpu`.

#### Docker or Podman CDI GPU

Input:

```yaml
resourceRequirements:
  devices:
    - name: gpu
      className: gpu
      count: 1
      parameters:
        - namespace: cdi.openshell.ai
          parameters:
            deviceId: nvidia.com/gpu=0
```

Docker or Podman runtime request:

```text
--device nvidia.com/gpu=0
```

The gateway can prefilter this request to drivers that advertise the
`cdi.openshell.ai` parameter namespace for the `gpu` device class.

#### VM GPU by BDF

Input:

```yaml
resourceRequirements:
  devices:
    - name: gpu
      className: gpu
      count: 1
      parameters:
        - namespace: vm.openshell.ai
          parameters:
            deviceId: "0000:2d:00.0"
            deviceIdType: bdf
```

VM driver realization:

```text
attach host PCI device 0000:2d:00.0 to the sandbox VM
```

The gateway can prefilter this request to VM-like drivers that advertise the
`vm.openshell.ai` parameter namespace for the `gpu` device class.

#### Conflicting portable and template resources

Input:

```yaml
resourceRequirements:
  devices:
    - name: gpu
      className: gpu
      count: 4
template:
  resources:
    limits:
      nvidia.com/gpu: "1"
```

Result:

```text
validation failure: portable GPU count conflicts with template GPU limit
```

The request must fail rather than letting either source silently override the
other.

### Related driver-specific configuration

Driver-specific configuration is intentionally separate from portable resource
requirements. The current API uses `SandboxTemplate.driver_config` as an
opaque envelope keyed by driver name. The gateway selects the block for the
active driver and forwards that inner object to the compute driver; the driver
owns nested schema validation.

`driver_config` is the right place for backend-native settings such as
Kubernetes node selectors, tolerations, image pull secrets, Docker or Podman
mounts, and exact GPU IDs. These settings are not portable resource
requirements, and the gateway must not interpret them as a scheduling contract.

This RFC does not introduce `--resources-json`, `--resource-requirements-json`,
or `--template-resources-json`. CPU, memory, GPU count, and exact GPU selection
should use typed resource fields, typed CLI flags, or the selected driver's
documented `driver_config` fields. Backend-native settings that are not modeled
by `resource_requirements` should remain driver-specific and should not be
presented as portable resource requests.

### Template realization and conflicts

Drivers compile resource requirements into their native realization model:
template resources, runtime device injection, VM device assignment, or platform
config.

`SandboxTemplate.resources` remains available for platform-native workload
settings. Those settings are applied after driver selection and must not be
used as the portable matching signal.

If resource requirements and template resources express incompatible demands
for the same resource, validation must fail loudly. For example, a sandbox that
requests `className=gpu,count=4` while also setting
`template.resources.limits["nvidia.com/gpu"] = "1"` is invalid. Drivers must
not silently override portable resource intent with template passthrough values,
or template passthrough values with portable resource intent.

Requests with only `SandboxTemplate.resources` are valid platform-native
passthrough, but they do not participate in portable driver matching. Existing
`SandboxTemplate.resources` behavior can be preserved during migration, but
should not gain a stable CLI flag named `--resources-json` because that name
conflicts with portable resource requirements.

### Driver request model

The internal compute-driver API mirrors the public resource request shape
without importing the public API types. `DriverSandboxSpec` receives translated
driver-owned resource requirements and drops `gpu` and `gpu_device`.

```proto
message DriverSandboxSpec {
  string log_level = 1;
  map<string, string> environment = 5;
  DriverSandboxTemplate template = 6;
  ResourceRequirements resource_requirements = 9;

  reserved 10;
  reserved "gpu_device";
}
```

Driver-owned resource requirement messages should have the same semantics as
the public messages, but live in `compute_driver.proto` to keep the public and
internal contracts separated. In the current implementation, the driver proto
mirrors the narrow GPU-focused shape:

```proto
message ResourceRequirements {
  GpuResourceRequirements gpu = 1;
}

message GpuResourceRequirements {
  optional uint32 count = 1;
}
```

The compute-driver API is version-coupled to the gateway in current deployments:
local drivers are launched by the gateway at startup, and the driver proto is
not treated as a public compatibility surface. It follows the same alpha-era
field replacement as the public API rather than preserving transitional GPU
fields.

### Driver capabilities

The current implementation removes the GPU-specific `supports_gpu` and
`gpu_count` capability fields from the compute-driver proto. It does not yet
replace them with a stable resource capability summary. Until that lands, the
selected driver's `ValidateSandboxCreate` remains the authority for whether a
GPU request can be served.

A later phase should add coarse resource capability summaries:

```proto
message GetCapabilitiesResponse {
  string driver_name = 1;
  string driver_version = 2;
  string default_image = 3;
  DriverResourceCapabilities resource_capabilities = 6;

  reserved 4, 5;
  reserved "supports_gpu", "gpu_count";
}

message DriverResourceCapabilities {
  ComputeResourceCapability compute = 1;
  repeated DeviceClassCapability device_classes = 2;
  repeated GenericResourceCapability extensions = 100;
}

message ComputeResourceCapability {
  bool supports_cpu_request = 1;
  bool supports_cpu_limit = 2;
  bool supports_memory_request = 3;
  bool supports_memory_limit = 4;
}

message DeviceClassCapability {
  string class_name = 1;

  // Omitted when the driver cannot cheaply or accurately report availability.
  optional uint32 allocatable_count = 2;

  // Portable attributes this driver may use for prefiltering. This is a
  // summary, not a per-device inventory.
  map<string, string> attributes = 3;

  // Parameter namespaces the driver understands for this device class.
  repeated string parameter_namespaces = 4;
}
```

Capabilities are advisory. They allow the gateway to reject clearly impossible
requests and choose a likely driver, but they are not a reservation.

### Gateway matching

The gateway should evaluate configured compute drivers in a deterministic
order. The default order is the order in gateway configuration.

For a sandbox create request:

1. Load or refresh driver capabilities.
2. Keep candidates that support the requested compute fields.
3. Keep candidates that support every requested device class.
4. Reject candidates whose known `allocatable_count` is lower than the
   requested device count.
5. Reject candidates that do not advertise every parameter namespace present in
   the request for that device class.
6. Apply portable selector prefiltering only when the driver advertises matching
   attributes. Absence of an advertised attribute should not be treated as a
   match.
7. Call `ValidateSandboxCreate` on remaining candidates in deterministic order.
8. Select the first driver that validates the request.
9. Return a user-facing error containing summarized validation failures if no
   driver can serve the request.

The selected driver's `CreateSandbox` call remains the final authority. A
request that passes gateway prefiltering can still fail if resources disappear
or if driver-specific validation rejects parameter values.

When no resource requirements are present, the gateway should preserve today's
default behavior and use the configured default driver.

## Implementation state and plan

Implemented in the first phase:

1. Replace the public and driver `gpu`/`gpu_device` request fields with
   `resource_requirements.gpu`.
2. Treat a present GPU requirement with omitted `count` as an effective request
   for one GPU, and reject `count = 0`.
3. Pass GPU requirements through gateway-to-driver create and validation paths.
4. Keep exact device IDs in `driver_config`:
   `driver_config.cdi_devices` for Docker and Podman, and
   `driver_config.gpu_device_ids` for VM.
5. Reject duplicate exact device IDs and require exact device list length to
   match the effective GPU count.
6. Let Kubernetes map GPU count to the `nvidia.com/gpu` limit.
7. Let Docker and Podman satisfy count-only GPU requests by selecting default
   CDI devices from a refreshed local inventory.
8. Remove GPU-specific capability fields from the compute-driver proto without
   adding replacement resource capability summaries yet.
9. Do not expose JSON-formatted portable resource request flags.

Remaining follow-up work:

1. Add the broader compute/device/dataset resource model when those semantics
   are stable enough for the public API.
2. Add coarse resource capability summaries and gateway matching across
   multiple configured drivers.
3. Add conflict validation between portable resource requirements and
   platform-native template resource passthrough where both can express the
   same resource.
4. Decide whether and how drivers should expose inventory or capacity for
   advisory matching without turning it into a reservation API.

Because the public and driver APIs are still alpha, the first implementation
intentionally breaks old live and persisted GPU intent instead of preserving
compatibility shims for the legacy GPU fields. Callers should use a matching
OpenShell CLI/API version and recreate GPU sandboxes after upgrade when they
need the new typed request shape.

## Tests

The implementation should include:

- protobuf translation tests for public resource requirements into driver
  resource requirements.
- shared helper tests showing that omitted GPU count is effective count one and
  explicit zero count is rejected.
- validation tests for duplicate exact device IDs and for mismatched exact
  device-list length versus effective GPU count.
- Kubernetes tests that map compute requirements to pod CPU/memory resources
  and GPU count to `nvidia.com/gpu` limits.
- Docker and Podman selector tests for numeric CDI ID ordering, named CDI ID
  fallback, count-based round-robin selection, all-only fallback, insufficient
  devices, and inventory refresh without cursor reset.
- Docker and Podman validation tests showing that explicit CDI IDs bypass
  default inventory selection and remain opaque.
- VM tests that map CPU/memory to VM allocation and request a GPU by BDF or
  index through `driver_config.gpu_device_ids`.
- CLI request-shape tests showing that there is no JSON-formatted portable
  resource request flag.
- future gateway matching tests for compute capability support, device class,
  count, selector, and parameter namespace filtering once resource capability
  summaries are added.
- future validation tests for conflicts between resource requirements and
  template resource passthrough once those conflicts can occur through stable
  portable fields.
- error-message tests for no matching driver and validation failure across all
  candidates.

## Risks

- The typed model may still need adjustment when dataset semantics are fully
  designed.
- Coarse capabilities can be stale, so users may still see create-time failures
  after gateway prefiltering succeeds.
- A breaking API change affects CLI users, SDK users, and any direct gRPC
  clients.
- Namespaced parameters can fragment if drivers define overlapping ways to
  express the same concept.
- Supporting multiple configured compute drivers changes gateway assumptions
  that currently require exactly one driver.
- Existing template resource passthrough creates a second way to express some
  platform-native requirements, so conflict validation and documentation need
  to be clear.

## Alternatives

- Use `SandboxTemplate.resources` as the only resource request interface. This
  works for Kubernetes-style CPU, memory, and extended resources, but it makes
  portable driver selection depend on backend-shaped data.
- Expose `--resources-json` as a CLI shortcut for `resource_requirements`. This
  would avoid adding one flag per typed resource, but it weakens the CLI
  contract and makes the portable resource model feel like another opaque
  passthrough surface.
- Expose `--resources-json` as a CLI shortcut for `SandboxTemplate.resources`.
  This matches PR #1340's immediate implementation direction, but the name
  implies portable resource semantics. Backend-native configuration needs a
  separate driver-specific design, tracked by issue #1492.
- Use a repeated `kind`-based requirement for all resources. This keeps gateway
  matching generic, but makes common resources such as CPU, memory, and GPU more
  stringly typed than necessary.
- Keep `gpu`, `gpu_device`, and add `gpu_count`. This is simple for GPUs but
  does not help CPU, memory, datasets, or other future resource kinds.
- Make all resource metadata opaque to the gateway. This gives drivers maximum
  flexibility but prevents meaningful gateway prefiltering.
- Expose detailed per-device inventory from drivers. This would improve
  matching precision but pushes the gateway toward scheduler and reservation
  responsibilities that this RFC intentionally avoids.
- Preserve GPU-specific fields and flags as compatibility shims. This reduces
  migration friction but keeps two request paths for the same concept.

## Prior art

- Kubernetes Dynamic Resource Allocation separates scheduler-visible selection
  from driver-owned resource parameters and allocation behavior.
- Kubernetes extended resources provide a count-based model for devices such as
  GPUs, but do not handle driver-specific parameterization by themselves.
- Container Device Interface gives container runtimes a common way to name and
  inject devices, but CDI names are still a container-runtime concern rather
  than a portable OpenShell resource identifier.

## Open questions

- Should OpenShell define a registry of standard device classes and portable
  selector attributes, or should that evolve informally as drivers add support?
- Should allocated resource identities be exposed in sandbox status in a later
  RFC?
- Should parameter namespaces have published schemas, or should drivers own
  validation and documentation independently?
- Should gateway capability summaries be refreshed on every create request, on
  a timer, or only when a driver reports a watch/event signal?
