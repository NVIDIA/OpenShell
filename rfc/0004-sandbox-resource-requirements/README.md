---
authors:
  - "@elezar"
state: accepted
links:
  - https://github.com/NVIDIA/OpenShell/issues/1338
  - https://github.com/NVIDIA/OpenShell/pull/1340
  - https://github.com/NVIDIA/OpenShell/pull/1360
  - https://github.com/NVIDIA/OpenShell/issues/1492
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

## Non-goals

- Defining dataset allocation, mount, caching, or access-control semantics.
  Datasets are only a motivating future domain in this RFC.
- Building a gateway-level scheduler or reservation system.
- Exposing detailed per-device inventory from drivers.
- Exposing JSON-formatted portable resource requests in the CLI.
- Defining the general driver-specific configuration passthrough API. Issue
  #1492 tracks that related API surface.
- Publishing allocated resource identities in sandbox status.
- Preserving long-term compatibility for `gpu`, `gpu_device`, or a
  GPU-specific `gpu_count` request field.

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
  SandboxResourceRequirements resource_requirements = 11;

  reserved 9, 10;
  reserved "gpu", "gpu_device";
}
```

`SandboxTemplate.resources` keeps its existing role as platform-native workload
configuration. It may contain Kubernetes-style CPU, memory, and extended
resource requests and limits, but it is not the portable resource contract.

The CLI should not expose a JSON flag for `resource_requirements`. Common
portable requests should use typed flags such as CPU, memory, and GPU-count
flags, and SDK/API callers should use the typed protobuf messages directly.
JSON-formatted driver-specific configuration is a related but separate API
topic. Issue #1492 tracks exposing an opaque driver-owned configuration surface,
potentially named `driver_config`. This RFC only requires that driver-native
configuration remains separate from portable resource requirements.

### Resource requirements

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
| Docker | Convert CDI parameters into Docker CDI device injection. For a count-only request, select an available CDI GPU device when device inventory is available. |
| Podman | Convert CDI parameters into Podman CDI device injection. For a count-only request, select an available CDI GPU device when device inventory is available. |
| VM | Convert VM parameters into BDF or index-based device assignment. |

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
requirements. Issue #1492 tracks an opaque driver-owned configuration surface
for backend-native settings such as Kubernetes node selectors, tolerations,
image pull secrets, Docker network mode, or VM disk shape. A future design may
place that surface on `SandboxTemplate.driver_config` and may use a namespaced
map-of-maps shape, but this RFC does not standardize that API or its CLI flags.

This RFC does not introduce `--resources-json`, `--resource-requirements-json`,
or `--template-resources-json`. CPU, memory, GPU count, and exact GPU selection
should use typed resource fields or typed CLI flags. Backend-native settings
that are not modeled by `resource_requirements` should remain driver-specific
and should not be presented as portable resource requests.

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
  DriverSandboxResourceRequirements resource_requirements = 11;

  reserved 9, 10;
  reserved "gpu", "gpu_device";
}
```

Driver-owned resource requirement messages should have the same semantics as
the public messages, but live in `compute_driver.proto` to keep the public and
internal contracts separated.

### Driver capabilities

Replace GPU-specific capability fields with coarse resource capability
summaries:

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

## Implementation plan

1. Update public protobufs to add `SandboxResourceRequirements` and remove the
   long-term use of `gpu` and `gpu_device`.
2. Update compute-driver protobufs with mirrored driver-owned resource
   requirements and coarse resource capability summaries.
3. Update gateway validation and public-to-driver translation.
4. Add validation that rejects conflicts between portable resource requirements
   and template resource passthrough.
5. Allow the gateway to consider multiple configured compute drivers for a
   create request, using capability prefiltering plus `ValidateSandboxCreate`.
6. Update Kubernetes, Docker, Podman, and VM drivers to advertise compute and
   GPU device capability summaries and interpret their supported parameter
   namespaces.
7. Update CLI/API request construction so CPU, memory, GPU count, and exact GPU
   selection use resource requirements instead of GPU-specific request fields.
8. Do not expose JSON-formatted portable resource request flags.
9. Update user-facing docs and driver README files once behavior is
   implemented.

Because this is a breaking request-spec change, the implementation must either
land in a breaking API version or be explicitly called out as a breaking change
for the current API. Removed protobuf tags should be reserved rather than
reused.

## Tests

The implementation should include:

- protobuf translation tests for public resource requirements into driver
  resource requirements.
- gateway matching tests for compute capability support, device class, count,
  selector, and parameter namespace filtering.
- gateway tests showing that the selected driver is the first validating
  candidate in configured order.
- validation tests for conflicts between resource requirements and template
  resource passthrough.
- validation tests that unsupported parameter namespaces are rejected.
- Kubernetes tests that map compute requirements to pod CPU/memory resources
  and GPU count to `nvidia.com/gpu` limits.
- Docker and Podman GPU e2e tests that request a CDI GPU with
  `cdi.openshell.ai`.
- VM tests that map CPU/memory to VM allocation and request a GPU by BDF or
  index with `vm.openshell.ai`.
- tests showing that template-only resources are treated as platform-native
  passthrough and are not used for portable driver matching.
- CLI request-shape tests showing that there is no JSON-formatted portable
  resource request flag.
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
