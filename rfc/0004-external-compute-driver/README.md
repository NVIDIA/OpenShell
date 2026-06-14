---
authors:
  - "@priel"
state: draft
links: []
---

# RFC 0004 - External Compute Driver Readiness and Introspection

<!--
See rfc/README.md for the full RFC process and state definitions.
-->

## Summary

This RFC proposes three contract-level additions for out-of-process
compute drivers:

1. **Driver readiness.** A driver that speaks
   `openshell.compute.v1.ComputeDriver` may also serve the standard
   `grpc.health.v1.Health` service on the same gRPC endpoint. The
   gateway can use that signal to gate new sandbox creates.
2. **Extensible capabilities.** Add an optional feature map to
   `GetCapabilitiesResponse`, preserving the existing response fields
   while giving future driver features a negotiation surface.
3. **Driver introspection.** Add a gateway-owned status view for the
   configured compute driver so operators can see readiness,
   capabilities, and connection state without reading logs.

The RFC intentionally stays at the `ComputeDriver` boundary. It does
not standardize how a particular driver launches processes, talks to
its backend, stores state, authenticates to local sockets, configures
VMs, or maps platform-specific resources.

## Motivation

OpenShell should be able to run sandboxes on more than the compute
backends compiled into the gateway. Teams will want to attach gateways
to local containers, Kubernetes clusters, VM pools, hosted accelerators,
and private fleet managers without turning each backend into gateway
code. The compute-driver boundary is the place where that happens: the
gateway owns the public sandbox API, persistence, policy, and supervisor
session model, while the driver owns platform-specific provisioning and
observation.

That boundary is useful only if it is operable as an independent
component. Once a driver can run outside the gateway process, the
gateway needs to know whether the driver is ready for new work, clients
need predictable behavior when a backend is temporarily unavailable, and
operators need enough status to debug the deployment without learning
the internals of every driver. This RFC adds the minimal contract needed
for that: readiness, feature negotiation, and gateway-owned
introspection.

### Gap 1: readiness is not part of the driver contract

A gateway can call the driver, but it cannot distinguish
"connected to the gRPC endpoint" from "ready to provision sandboxes."
A driver may need time to validate backend permissions, warm caches, or
reconcile existing platform resources before `CreateSandbox` is safe.
The same driver may later become unable to create new sandboxes while
existing sandboxes remain observable and deletable.

Without a driver readiness signal, those conditions surface as ordinary
sandbox create failures. Operators and clients lose the difference
between "the request is invalid" and "the compute backend is temporarily
not accepting new work."

### Gap 2: capabilities cannot describe optional behavior

`GetCapabilitiesResponse` contains driver identity, default image, and
GPU capacity:

```proto
message GetCapabilitiesResponse {
  string driver_name = 1;
  string driver_version = 2;
  string default_image = 3;
  bool supports_gpu = 4;
  uint32 gpu_count = 5;
}
```

Those fields cover the baseline driver contract, but they do not give the
gateway a general way to discover optional behavior before relying on
it. Adding a new top-level field for every optional capability will not
scale, and overloading `driver_name` or `driver_version` would make
feature detection brittle.

### Gap 3: operator visibility stops at gateway health

The gateway has `/health`, `/healthz`, `/readyz`, metrics support, and
the public `OpenShell.Health` RPC. Those surfaces answer gateway-level
questions, not driver-specific questions:

- Which compute driver is configured?
- What capabilities did it advertise?
- Is the driver ready for new creates?
- If readiness changed, when did it change and why?
- Is the driver local, remote, in-process, or otherwise connected?

For a single-process local driver this is inconvenient. For an
out-of-process driver, it becomes a production support problem.

## Existing contract

This RFC assumes the existing compute-driver layering:

- The internal driver API is `openshell.compute.v1.ComputeDriver`.
- Drivers return `DriverSandbox` observations, not public
  `openshell.v1.Sandbox` resources.
- The gateway translates driver observations into the public sandbox
  model and owns public sandbox phase, persistence, and client-visible
  metadata.
- `GetCapabilitiesResponse` is the driver-to-gateway capability
  exchange.
- The supervisor connection and relay protocol are separate from the
  compute-driver API.

For out-of-process drivers, this RFC assumes the gateway already holds
a long-lived gRPC channel to the driver. How that channel is
established (binary discovery, argv, sockets, restart policy) is the
job of a separate external-driver launcher contract. This RFC
intentionally does not cover it, and the readiness contract below is
only fully operational once that launcher contract exists.

## Non-goals

- **Changing sandbox lifecycle RPCs.** `ValidateSandboxCreate`,
  `CreateSandbox`, `StopSandbox`, `DeleteSandbox`, `GetSandbox`,
  `ListSandboxes`, and `WatchSandboxes` keep their current request and
  response shapes except for additive capability metadata.
- **Standardizing driver launch.** Binary discovery, argv shape,
  working directory, environment variables, socket paths, restart
  policy, and process supervision are intentionally out of scope.
- **Standardizing backend configuration.** Backend-specific settings
  belong in existing driver configuration or in
  `DriverSandboxTemplate.platform_config`, depending on whether they
  are gateway-level or sandbox-level inputs.
- **Standardizing session behavior.** Supervisor connection and relay
  behavior remain part of the public OpenShell API and sandbox
  supervisor contract, not the compute-driver API.
- **Adding a second public sandbox model.** Drivers continue to report
  driver-native observations; the gateway continues to own public
  sandbox phase, persistence, and client-visible metadata.
- **Defining future features.** This RFC defines the feature
  negotiation mechanism, not the semantics of future features such as
  snapshot restore, warm start, placement hints, or GPU allocation
  policy.

## Proposal

### 1. Driver readiness via gRPC health

Drivers that run out of process SHOULD serve the standard
`grpc.health.v1.Health` service on the same endpoint as
`openshell.compute.v1.ComputeDriver`.

The gateway probes this service name:

```text
openshell.compute.v1.ComputeDriver
```

```mermaid
sequenceDiagram
    participant G as Gateway
    participant D as Compute Driver
    G->>D: Health.Watch(service="openshell.compute.v1.ComputeDriver")
    D-->>G: SERVING
    G->>D: GetCapabilities
    Note over G: New creates may be dispatched
    G->>D: CreateSandbox
    D-->>G: ok
    D-->>G: NOT_SERVING
    Note over G: New creates are gated; observation and cleanup continue
    D-->>G: SERVING
    Note over G: New creates may resume
```

Gateway behavior:

- The gateway uses `Health.Watch` against the specific service name
  `openshell.compute.v1.ComputeDriver`, not the empty service name.
- `SERVING` makes the driver eligible for new `CreateSandbox`
  requests.
- `NOT_SERVING` gates new `CreateSandbox` requests for that driver.
- `SERVICE_UNKNOWN` and `UNIMPLEMENTED` on the service are treated as
  readiness-unknown, not as non-serving: the gateway preserves
  current behavior and logs that the readiness signal is unavailable.
- On `Watch` stream loss, the gateway holds the last known state for a
  short grace window before transitioning to readiness-unknown, so
  transient network blips do not look like driver outages.
- `GetSandbox`, `ListSandboxes`, `WatchSandboxes`, `StopSandbox`, and
  `DeleteSandbox` remain callable while readiness is degraded, because
  observation and cleanup should remain possible when create capacity is
  unavailable.
- The gateway records the most recent readiness state, transition time,
  and error detail for introspection.

Driver behavior:

- Report `SERVING` only when the driver can accept new
  `CreateSandbox` work for its configured backend.
- Report `NOT_SERVING` when new creates should be held back, even if
  existing sandboxes are still observable or deletable.
- Keep `Health.Check` inexpensive. Expensive backend validation should
  update cached readiness state rather than run in the RPC path.
- Debounce rapid internal state transitions before publishing them
  through `Health.Watch`.

This RFC does not require the gateway to restart a process because of a
readiness transition. Restart policy is a launcher concern and should be
defined with a generic external-driver launcher, not hidden inside this
readiness contract.

### 2. Add feature flags to `GetCapabilitiesResponse`

Extend the existing response message additively:

```proto
message GetCapabilitiesResponse {
  string driver_name = 1;
  string driver_version = 2;
  string default_image = 3;
  bool supports_gpu = 4;
  uint32 gpu_count = 5;

  // Optional feature flags advertised by the driver.
  //
  // Keys are stable strings registered in the compute-driver capability
  // registry. A driver must advertise true only for behavior it fully
  // supports for this gateway configuration.
  map<string, bool> features = 6;
}
```

This RFC bootstraps the registry but does not define any feature keys
itself. Readiness is intentionally not exposed as a feature flag,
because the live `Health` probe is already authoritative; advertising
`grpc_health_v1` would just be a second place for a driver to lie.

Rules:

- Unknown feature keys are ignored by the gateway.
- Missing `features` is equivalent to an empty map.
- A gateway must check a feature flag before depending on optional
  behavior represented by that flag.
- A driver must not advertise a feature merely because it recognizes the
  name; it should advertise only behavior that is enabled and usable in
  the current configuration.

The feature registry should live in the compute-driver architecture or
reference documentation once this RFC is accepted. Future RFCs or PRs
that add feature flags should update that registry with semantics and
compatibility expectations.

### 3. Add gateway-owned introspection

Add an authenticated, admin-authorized OpenShell API method that
exposes gateway state, starting with compute driver status. Keeping
this on the existing gateway API surface avoids a new unauthenticated
HTTP endpoint and gives us a single place to grow other introspection
(providers, policy engine, build info) without one RPC per subsystem.

Illustrative shape:

```proto
service OpenShell {
  rpc GetGatewayStatus(GetGatewayStatusRequest)
      returns (GetGatewayStatusResponse);
}

message GetGatewayStatusRequest {}

message GetGatewayStatusResponse {
  // The gateway accepts one compute driver today. The field is
  // plural so the shape survives a future move to multiple drivers
  // without a breaking change.
  repeated ComputeDriverStatus compute_drivers = 1;
}

message ComputeDriverStatus {
  // What the operator asked for; may be empty for auto-detection.
  string configured_driver = 1;
  // What the gateway actually loaded.
  string active_driver = 2;
  ComputeDriverInfo info = 3;
  DriverReadiness readiness = 4;
  Connection connection = 5;
}

message ComputeDriverInfo {
  string driver_name = 1;
  string driver_version = 2;
  string default_image = 3;
  bool supports_gpu = 4;
  uint32 gpu_count = 5;
  map<string, bool> features = 6;
}

enum DriverReadinessState {
  DRIVER_READINESS_STATE_UNSPECIFIED = 0;
  // Driver does not implement gRPC health, or the watch stream is
  // lost and the grace window has elapsed.
  DRIVER_READINESS_STATE_UNKNOWN = 1;
  DRIVER_READINESS_STATE_SERVING = 2;
  DRIVER_READINESS_STATE_NOT_SERVING = 3;
}

message DriverReadiness {
  DriverReadinessState state = 1;
  google.protobuf.Timestamp last_transition_time = 2;
  string last_error = 3;
}

enum ConnectionMode {
  CONNECTION_MODE_UNSPECIFIED = 0;
  CONNECTION_MODE_IN_PROCESS = 1;
  CONNECTION_MODE_UNIX = 2;
  CONNECTION_MODE_GRPC = 3;
}

message Connection {
  ConnectionMode mode = 1;
  // URI-style endpoint. The gateway strips userinfo and any embedded
  // credentials before returning it.
  string endpoint = 2;
}
```

Proto names can change during implementation. The contract this RFC
proposes is the presence of a gateway-owned status view that, for
each configured compute driver, exposes configured vs. active driver
name, advertised identity and capabilities (translated from
`GetCapabilitiesResponse`), readiness state with transition time and
last error, and connection mode and endpoint with credentials
stripped. Public API consumers should not depend directly on internal
compute-driver messages.

The existing `/readyz` endpoint remains a coarse readiness probe. If
driver readiness is available and non-serving, `/readyz` returns
not-ready. If driver readiness is unknown, `/readyz` preserves current
behavior.

## Implementation plan

1. **Proto changes.** Add `features = 6` to
   `GetCapabilitiesResponse`. Add the gateway-owned driver status RPC
   and response messages to `openshell.proto`.
2. **Driver updates.** Update in-tree drivers to populate `features`
   (initially empty) and to serve `grpc.health.v1.Health` for
   `openshell.compute.v1.ComputeDriver` when they run out of process.
3. **Gateway readiness monitor.** For drivers reached through a gRPC
   channel, subscribe to `grpc.health.v1.Health/Watch` when available
   and store the latest readiness state. For in-process drivers or
   drivers without health, use readiness-unknown and preserve current
   create behavior.
4. **Create gating.** Gate new `CreateSandbox` dispatch only when the
   gateway has an explicit non-serving readiness signal. Do not block
   observation or cleanup RPCs.
5. **Introspection.** Implement `GetGatewayStatus` from gateway
   state. Add the method to admin authorization and scope tables.
6. **Readiness probes.** Include explicit non-serving driver readiness
   in `/readyz`; leave `/health` and `/healthz` as liveness-style
   endpoints.
7. **Docs and tests.** Document the feature registry and readiness
   contract. Add tests for feature parsing, readiness transitions,
   create gating, status response redaction, and `/readyz` behavior.
8. **Follow-ups (not blocking acceptance).** CLI surface
   (`openshell gateway status`) and basic gauges/counters for driver
   readiness and transitions, tracked as separate issues.

## Risks

- **Readiness becomes a hidden control plane.** Mitigated by keeping
  readiness limited to create gating. Sandbox lifecycle observation and
  cleanup remain available during degraded readiness.
- **Feature names become inconsistent.** Mitigated by a documented
  registry and by ignoring unknown keys.
- **Operators overinterpret readiness.** `NOT_SERVING` means the driver
  should not receive new creates. It does not imply existing sandboxes
  are dead.
- **Status leaks deployment detail.** Mitigated by making the status RPC
  authenticated, admin-authorized, and careful about endpoint redaction.
- **Mixed driver behavior during rollout.** Mitigated by treating
  missing health and missing feature maps as current behavior.
- **False-SERVING drivers.** A driver can report `SERVING` and still
  fail every `CreateSandbox`. Readiness cannot catch this; the gateway
  still relies on per-request error handling and any future circuit
  breaking. Called out here so operators don't read `SERVING` as a
  success oracle.

## Alternatives

- **Custom readiness RPC on `ComputeDriver`.** Rejected because gRPC
  health is standard and already has client and server implementations.
- **Driver HTTP `/healthz`.** Rejected because compute drivers already
  speak gRPC to the gateway; a second listener adds deployment and auth
  surface.
- **Use only `GetCapabilities` as a readiness check.** Rejected because
  capabilities are static driver metadata, while readiness can change at
  runtime.
- **Add top-level capability fields for every optional behavior.**
  Rejected because optional features will grow over time and many are
  meaningful only for specific driver classes.
- **Expose status only through logs and metrics.** Rejected because logs
  are hard to query operationally, and metrics are not a good place for
  structured driver identity, endpoint, and last-error information.
- **Use gRPC channel state as readiness.** Rejected because channel
  `READY` only means the gateway can reach a server; it does not mean
  the driver has validated its backend and can accept new creates.

## Prior art

- **gRPC Health Checking Protocol.** Standard service for per-service
  health state over gRPC.
- **Kubernetes readiness probes.** Readiness gates new traffic without
  necessarily killing existing work.
- **Envoy upstream health state.** Separates endpoint health from
  request routing and operator introspection.
- **Kubernetes feature gates and capability registries.** Provide a
  stable vocabulary for optional behavior without forcing every feature
  into the core version number.

## Open questions

- Should `GetGatewayStatus` return a history of recent readiness
  transitions, or only the latest state?
- Where should the capability registry live after acceptance:
  `docs/reference/sandbox-compute-drivers.mdx`, an architecture doc, or
  a dedicated proto comment block?
- Multi-driver: the gateway accepts one driver today, and
  `--drivers` is plural in anticipation. The response is already
  plural-shaped, but the readiness/create-gating wording assumes a
  single driver. Worth aligning before or alongside the multi-driver
  change.
- Driver capacity: `Health` is binary, but "healthy with zero free
  GPUs" is a real state. Out of scope for this RFC, or worth a
  placeholder field in `ComputeDriverInfo`?
- Should `features` be `repeated string` (Kubernetes feature-gate
  style) rather than `map<string, bool>`? `false` has no defined
  meaning in this RFC.
