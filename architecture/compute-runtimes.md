# Compute Runtimes

Compute runtimes create, stop, start, delete, and watch sandbox workloads for the
gateway. A supported runtime provisions `openshell-sandbox` inside the workload,
`openshell-supervisor` outside it, a protected channel between them, and an
independent outer network fence. Drivers do not implement policy evaluation.

## Driver Contract

Each runtime receives a sandbox spec and canonical policy from the gateway and
is responsible for:

- Selecting the sandbox image.
- Resolving an immutable non-root sandbox identity before workload creation.
- Supplying separate sandbox and supervisor bootstrap material.
- Delivering `openshell-sandbox` to the workload and `openshell-supervisor` only
  to the external supervisor placement.
- Provisioning protected control and boundary configs plus a private Unix socket,
  TLS-authenticated TCP, or vsock transport when the supervisor is separated.
  Runtime-specific code supplies immutable resource claims and transport
  coordinates; the shared boundary protocol supplies lifecycle, exec, signaling,
  forwarding, and binary identity semantics.
- Forwarding the exact canonical main-process argv and TTY mode without shell
  reconstruction. The sandbox-level environment and policy workspace apply to
  the main process.
- Reporting lifecycle and platform events back to the gateway.
- Cleaning up runtime-owned resources.

Drivers report **runtime-observed state only** and must not hold references to
gateway-internal types. For supervisor-controlled runtimes, `Ready=True` means
only that the compute resource is healthy; the gateway also requires a
supervisor session before publishing `SandboxPhase::Ready`. For
drivers that report runtime readiness, `Ready=True` is authoritative because the driver
launches and monitors the policy-constrained workload itself.

`compute_driver.proto` is the supported gateway/driver extension boundary.
At initialization the gateway snapshots the driver's identity, version,
default image, gateway-lifecycle preference, and
`driver_reports_runtime_readiness` from `GetCapabilities`. The gateway includes
the canonical `SandboxPolicy` in `DriverSandboxSpec.policy` for validation and
creation. Drivers that enforce policy outside the standard supervisor fetch
later revisions through `GetSandboxConfig` and acknowledge them through
`ReportPolicyStatus`.
Process-identity omissions are preserved across this boundary so every driver
can apply its native image or runtime defaults. Driver-requested listeners are
structurally validated and remain restricted to sandbox callback RPCs.

Canonical main-process support is part of the `ComputeDriver` contract. Every
in-tree and extension driver must forward the exact specification; it is not an
optional capability that drivers can omit or negotiate.

Drivers own runtime-specific platform event interpretation. When an event should
drive client provisioning UI, the driver attaches the shared
`openshell.progress.*` metadata defined in `openshell-core` instead of requiring
clients to parse Kubernetes reasons, VM cache states, or other driver-local
reason strings.

## Sandbox Readiness Composition

The gateway composes driver state with the advertised readiness behavior to
produce the public `SandboxPhase`:

```
backend_phase = derive_phase(driver_status)

public_phase =
  if backend_phase in {Error, Deleting}:                     → pass through (terminal precedence)
  if driver_reports_runtime_readiness && backend_phase == Ready: → Ready
  if backend_phase == Ready && session connected:             → Ready
  if backend_phase == Ready && no session:                    → Provisioning
  if backend_phase in {Provisioning, Unknown} && session:    → Ready
  if backend_phase in {Provisioning, Unknown} && no session: → Provisioning
```

For a supervisor-controlled runtime, `public_phase == Ready` means both the
backend resource is healthy and a supervisor session is registered. A sandbox whose
backend reports ready but has no supervisor session yet holds `Provisioning` with a
`Ready=False`, `SupervisorNotConnected` condition and the message
`Backend ready; waiting for supervisor session`. This distinguishes it from a sandbox
whose compute resource is still provisioning without exposing contradictory public
readiness signals. When the driver reports runtime readiness, its ready condition
is published without waiting for a supervisor session.

**Session precedence over lagging driver snapshots:** A supervisor session can only be
established by a running workload. When `set_supervisor_session_state` promotes the
store record to `Ready` on session connect, a driver watch event may still arrive
shortly after carrying a stale `Provisioning` or `Unknown` backend phase. The
composition rule treats a connected session as the stronger signal and keeps `Ready`
in that case, preventing a lagging snapshot from undoing the session-driven promotion.

**Known HA limitation:** Supervisor sessions are process-local while the public
sandbox phase is shared. A replica that reconciles a driver snapshot without owning
the active supervisor session can demote the shared phase to `Provisioning`. The
session-owning replica may not receive another connection event to restore `Ready`,
so a usable sandbox can remain unavailable through the public phase gate. Reliable
HA readiness requires persisted or leased supervisor presence plus routing to the
session-owning replica. That work is deferred to GitHub issue #1868. Until then,
deployments that require reliable readiness composition must run a single gateway
replica.

**Extension point:** Driver-reported readiness is a capability, not an
operator-configurable hook. A driver may enable it only when it owns workload
readiness. Policy delivery remains independent: create-time policy is embedded
in the sandbox specification, and later revisions use the existing sandbox
configuration API. RFC-0010 lifecycle hooks may observe readiness transitions via
`post_commit`; they do not override the composition rule.

The capability RPC reports driver identity, version, and the default sandbox
image used by the gateway. GPU availability stays driver-local and is validated
when a sandbox create request asks for GPU resources.

The gateway records driver identity and version from the startup capability
response. Elevated gateway info reports that initialized driver snapshot instead
of re-querying drivers on each request.

## Compiled Driver Selection

The gateway binary explicitly installs the compute drivers compiled into that
binary before entering server startup. The server selects a configured driver
by normalized registry name. When no driver is configured, it evaluates only
the installed drivers' probes and chooses the lowest registered priority.
Drivers without a probe, including VM, remain opt-in.

Startup computes this selection once after merging configuration. The same
selection drives authentication defaults and runtime construction, so a probe
result cannot change which driver is constructed later in startup.

This follows the same composition model as SQLx's `Any` drivers: the binary
defines the available implementation set, while the runtime consumes a generic
registry. Adding or removing a compiled driver therefore changes registration
rather than the server's selection flow. Alternate gateway binaries can install
their own `ComputeDriverFactory` registrations and hand the completed registry
to `run_cli_with_compute_drivers`; factories receive merged driver config and
return either an in-process driver or a gateway-managed remote endpoint. The
server constructs the common runtime adapter and snapshots `GetCapabilities`
for either result. A configured UDS endpoint still takes precedence over a
compiled registration with the same name.

The `openshell-gateway` composition crate groups first-party registrations
behind the `in-tree-compute-drivers` feature. `openshell-server` has no compute
driver dependencies or backend-name dispatch. Protocol-only gateway builds
disable the composition feature and link no compute-driver crates. E2E lanes
compose that gateway with Docker, Podman, Kubernetes, and VM driver executables
over the public UDS gRPC contract so an in-tree driver cannot silently depend
on a server-only API.

## Stop and Start Lifecycle

The gateway persists lifecycle intent before mutating compute:

```text
Ready -> Stopping -> Stopped -> Starting -> Ready
```

A canonical main process that exits successfully follows `Ready -> Completed`.
A nonzero or signal-normalized result follows `Ready -> Error` with a
`MainProcessFailed` condition. Both retained results may be started explicitly,
which creates a fresh main-process instance. Drivers must not automatically
restart a completed or failed canonical process. Before an explicit restart,
the gateway disconnects the prior supervisor session and deletes its SSH
sessions so credentials cannot cross runtime generations.

`StopSandbox` and `StartSandbox` are idempotent driver operations. Stop
retains the driver resource and its persistent workspace boundary while making
exec, SSH, forwarding, and exposed services unavailable. Start reactivates the
same resource. The gateway requires a fresh supervisor session before a
starting sandbox returns to `Ready`; stale driver snapshots and supervisor
sessions cannot promote a `Stopped` row.

A driver stop operation does not complete while its backend still reports an
in-progress stop. This prevents an immediate start from racing the previous
run's delayed exit event and regressing the new run to `Error`.

Persisted `Stopping` and `Starting` rows are retried at startup. Stable
`Stopped` rows remain stopped. Docker and Podman retain the stopped container
and attached storage, Kubernetes retains the Sandbox CR and PVC while scaling
compute to zero, and VM retains its launch request and writable overlay beside
a stop marker. Delete remains a separate operation that removes these
resources.

On graceful gateway shutdown, persisted running intent for Docker, Podman, and
VM is stopped through the shared `StopSandbox` RPC before any gateway-managed
driver process exits. The gateway does not persist `Stopped` for this
infrastructure event. On startup, it reconciles the retained intent through the
shared idempotent `StartSandbox` RPC before watch processing begins. Explicitly
`Stopped` sandboxes are excluded from both sweeps. Kubernetes workloads are
cluster-owned and continue running without gateway shutdown or startup
lifecycle calls.

The driver reports this behavior through
`GetCapabilities.gateway_manages_lifecycle`. The same declaration works for
in-process and external drivers. Older drivers omit the field and retain the
conservative operator-managed behavior.

Drivers that can verify a platform-native sandbox credential advertise
`GetCapabilities.supports_sandbox_authentication`. On the path-scoped
`IssueSandboxToken` exchange, the gateway forwards the opaque bearer credential
to that selected driver through `AuthenticateSandbox`. The driver returns only
the authenticated sandbox ID. The gateway then verifies that its durable
sandbox record exists and mints the gateway JWT. The driver socket is therefore
a sandbox-identity trust boundary, but it does not grant user or administrator
authority.

## Deletion Lifecycle

Lifecycle requests use per-sandbox gates to serialize stop, start, and
delete attempts. A delete request
resolves the name once and remains bound to that stable ID. The only
combined lock order is lifecycle gate, then the gateway-wide state guard; external
driver calls run without the global guard.

Lifecycle gates are process-local and do not coordinate gateway replicas. They
serialize attempts rather than share results: if one attempt fails and recovery
restores a deletable state, a request waiting on the gate may retry the driver.
Persisted resource-version checks remain the cross-replica safety boundary.

Watcher events do not acquire lifecycle gates. Exact resource-version checks allow
them to interleave safely: status snapshots are no-ops for `Deleting` rows,
deleted events are idempotent, and snapshots for absent rows are ignored.

An accepted delete (`deleted = true`) is finalized by the watcher. If the
backend is already absent (`deleted = false`), the request removes gateway state
synchronously. Sandbox row removal remains bound to the stable ID and resource
version. Settings retain their existing best-effort name-based cleanup; SSH
sessions, indexes, and watch/log buses are cleaned after confirmed removal.
Owned-record cleanup discovers records before mutating them and uses bounded
set-based deletes so teardown cannot amplify one sandbox into an unbounded
sequence of individual persistence writes.

When a sandbox is instead discovered gone out-of-band — a watcher deletion
event, or the periodic prune sweep finding no matching driver resource, with
no explicit `DeleteSandbox` request involved at all — the gateway also
releases driver-owned resources (for example Podman's per-sandbox secrets and
workspace volume) by calling the driver's idempotent `DeleteSandbox`, not just
gateway state. Both paths skip that call when a request-side lifecycle
operation already holds the sandbox's gate, since that operation already owns
driver-side cleanup. The watch path defers the call itself to a background
task after a non-blocking gate check, so a slow driver call cannot stall the
sequential watch loop; the prune sweep calls the driver inline, since it
already makes a blocking `GetSandbox` call per sandbox as part of its normal
operation.

The request acquires both locks before starting owned work, so cancellation
while queued does not leave a delete armed. After that commitment point, the
owned task prevents cancellation from stranding a mutation. A gateway restart
does not start a persisted `Deleting` operation. If the backend completed the
delete, reconciliation removes the row; otherwise it can remain `Deleting`.

## Runtime Summary

| Runtime | Best fit | Sandbox boundary | Notes |
|---|---|---|---|
| Docker | Local development with Docker available. | Capability-free workload container. | Uses `network_mode=none`; a separate capability-free supervisor container mediates egress and access over a private daemon-local Unix socket volume. |
| Podman | Existing rootless driver. | Container. | Not converted by this isolation stack. |
| Kubernetes | Cluster deployment through Helm. | Capability-free sandbox Pod. | Uses empty-egress NetworkPolicy, paired-only supervisor ingress, and a separate capability-free supervisor Deployment over mutually authenticated TLS. It requires an enforcing CNI and trusted sandbox namespace. |
| VM | Experimental microVM isolation. | Per-sandbox libkrun or QEMU VM. | The NIC-less guest runs `openshell-sandbox` as PID 1; host `openshell-supervisor` owns gateway networking and reaches the guest over vsock. |
| Extension | Out-of-tree drivers operated alongside the gateway. | Whatever boundary the driver implements. | Selected by a custom `compute_drivers = ["<name>"]` entry with `[openshell.drivers.<name>].socket_path`, or at launch time by pairing `--drivers <name>` with `--compute-driver-socket=<path>`. A launch-time endpoint may use a canonical built-in name to preserve its driver-config key while replacing in-process construction. The gateway connects to an operator-provisioned UDS, snapshots `GetCapabilities`, and dispatches all sandbox lifecycle calls through `compute_driver.proto`. The driver process and socket lifecycle are operator-owned; the gateway does not spawn, supervise, or remove unmanaged extension drivers. The trust boundary is the socket's filesystem permissions: the operator must ensure only the gateway uid can read/write it. |

Per-sandbox CPU and memory values currently enter the driver layer through
template resource limits. Docker and Podman apply them as runtime limits.
Kubernetes mirrors each limit into the matching request. VM accepts the fields
but currently ignores them.

Reusable sandbox workload templates are resolved before the compute-driver
boundary. Drivers do not receive a separate template resource; the gateway
lowers the selected `SandboxWorkloadTemplate` into the existing sandbox spec
and validates that spec before calling `ValidateSandboxCreate` or
`CreateSandbox`. Template CPU and memory become the same typed resource limits
described above. Template GPU settings become `ResourceRequirements`, preserving
the driver's default GPU assignment when the count is omitted. Template
`driver_config` remains a driver-keyed envelope until the compute layer selects
the active driver block and forwards only that block to the driver.

Docker and Podman also accept per-sandbox driver-config mounts for existing
runtime-managed named volumes and tmpfs mounts. Podman additionally accepts
image mounts through its image-volume API. User-supplied bind and volume mounts
default to read-only. Direct host bind mounts, and Docker or Podman local-driver
bind-backed named volumes, are available only when explicitly enabled in the
active local driver table of `gateway.toml`. Host bind mounts are an unsafe
operator override because they place gateway-host filesystem state inside the
sandbox and can negate OpenShell workspace isolation and filesystem-policy
controls. Driver-owned supervisor, token, and TLS bind mounts stay reserved.

Network features follow the driver/substrate split. Drivers own only the outer
fence and protected channel. The sandbox owns seccomp notification, local DNS,
socket virtualization, process observation, and binary identity. The supervisor
owns DNS eligibility, policy authorization, destination filtering, upstream
dials, relay behavior, credential rewriting, and OCSF decisions. No supported
path requires nftables, a workload network namespace, proxy environment
variables, added capabilities, or an unconfined AppArmor profile.

The Kubernetes deployment packaging has two ownership boundaries. The gateway
chart owns the gateway workload, configuration, Services, PKI, and
cluster-scoped gateway resources. The workspace chart is installed into a
pre-provisioned sandbox namespace and owns only the sandbox ServiceAccount,
namespaced RBAC, and sandbox ingress NetworkPolicy. Its RoleBinding names the
gateway ServiceAccount and namespace explicitly, so the two releases have
disjoint lifecycle ownership. A shared-mode gateway can target one external
namespace, while operator mode maps workspace names to multiple
platform-provisioned namespaces.

Resource requirements enter the driver layer through `SandboxSpec.resource_requirements`. This includes a set of GPU requirements, where a user
can request a specific number of GPUs or the driver-specific default behaviour.
For all in-tree drivers, this is equivalent to selecting a single GPU.

VM runtime state paths are derived only from driver-validated sandbox IDs
matching `[A-Za-z0-9._-]{1,128}`. The gateway-owned VM driver socket uses a
private `run/` directory plus Unix peer UID/PID checks. Standalone
unauthenticated TCP mode is disabled unless explicitly enabled for local
development.

Runtime-specific implementation notes belong in the driver crate README:

- `crates/openshell-driver-docker/README.md`
- `crates/openshell-driver-podman/README.md`
- `crates/openshell-driver-kubernetes/README.md`
- `crates/openshell-driver-vm/README.md`

The VM guest bootstrap runs once as root to prepare mounts, loopback, and the
safe port-53 sysctl. It then drops to the resolved identity with empty
capability sets and executes `openshell-sandbox` as guest PID 1.

## Supervisor Delivery

Drivers deliver the two binaries to separate trust domains:

| Runtime | Delivery model |
|---|---|
| Docker | A digest-pinned daemon-local volume supplies `openshell-sandbox`; the companion image runs `openshell-supervisor`. |
| Podman | Existing driver behavior; not converted by this stack. |
| Kubernetes | A non-root init container stages `openshell-sandbox` into a memory volume; the separate Deployment image runs `openshell-supervisor`. |
| VM | `openshell-sandbox` is embedded in the guest rootfs; a separately digest-checked native `openshell-supervisor` runs on the host. |
| Extension | Defined by the out-of-tree driver. |

Driver-controlled sandbox bootstrap must override image or template values for
sandbox identity, command metadata, resolver configuration, and public trust
paths. Gateway endpoints, callback credentials, policy, and private TLS material
belong only to the supervisor placement.

## Process Identity

The gateway preserves whether each policy process field was omitted and passes
the admitted selectors to the driver. The driver resolves one exact UID, GID,
and supplementary-group set before creating the immutable workload:

- Docker pins the image ID, resolves policy selectors against the image's
  `/etc/passwd` and `/etc/group`, and validates its OCI working directory.
- Kubernetes uses platform-resolved numeric values, including OpenShift
  namespace ranges.
- VM uses the configured numeric guest identity.

UID/GID zero and `u32::MAX` are invalid. The sandbox and every child start with
the resolved identity and zero capability masks; neither process performs an
in-workload UID transition. Identity-changing policy updates require sandbox
recreation, while other policy updates remain live.

Docker uses an absolute OCI working directory as the workspace. Empty, root,
and explicit `/sandbox` values select `/sandbox`; other paths must already
exist without symlink or reserved-mount collisions and must be usable by the
resolved identity. Kubernetes and VM use `/sandbox`.

Kubernetes uses only the proxy-pod topology. The driver creates the empty-egress
workload fence before a suspended Sandbox CR, then provisions split immutable
bootstrap Secrets, the boundary Service, and the supervisor Deployment. A
non-root init container stages `openshell-sandbox` and one-use bootstrap files
into memory volumes. The workload Pod never mounts supervisor or gateway
credentials. The driver removes its scheduling gate only after the companions
exist; measured confirmation and supervisor-session registration gate public
readiness.

## Images

The gateway image and Helm chart are built from this repository. Sandbox images
are maintained separately in the OpenShell Community repository or supplied by
users.

Custom sandbox images must include the agent runtime and any system
dependencies, but they should not need to include the gateway. GPU-capable
images must include the user-space libraries required by the workload. The
runtime still owns GPU device injection. GPU requests are explicit, and can be
refined with a driver-native device identifier or requested count; the gateway
validates the request shape and each runtime enforces the GPU allocation modes it
supports.

## Deployment Shape

Kubernetes deployments use the Helm chart under `deploy/helm/openshell`. The
chart deploys the gateway and sandbox runtime integration. The default gateway
workload is a StatefulSet for SQLite-backed single-replica installs. External
database-backed installs can render a Deployment with `workload.kind=deployment`;
HA deployments must point `server.externalDbSecret` at an operator-managed
PostgreSQL database. Agent Sandbox CRDs and controller lifecycle remain
operator-owned; the chart can optionally preflight for a served supported API
but does not install the cluster-scoped dependency.
Standalone local deployments start the gateway with a selected runtime such as
Docker, Podman, or VM. The CLI can register multiple gateways and switch between
them without changing the sandbox architecture.

## Workspace Namespace Modes (Kubernetes)

The Kubernetes driver maps workspaces to namespaces through the `workspace_mode`
configuration field (`WorkspaceMode` in `crates/openshell-driver-kubernetes/src/config.rs`).
The mode controls namespace resolution, resource naming, sandbox CR watching, SA
token authentication, and RBAC requirements.

| Mode | Namespace resolution | Resource name | Namespace lifecycle |
|---|---|---|---|
| **Shared** (default) | Single static namespace from config | `{workspace}--{name}` | None |
| **Managed** | `openshell-{gateway_id}-{workspace}` | bare sandbox name | Driver creates and deletes |
| **Operator** | Workspace name maps 1:1 to a pre-provisioned namespace | bare sandbox name | External (platform team) |

**Shared** renders all sandboxes into one configured namespace. Resource names
embed the workspace prefix for collision avoidance. No namespace lifecycle
management. RBAC uses a namespace-scoped Role.

**Managed** auto-creates a K8s namespace per workspace on first sandbox create.
Each new namespace receives a ServiceAccount and the configured gateway-only
SSH ingress NetworkPolicy. Configured image-pull Secrets are copied from the
driver's source namespace on every sandbox create so registry credential
rotations propagate. The namespace also copies OpenShift SCC UID-range and
supplemental-group annotations from the gateway namespace when present. The
driver deletes the namespace during workspace deletion. The workspace remains
durably `Terminating` until the Kubernetes API accepts namespace cleanup, so a
transient failure can be retried. Namespace deletion uses the fetched UID as a
precondition to avoid deleting a replacement namespace. Requires a non-empty
`gateway_id` (validated as a
DNS-1123 label at startup) so the namespace prefix fits within the K8s 63-character
limit. RBAC promotes sandbox CRD permissions to a ClusterRole and adds namespace
`create`/`delete` and ServiceAccount `create`/`get` permissions.

Secret copies use server-side apply. Kubernetes authorizes an apply to an
existing Secret as `patch`, but also requires `create` authorization when the
target does not exist. RBAC cannot constrain `create` by `resourceNames`, so
managed mode grants cluster-wide Secret `create` while keeping source reads and
subsequent patches restricted to the explicitly configured TLS and image-pull
Secret names. The driver exercises `create` only in gateway-owned managed
namespaces. This depends on the managed-mode ownership invariant described
below; the gateway ServiceAccount must not be shared with unrelated workloads.

Operator mode does not create NetworkPolicies or copy image-pull Secrets.
Platform teams must apply the gateway ingress boundary and provision configured
image-pull Secrets in every operator-managed namespace.

**Operator** uses pre-provisioned namespaces discovered through two optional
sources: a K8s label selector (`operator_namespace_label`) and a drop-in
allowlist file (`operator_namespace_file`). Exactly one must be configured.
The compute driver and the gateway's ServiceAccount authenticator independently
watch that public config source; no in-process driver state crosses into the
server. Sandbox creation and token bootstrap fail closed if the workspace is
not in the current allowlist. Platform teams manage namespace lifecycle
externally. RBAC uses the same ClusterRole as managed mode but without namespace
`create`/`delete` or ServiceAccount permissions.

### Watching and Querying

Managed and operator modes set `is_multi_namespace() == true`, which switches
sandbox CR watchers from namespace-scoped `Api::namespaced` to cluster-wide
`Api::all_with`. In managed mode the driver scopes cluster-wide queries with a
`LABEL_GATEWAY_ID` label selector to support multiple gateways on the same
cluster. K8s Events are not watched in cluster-wide mode — the cluster-wide
watcher emits only sandbox CR changes, not platform events.

### SA Token Authentication

The Kubernetes driver's `AuthenticateSandbox` implementation applies its named
`[openshell.drivers.kubernetes]` configuration per mode:

- **Shared:** `Exact` — accepts only the single configured namespace.
- **Managed:** `Prefix` — accepts any namespace starting with `openshell-{gateway_id}-`.
- **Operator:** `Allowlist` — accepts namespaces present in the dynamic
  `BTreeSet` populated by the label/file watchers. Starts empty (fail-closed)
  until the first watcher update.

It validates the projected token with Kubernetes `TokenReview`, checks the live
pod UID, and verifies the pod's controlling Sandbox CR UID and sandbox ID before
returning the identity to the gateway. These checks rely on an ownership
invariant. In shared and managed modes, the Kubernetes driver and its trusted
Agent Sandbox controller exclusively administer the sandbox namespace, Sandbox
CRs, sandbox pods, and configured sandbox ServiceAccount. Other principals must
not create or mutate those resources or use that ServiceAccount. In operator
mode, the platform operator retains
namespace lifecycle ownership, but must preserve the same exclusive control of
Sandbox CRs and the pods and ServiceAccount used for sandbox token bootstrap.
An allowlisted namespace is therefore a trust grant, not a tenant isolation
boundary. Kubernetes owner references alone do not prove which controller
created a pod, so admitting principals that can fabricate that resource chain
would allow them to claim an existing sandbox identity.

### Credential Driver Integration

The Kubernetes Secrets credential driver (`openshell-driver-kubernetes-secrets`)
stores secrets in workspace-specific namespaces when `workspace_mode` is managed
or operator. In shared mode, all secrets render into the single configured
namespace.

When runtime infrastructure changes, validate the relevant sandbox e2e path and
update the matching driver README if a maintainer-facing constraint changes.
