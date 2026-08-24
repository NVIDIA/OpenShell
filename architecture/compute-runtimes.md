# Compute Runtimes

Compute runtimes create, stop, start, delete, and watch sandbox workloads for the
gateway. They do not replace sandbox policy enforcement. Every runtime starts a
workload that runs the `openshell-sandbox` supervisor, and the supervisor
enforces the sandbox contract locally.

## Driver Contract

Each runtime receives a sandbox spec from the gateway and is responsible for:

- Selecting the sandbox image.
- Injecting sandbox identity and gateway callback configuration.
- Supplying TLS or secret material for supervisor callbacks.
- Providing the supervisor binary or image in the workload.
- Forwarding the exact canonical main-process argv and TTY mode without shell
  reconstruction. The sandbox-level environment and policy workspace apply to
  the main process.
- Reporting lifecycle and platform events back to the gateway.
- Cleaning up runtime-owned resources.

Drivers report **backend state only**. A driver snapshot with `Ready=True` means
the underlying compute resource (container, pod, VM) is healthy and running —
nothing more. Drivers must not gate on supervisor session state or hold
references to gateway-internal types. The gateway owns the public
`SandboxPhase::Ready` decision. This applies equally to extension drivers
implementing `ComputeDriver` out of tree.

`compute_driver.proto` is the supported gateway/driver extension boundary.
At initialization the gateway snapshots the driver's identity, version,
default image, and gateway-lifecycle preference from `GetCapabilities`.
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

The gateway composes driver backend state with supervisor session presence to
produce the public `SandboxPhase`. This composition is gateway-owned and applied
uniformly across all drivers:

```
backend_phase = derive_phase(driver_status)

public_phase =
  if backend_phase in {Error, Deleting}:                     → pass through (terminal precedence)
  if backend_phase == Ready && session connected:             → Ready
  if backend_phase == Ready && no session:                    → Provisioning
  if backend_phase in {Provisioning, Unknown} && session:    → Ready
  if backend_phase in {Provisioning, Unknown} && no session: → Provisioning
```

When `public_phase == Ready` the sandbox is usable through the gateway — both the
backend resource is healthy and a supervisor session is registered. A sandbox whose
backend reports ready but has no supervisor session yet holds `Provisioning` with a
`Ready=False`, `SupervisorNotConnected` condition and the message
`Backend ready; waiting for supervisor session`. This distinguishes it from a sandbox
whose compute resource is still provisioning without exposing contradictory public
readiness signals.

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

**Extension point:** The readiness decision is a safety invariant, not an
operator-configurable hook. The driver contract is the correct extension point for
custom backend readiness semantics. RFC-0010 lifecycle hooks may observe readiness
transitions via `post_commit`; they do not override the composition rule.

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
the installed drivers' probes in registered priority order, records every
available registration, and selects the first. Drivers without a probe,
including VM, remain opt-in.

Startup computes this selection once after merging configuration. The same
selection drives authentication defaults and runtime construction, so a probe
result cannot change which driver is constructed later in startup.

This follows the same composition model as SQLx's `Any` drivers: the binary
defines the available implementation set, while the runtime consumes a generic
registry. Adding or removing a compiled driver therefore changes registration
rather than the server's selection flow. Alternate gateway binaries can install
their own `ComputeDriverFactory` registrations and hand the completed registry
to `run_cli_with_compute_drivers`; factories receive merged driver config and
finish through the same in-process runtime adapter. A configured UDS endpoint
still takes precedence over a compiled registration with the same name.

The standard server crate groups first-party registrations behind the
`in-tree-compute-drivers` feature. Protocol-only gateway builds disable that
feature and link no compute-driver crates. E2E lanes compose that gateway with
Docker, Podman, Kubernetes, and VM driver executables over the public UDS gRPC
contract so an in-tree driver cannot silently depend on a server-only API.
External Kubernetes drivers support shared and managed workspace modes.
Operator mode requires an in-process dynamic namespace allowlist and is
rejected when Kubernetes is configured through an external endpoint.

## Stop and Start Lifecycle

The gateway persists lifecycle intent before mutating compute:

```text
Ready -> Stopping -> Stopped -> Starting -> Ready
```

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

The request acquires both locks before starting owned work, so cancellation
while queued does not leave a delete armed. After that commitment point, the
owned task prevents cancellation from stranding a mutation. A gateway restart
does not start a persisted `Deleting` operation. If the backend completed the
delete, reconciliation removes the row; otherwise it can remain `Deleting`.

## Runtime Summary

| Runtime | Best fit | Sandbox boundary | Notes |
|---|---|---|---|
| Docker | Local development with Docker available. | Container plus nested sandbox namespace. | Uses host networking so loopback gateway endpoints work from the supervisor. Advertises the combined-supervisor policy-DNS and transparent-TCP substrate. |
| Podman | Rootless or single-machine deployments. | Container plus nested sandbox namespace. | Uses the Podman REST API and CDI GPU devices when available. Delivers the supervisor via OCI image volume by default; falls back to extracting the binary to a host-side cache and bind-mounting it when `userns` is configured (overlay does not support idmapped mounts). Advertises the combined-supervisor policy-DNS and transparent-TCP substrate. |
| Kubernetes | Cluster deployment through Helm. | Pod plus nested sandbox namespace. | Uses Kubernetes API objects, service accounts, secrets, PVC-backed workspace storage, and GPU resources. |
| VM | Experimental microVM isolation. | Per-sandbox libkrun VM. | Managed endpoint-backed driver. The gateway spawns `openshell-driver-vm`, waits for its Unix socket, and then consumes it through the same remote `compute_driver.proto` path used by unmanaged endpoint drivers. The VM driver boots a cached bootstrap `rootfs.ext4`, prepares requested OCI images inside a bootstrap VM with `umoci`, attaches the prepared image disk read-only, and gives each sandbox a writable `overlay.ext4` for merged-root changes and runtime material. The driver persists each accepted launch request beside the overlay and restarts those VMs on driver startup without recreating the overlay. |
| Extension | Out-of-tree drivers operated alongside the gateway. | Whatever boundary the driver implements. | Selected by a custom `compute_drivers = ["<name>"]` entry with `[openshell.drivers.<name>].socket_path`, or at launch time by pairing `--drivers <name>` with `--compute-driver-socket=<path>`. A launch-time endpoint may use a canonical built-in name to preserve its driver-config key while replacing in-process construction. The gateway connects to an operator-provisioned UDS, snapshots `GetCapabilities`, and dispatches all sandbox lifecycle calls through `compute_driver.proto`. The driver process and socket lifecycle are operator-owned; the gateway does not spawn, supervise, or remove unmanaged extension drivers. The trust boundary is the socket's filesystem permissions: the operator must ensure only the gateway uid can read/write it. |

Per-sandbox CPU and memory values currently enter the driver layer through
template resource limits. Docker and Podman apply them as runtime limits.
Kubernetes mirrors each limit into the matching request. VM accepts the fields
but currently ignores them.

Docker and Podman also accept per-sandbox driver-config mounts for existing
runtime-managed named volumes and tmpfs mounts. Podman additionally accepts
image mounts through its image-volume API. User-supplied bind and volume mounts
default to read-only. Direct host bind mounts, and Docker or Podman local-driver
bind-backed named volumes, are available only when explicitly enabled in the
active local driver table of `gateway.toml`. Host bind mounts are an unsafe
operator override because they place gateway-host filesystem state inside the
sandbox and can negate OpenShell workspace isolation and filesystem-policy
controls. Driver-owned supervisor, token, and TLS bind mounts stay reserved.

Network features follow the existing driver/substrate split. Compute drivers
advertise only the runtime mechanics they can guarantee: namespace and
capability ownership, DNS/TCP capture installation, and coupled
restart ordering. The shared supervisor remains the sole owner of DNS
eligibility, synthetic mappings, process authorization, destination filtering,
pinned dialing, relay behavior, and OCSF decisions. Docker and Podman advertise
`policy-dns-transparent-tcp`; other runtimes reject explicit TCP policy until
they implement and validate the same complete contract. The capability marker
is driver-owned supervisor input and is removed from workload environments.

Kubernetes deployments may set an AppArmor profile on sandbox agent containers
through the driver configuration. The Helm chart defaults sandbox agents to
`Unconfined` so runtime/default AppArmor profiles do not block supervisor
network namespace setup on AppArmor-enabled nodes.

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

The combined VM topology runs `openshell-sandbox` as guest PID 1. libkrun
executes the driver-owned guest bootstrap as PID 1, and the bootstrap preserves
that identity when it execs the supervisor after mounting and network setup.

## Supervisor Delivery

The supervisor must be available inside each sandbox workload:

| Runtime | Delivery model |
|---|---|
| Docker | Bind-mounted local supervisor binary, or a binary extracted from the configured supervisor image. |
| Podman | Read-only OCI image volume by default; host-cached bind mount when `userns` is configured. |
| Kubernetes | Supervisor image side-loaded into the sandbox pod by image volume or init container. |
| VM | Embedded in the guest rootfs bundle. |
| Extension | Defined by the out-of-tree driver. |

Driver-controlled environment variables must override sandbox image or template
values for sandbox ID, sandbox name, gateway endpoint, relay socket path, TLS
paths, and command metadata.

## Process Identity

The gateway preserves whether each policy process field was omitted. The active
driver then supplies one authoritative identity input to the supervisor:

- Docker and Podman inspect the final sandbox image, pin container creation to
  its immutable image ID, and pass its raw OCI `Config.User`. Docker also
  resolves the workspace from OCI `Config.WorkingDir` during that inspection.
- Kubernetes passes its platform-resolved numeric UID/GID, including OpenShift
  SCC-derived values.
- VM keeps its existing guest identity behavior.

Explicit numeric workload identities may use any Linux UID/GID from `1`
through `u32::MAX - 1`. UID/GID `0` remains prohibited as root, and
`u32::MAX` remains prohibited because Linux APIs and POSIX ACLs use it as an
invalid identity sentinel. Infrastructure identities use separate validation:
the Kubernetes network proxy UID remains at least `1000` and must not match the
workload UID because its traffic bypasses the pod egress fence.

For Docker and Podman, policy values take precedence independently. An omitted
`run_as_user` or `run_as_group` falls back to the corresponding identity from
the image. The supervisor resolves names from the image's `/etc/passwd` and
`/etc/group` before readiness, preserves declared name or numeric components,
and uses the same privilege-drop path for direct and SSH children. When a
declaration omits the group, the supervisor fills it with the user's numeric
primary GID. It does not rewrite the account files.

Docker uses an absolute OCI working directory as the workspace. An
empty, root (`/`), or explicit `/sandbox` declaration uses `/sandbox`, which
OpenShell creates and owns as a compatibility workspace. Any other workdir must already
exist in the immutable image without symlink components. The completed
identity, including supplementary groups, must already be able to traverse
every parent and write and enter the workdir; OpenShell does not change that
directory's ownership or mode. A one-shot validator drops to that identity and
uses kernel effective-access checks so POSIX ACL and LSM decisions are honored.
Path checks reserve the standard OCI runtime namespaces under `/proc`, `/sys`,
and `/dev`, while separate collision checks are derived from actual OpenShell
control paths.
Docker performs the check in the final container before workload launch and
rejects image `VOLUME` declarations that would mask the workdir ancestry. The
resolved workspace is the child cwd and `HOME`; when
`filesystem.include_workdir` is enabled, it becomes the automatic writable
policy path. Podman, Kubernetes/OpenShift, and VM retain their existing
`/sandbox` workspace behavior.

Sandbox creation fails before the workload becomes ready when a required image
identity is absent, malformed, unknown, ambiguous, or resolves to UID/GID 0.
The supervisor itself remains root so it can establish isolation before
starting unprivileged children.

Kubernetes can run the supervisor in the default combined topology or in a
sidecar topology. Combined mode keeps network and process supervision in the
agent container. Sidecar mode runs network enforcement, the proxy, and gateway
session in a dedicated sidecar, while the agent container runs only the
process-supervision leaf and launches the user workload after the sidecar
serves bootstrap state over a local control socket. The network sidecar owns
gateway credentials and sends policy plus workload-facing provider environment
state to the process leaf over that socket. It also streams provider
environment updates after settings polls so future process sessions see
updated provider env without giving the process leaf gateway access. The
pre-workload process supervisor is the only accepted control client: the
network sidecar verifies its UID, GID, and PID with peer credentials, removes
the listener after accepting it, and ignores workload-supplied relay targets.
SSH relays use a Linux abstract socket and verify its peer PID against that
authenticated process-supervisor connection, so workload filesystem access
cannot replace the relay endpoint. Either supervisor exits when this control
connection closes. This couples their restart lifecycle and prevents a workload
that survives an isolated network-sidecar restart from becoming the next
authoritative control client. In sidecar mode, an init container performs the
privileged pod-network nftables setup with
`NET_ADMIN`. The default binary-aware network sidecar runs as UID 0 without
`NET_ADMIN` and adds `SYS_PTRACE` plus `DAC_READ_SEARCH` so it can resolve
cross-UID workload process/binary identity through shared `/proc`. Operators
can set the sidecar `process_binary_aware_network_policy` flag false to run the
sidecar as the configured non-root proxy UID, omit both inspection capabilities,
and downgrade network policy to endpoint/L7 matching without `policy.binaries`.
The init path applies nftables as individual commands so optional conntrack and
log expressions can fail without rolling back the required table, chain, and
reject rules.
The agent container runs as the resolved sandbox UID/GID with no added Linux
capabilities. Sidecar mode preserves gateway session and SSH behavior, but
treats the process leaf as network-only: Landlock filesystem policy and child
seccomp still apply where supported, while process privilege dropping and
supervisor identity mount isolation do not run because the agent container is
already unprivileged. Sidecar pods use a shared process namespace so the
network sidecar can resolve workload process and binary identity through
`/proc/<entrypoint-pid>`.

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
allowlist file (`operator_namespace_file`). At least one must be configured.
The `OperatorNamespaceAllowlist` (`Arc<RwLock<BTreeSet<String>>>`) is populated
at runtime by background watchers and read by the namespace resolver. Sandbox
creation fails closed if the workspace is not in the current allowlist. Platform
teams manage namespace lifecycle externally. RBAC uses the same ClusterRole as
managed mode but without namespace `create`/`delete` or ServiceAccount
permissions.

### Watching and Querying

Managed and operator modes set `is_multi_namespace() == true`, which switches
sandbox CR watchers from namespace-scoped `Api::namespaced` to cluster-wide
`Api::all_with`. In managed mode the driver scopes cluster-wide queries with a
`LABEL_GATEWAY_ID` label selector to support multiple gateways on the same
cluster. K8s Events are not watched in cluster-wide mode — the cluster-wide
watcher emits only sandbox CR changes, not platform events.

### SA Token Authentication

The gateway's `K8sServiceAccountAuthenticator` adapts its `NamespaceValidator`
per mode (`crates/openshell-server/src/auth/k8s_sa.rs`):

- **Shared:** `Exact` — accepts only the single configured namespace.
- **Managed:** `Prefix` — accepts any namespace starting with `openshell-{gateway_id}-`.
- **Operator:** `Allowlist` — accepts namespaces present in the dynamic
  `BTreeSet` populated by the label/file watchers. Starts empty (fail-closed)
  until the first watcher update.

These checks rely on an ownership invariant. In shared and managed modes, the
gateway and its trusted Agent Sandbox controller exclusively administer the
sandbox namespace, Sandbox CRs, sandbox pods, and configured sandbox
ServiceAccount. Other principals must not create or mutate those resources or
use that ServiceAccount. In operator mode, the platform operator retains
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
