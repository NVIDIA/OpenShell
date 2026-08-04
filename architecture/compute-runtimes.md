# Compute Runtimes

Compute runtimes create, stop, delete, and watch sandbox workloads for the
gateway. They do not replace sandbox policy enforcement. Every runtime starts a
workload that runs the `openshell-sandbox` supervisor, and the supervisor
enforces the sandbox contract locally.

## Driver Contract

Each runtime receives a sandbox spec from the gateway and is responsible for:

- Selecting the sandbox image.
- Injecting sandbox identity and gateway callback configuration.
- Supplying TLS or secret material for supervisor callbacks.
- Providing the supervisor binary or image in the workload.
- Reporting lifecycle and platform events back to the gateway.
- Cleaning up runtime-owned resources.

Drivers report **backend state only**. A driver snapshot with `Ready=True` means
the underlying compute resource (container, pod, VM) is healthy and running —
nothing more. Drivers must not gate on supervisor session state or hold
references to gateway-internal types. The gateway owns the public
`SandboxPhase::Ready` decision. This applies equally to extension drivers
implementing `ComputeDriver` out of tree.

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

## Deletion Lifecycle

Delete requests use per-sandbox gates to serialize delete attempts. A request
resolves the name once and remains bound to that stable ID. The only
combined lock order is delete gate, then the gateway-wide state guard; external
driver calls run without the global guard.

Delete gates are process-local and do not coordinate gateway replicas. They
serialize attempts rather than share results: if one attempt fails and recovery
restores a deletable state, a request waiting on the gate may retry the driver.
Persisted resource-version checks remain the cross-replica safety boundary.

Watcher events do not acquire delete gates. Exact resource-version checks allow
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
does not resume a persisted `Deleting` operation. If the backend completed the
delete, reconciliation removes the row; otherwise it can remain `Deleting`.

## Runtime Summary

| Runtime | Best fit | Sandbox boundary | Notes |
|---|---|---|---|
| Docker | Local development with Docker available. | Container plus nested sandbox namespace. | Uses host networking so loopback gateway endpoints work from the supervisor. |
| Podman | Rootless or single-machine deployments. | Container plus nested sandbox namespace. | Uses the Podman REST API, OCI image volumes, and CDI GPU devices when available. |
| Kubernetes | Cluster deployment through Helm. | Pod plus nested sandbox namespace. | Uses Kubernetes API objects, service accounts, secrets, PVC-backed workspace storage, and GPU resources. |
| VM | Experimental microVM isolation. | Per-sandbox libkrun VM. | Managed endpoint-backed driver. The gateway spawns `openshell-driver-vm`, waits for its Unix socket, and then consumes it through the same remote `compute_driver.proto` path used by unmanaged endpoint drivers. The VM driver boots a cached bootstrap `rootfs.ext4`, prepares requested OCI images inside a bootstrap VM with `umoci`, attaches the prepared image disk read-only, and gives each sandbox a writable `overlay.ext4` for merged-root changes and runtime material. The driver persists each accepted launch request beside the overlay and restarts those VMs on driver startup without recreating the overlay. |
| Extension | Out-of-tree drivers operated alongside the gateway. | Whatever boundary the driver implements. | Selected by a non-reserved custom `compute_drivers = ["<name>"]` entry with `[openshell.drivers.<name>].socket_path`, or at launch time by pairing `--drivers <name>` with `--compute-driver-socket=<path>`. Reserved built-in names such as `vm`, `docker`, `podman`, and `kubernetes` cannot be used as unmanaged socket endpoints. The gateway connects to a UDS the operator already provisioned, runs `GetCapabilities`, logs the advertised `driver_name`, and dispatches all sandbox lifecycle calls through `compute_driver.proto`. The driver process and socket lifecycle are operator-owned; the gateway does not spawn, supervise, or remove unmanaged extension drivers. The trust boundary is the socket's filesystem permissions: the operator must ensure only the gateway uid can read/write it. |

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
| Podman | Read-only OCI image volume containing the supervisor binary. |
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
  its immutable image ID, and pass its raw OCI `Config.User`.
- Kubernetes passes its platform-resolved numeric UID/GID, including OpenShift
  SCC-derived values.
- VM keeps its existing guest identity behavior.

For Docker and Podman, policy values take precedence independently. An omitted
`run_as_user` or `run_as_group` falls back to the corresponding identity from
the image. The supervisor resolves names from the image's `/etc/passwd` and
`/etc/group` before readiness, preserves declared name or numeric components,
and uses the same privilege-drop path for direct and SSH children. When a
declaration omits the group, the supervisor fills it with the user's numeric
primary GID. It does not rewrite the account files.

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

The cni-sidecar topology keeps the sidecar runtime model and its shared-state
boundary, but removes the privileged `openshell-network-init` init container and
its `NET_ADMIN`. Instead, the privileged OpenShell CNI DaemonSet installs the
pod-network bypass-prevention rules during CNI `ADD` using nftables or iptables.
The driver annotates sandbox pods so the chained CNI plugin can read the proxy
UID and enforcement mode. The network sidecar keeps the same privilege profile
as the other sidecar topologies: in the default binary-aware mode it runs as UID
0 with `SYS_PTRACE` and `DAC_READ_SEARCH` (but no `NET_ADMIN`) to resolve
cross-UID `/proc`, and only stays non-root with no added capabilities when
`process_binary_aware_network_policy` is disabled. The agent container stays
non-root with no added Linux capabilities in either mode. Because the node CNI —
not an in-pod container — programs the firewall, no container in the sandbox pod
holds `NET_ADMIN`.

The CNI installer supports two modes. `conflist` (default) appends the
`openshell-cni` plugin to an existing CNI `.conflist` (k3s / vanilla). On
OpenShift (Multus / OVN-Kubernetes) there is no appendable `.conflist`, so
`multus-chain` writes a standalone plugin `.conf` into the Multus
`vendor-cni-chain` auxiliary-chain directory and stores plugin credentials in a
persistent `stateDir`. Neither mode modifies a CNO-managed file.

The installer patches the chained plugin at startup and then re-verifies it on a
reconcile tick, re-patching when the plugin is missing. This keeps enforcement in
place across CNI config rewrites (for example a CNO reconcile) and DaemonSet
restarts, bounding any such gap to one reconcile interval. The chained plugin
lives in the host CNI config and survives installer pod restarts, so an ordinary
DaemonSet restart or rolling update never strips enforcement: the `preStop` hook
removes it only when the owning DaemonSet is actually being deleted (helm
uninstall), and fences the node before doing so.

A per-node scheduling gate closes the cold-start race. Once the chained plugin is
installed, the installer labels its node `openshell.ai/cni-ready=true`. Each
reconcile tick fences before it repairs: the instant enforcement is not
verifiably in place it clears the label, attempts repair, and only re-marks the
node ready once the plugin is healthy again. The gateway sets a required
`nodeAffinity` on that label for every cni-sidecar sandbox pod, so a pod cannot
schedule onto a node before that node's egress enforcement is active, and a node
whose enforcement later breaks stops accepting new sandbox pods. The label is set
through a minimal cluster-scoped grant (`nodes` `get`/`patch`, plus `get` on the
installer's own DaemonSet) bound to the dedicated CNI ServiceAccount. One residual
limitation: an ungraceful DaemonSet pod deletion (no `preStop`) leaves a stale
`cni-ready=true` until the pod is rescheduled and the next reconcile tick
re-evaluates it.

The CNI installer is a **cluster singleton**. The chained plugin enforces any pod
carrying the OpenShell annotations (`openshell.ai/cni=enabled` plus the proxy-UID
and enforcement-mode annotations, set only by a gateway on its own sandbox pods),
so a single installation serves every OpenShell release across all namespaces —
enforcement is gated by per-pod annotations, not a namespace list. The installer
resources use release-independent names, the plugin config carries a fixed
`openshell` owner and an empty namespace allowlist, and a `configVersion` binds
readiness to the desired config so a stale-version entry is repaired before the
node is re-marked ready. Install the singleton (`cni.enabled=true`) in one release
per cluster; additional gateway releases set `cni.enabled=false` +
`cni.external=true` to share it, and the installer refuses to overwrite a chained
plugin entry with a non-OpenShell owner. Because the plugin serves all sandbox
namespaces, its `pods get` grant is cluster-scoped.

On OpenShift, binary-aware network policy also requires a purpose-built
SecurityContextConstraints for sandbox pods: the network sidecar runs as UID 0
with `SYS_PTRACE` and `DAC_READ_SEARCH` to inspect cross-UID `/proc`, which
`restricted-v2` forbids. `sandboxServiceAccount.openshift.binaryAwareSCC` creates
a minimal SCC (the `restricted-v2` baseline plus only those two capabilities, UID
0, and the `image` volume type) and binds it to the sandbox ServiceAccount.
Disabling `processBinaryAwareNetworkPolicy` drops the capability requirement and
lets the stock `restricted-v2` SCC apply.

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
PostgreSQL database.
Standalone local deployments start the gateway with a selected runtime such as
Docker, Podman, or VM. The CLI can register multiple gateways and switch between
them without changing the sandbox architecture.

When runtime infrastructure changes, validate the relevant sandbox e2e path and
update the matching driver README if a maintainer-facing constraint changes.
