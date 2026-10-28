# openshell-driver-kubernetes

Kubernetes-backed compute driver for OpenShell cluster deployments.

Caller driver config is disabled by default. External resource references need
administrator-controlled approval labels in every workspace mode, including
before restart and scheduling-gate release. GPU devices are temporarily exempt.
Image-pull Secrets are operator-selected gateway configuration rather than caller
attachments. Managed mode stages an immutable copy for each sandbox runtime
generation.
See [resource admission configuration](../../docs/how-it-works/gateways/configuration.mdx#external-resource-admission).

Caller PVC mounts cannot overlap the driver-managed `/.openshell` control tree
or `/run`, including nested `subPath` mounts. Resource approval labels do not
permit mounting over these paths. Use data paths such as `/data` or a directory
below `/sandbox`.

The driver uses the Kubernetes API to create, delete, fetch, and watch sandbox
custom resources. It runs in-process with the gateway server and supports three
workspace namespace modes via `workspace_mode`:

- **Shared** (default): All sandboxes render into a single static namespace.
  Resource names use `{workspace}--{name}` for collision avoidance.
- **Managed**: The driver auto-creates/deletes a K8s namespace per workspace
  (`openshell-{gateway_id}-{workspace_name}`) and creates a ServiceAccount in
  each. On OpenShift, it leaves SCC annotations to the namespace allocator and
  waits for the namespace's own MCS, UID-range, and supplemental-group
  annotations before provisioning sandbox resources. An existing namespace with
  a UID range but no MCS must be recreated so OpenShift can allocate a complete
  set of SCC annotations.
- **Operator**: Workspace names map 1:1 to pre-provisioned namespaces discovered
  through exactly one source: either a label selector
  (`operator_namespace_label`) or a drop-in allowlist file
  (`operator_namespace_file`). Sandbox creation fails closed if the workspace
  namespace is not in the current allowlist. With a label selector, workspace
  checks that run before the watcher's first namespace listing wait up to 10
  seconds for it and then return `Unavailable`, so a gateway restart does not
  reject labeled workspaces as unknown. Workspace deletion only removes
  gateway state; it never deletes or otherwise accesses the operator-managed
  Kubernetes namespace.

When the gateway configures `[openshell.gateway.otlp]`, Kubernetes
compute-driver spans export to the same OTLP/gRPC collector with the service
name `openshell-driver-kubernetes`. The driver preserves the gateway trace
context and uses the same compute-driver RPC span names in its in-process and
standalone forms. Standalone deployments set `--gateway-name` or
`OPENSHELL_GATEWAY_NAME` so exported spans carry the same
`openshell.gateway.name` resource attribute as gateway spans.

When it creates an Agent Sandbox resource, the driver serializes the active W3C
trace context into the controller-reserved `opentelemetry.io/trace-context`
annotation. An OTLP-enabled Agent Sandbox controller can therefore attach its
asynchronous reconciliation spans to the originating OpenShell create trace.

Workspace namespace modes assume exclusive control of the sandbox identity
resource chain. In shared and managed modes, only the driver and its trusted
Agent Sandbox controller may administer the sandbox namespace, Sandbox CRs,
sandbox pods, or configured sandbox ServiceAccount. In operator mode, the
platform operator owns namespace lifecycle but must prevent other principals
from creating or mutating Sandbox CRs, creating sandbox pods with fabricated
owner references, or using the configured sandbox ServiceAccount. Treat adding
a namespace to the operator allowlist as granting this trust; the allowlist is
not a tenant isolation boundary.

## Runtime Model

The gateway stores platform state and delegates sandbox workload creation to
this driver. Kubernetes owns scheduling and pod lifecycle. The workload Pod
stages the statically linked musl `openshell-sandbox` binary from
`sandbox_runtime_image`, while a directly managed Pod runs the dynamically
linked glibc `openshell-supervisor` from `supervisor_image`.

The sandbox owns the agent process, applies Landlock and child seccomp filters,
identifies the binary behind each network syscall, and relays mediated streams
to the supervisor. The supervisor authenticates to the gateway with a JWT,
loads policy and provider state, performs destination and L7 authorization, and
opens upstream connections. The workload receives no gateway credential,
provider identity socket, or corporate-proxy credential.

Both Pods run as the namespace-resolved non-root UID/GID with
`allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, and the runtime
default seccomp profile. The sandbox installs a nested seccomp user-notification
filter without requesting a capability in the Pod spec. Startup fails closed
when the runtime blocks the required seccomp or Landlock operations.

The supervisor Pod has a direct, non-controller owner reference to the Sandbox
resource. This links its garbage-collection lifecycle to the sandbox without
competing with the Agent Sandbox controller for workload-Pod ownership.

When the gateway exports OTLP traces, the driver sets
`OPENSHELL_OTLP_ENDPOINT` on the supervisor Pod to the gateway's endpoint and
`TRACEPARENT` to the trace context of the operation that created the Pod. The
supervisor exports its spans there and parents its startup span on that
context. The endpoint is not configurable in driver TOML.

The driver creates one namespace-wide `NetworkPolicy` before it releases any
workload Pod. It selects every OpenShell workload, denies all workload egress,
and permits OpenShell supervisor Pods to reach the sandbox TLS port. The
authenticated Sandbox Protocol binds each connection to the exact sandbox and
supervisor Pod identities. Supervisors have normal egress for gateway, DNS,
and policy-approved upstream connections unless an operator policy restricts
them. The cluster CNI must enforce ingress and egress `NetworkPolicy` for every
sandbox namespace. Kubernetes accepts policy objects without confirming
enforcement, so operators must verify CNI support before running sandboxes.

### Control connection direction

Every new runtime generation uses `runtime-initiated` control. The Sandbox
annotation `openshell.ai/sandbox-runtime-control-connection` records the mode,
bound to `openshell.ai/sandbox-runtime-control-generation`. A missing marker or
a different current runtime generation identifies a legacy,
`supervisor-initiated` generation, which keeps working until replaced. Stop/start
upgrades it automatically: with both old Pods removed, the driver adds the
supervisor Service and records the new mode and generation
before releasing the replacement workload. Gateway recovery that recreates both
Pods also upgrades the generation. Reconciliation never migrates a running
generation. An unknown annotation value fails closed; there is no rollout flag.

Only the dial direction differs. In both modes the sandbox runtime presents the
generation-pinned TLS server identity and serves gRPC, and the supervisor
verifies that identity, acts as the gRPC client, and sends the Sandbox Protocol
JWT. The per-sandbox Service `os-boundary-<id>` always selects the paired
workload Pod. A separate `os-supervisor-<id>` Service always selects the paired
supervisor Pod. New gateways create both Services, retaining the legacy
Service's UID, ClusterIP, and selector across restarts so an older gateway can
still replace the generation during a rolling upgrade.

For `runtime-initiated`:

- The bootstrap Secret gives the runtime the Service ClusterIP and port. The
  runtime retries with capped backoff until the supervisor listens, so neither
  Pod waits on the other during bootstrap. The Service sets
  `publishNotReadyAddresses` because the supervisor becomes Ready only after
  the runtime attaches through it. The workload still cannot reach the control
  port.
- A per-sandbox `NetworkPolicy` `os-control-<id>` selects only this sandbox's
  two Pods and admits one flow, from its workload Pod to its supervisor Pod on
  `boundary_port` over TCP, as workload egress and supervisor ingress.
  Supervisors may already be ingress-isolated by the managed SSH ingress policy;
  when that policy is disabled, this one isolates them. Exec, file sync, and
  logs need no other supervisor ingress because the supervisor opens those
  connections. The CNI must still allow kubelet readiness probes. The
  namespace-wide policies are unchanged.
- The policy's UID and resourceVersion are bound into the boundary resource
  claims and outer-fence evidence. Reconciliation suspends the workload if the
  policy disappears, diverges, or changes generation, or if the active control
  Service no longer selects the role the recorded mode requires.
- Both Services and the control policy are owned by the Sandbox resource and are
  deleted only with that sandbox.

Deploy a gateway, supervisor image, and sandbox runtime image that all support
`runtime-initiated` before using it. Older binaries reject the new descriptor
shapes and fail closed.

During a mixed-version rollout, an old gateway can restart a sandbox by
creating its own compatible supervisor/runtime pair through the legacy
Service. It preserves unknown annotations, so the mode marker is accepted only
for its recorded generation. Do not replace an individual generation's
supervisor or runtime binary with one that cannot read its descriptor.

Each sandbox generation uses two immutable bootstrap Secrets. A trusted init
container stages the sandbox bootstrap into memory, and the sandbox removes it
before starting untrusted code. The other Secret is mounted only by the
supervisor; when `proxy_ca_bundle` is configured it also carries the operator's
corporate proxy CA bundle, which the gateway reads from its own filesystem so
the anchor stays in the gateway's trust domain rather than the sandbox
namespace. The TLS channel binds the namespace, Sandbox CR, workload Pod,
supervisor Pod, and shared network-policy identities, plus the per-sandbox
control policy for `runtime-initiated` sandboxes. Stop deletes the workload
and supervisor Pods. Start rotates both Secrets and creates a new supervisor
Pod before releasing a new workload Pod. It also renders the trusted init
container again from gateway config, so a sandbox created by an older gateway
starts with the current sandbox runtime image. The shared network fence
remains for the lifetime of the namespace.

Kubernetes policies are additive, and the API does not attest that the CNI
enforces them. Keep sandbox namespaces administrative: untrusted principals
must not create permissive policies, create Pods, read bootstrap Secrets, or
spoof the OpenShell role labels. Exact supervisor-to-sandbox authorization is
still enforced by TLS, JWT claims, session generation, and recorded Pod UIDs.

### Shared supervisor topology

With `supervisor_topology = "gateway"`, each new runtime
generation becomes a sandbox instance on one supervisor process that Helm
deploys in the gateway namespace, instead of a supervisor Pod and boundary
Service of its own. A sandbox instance is one running generation of a stable
Sandbox resource. The generation's placement is recorded on the Sandbox
resource (`openshell.ai/sandbox-runtime-supervisor-topology: gateway` and the
instance route in `openshell.ai/sandbox-runtime-supervisor-session`, whose key
keeps its established name) when the generation starts. Every later lifecycle decision reads the record, so changing the setting
never reinterprets a running generation, and an unknown or incomplete record
fails closed.

- **Ownership.** The gateway owns which instances the shared supervisor
  hosts. It constructs an `openshell_supervisor_control::SharedSupervision`
  when the gateway binary builds this driver with
  `KubernetesComputeDriver::with_shared_supervision`, serves its assignments
  to the supervisor over the private `openshell.supervisor.host.v1` stream,
  and mints the supervisor token the supervisor dials it with over TLS (see
  the `openshell-supervisor` README); that token authorizes only the
  assignment stream. The coordinator owns the control contracts (launch
  material is persisted before an instance is assigned, recovery is
  compare-and-replace against a baseline read before the list, an incomplete
  recovery never replaces the published set, host observations are
  interpreted once); this driver adapts them to Kubernetes objects. The
  standalone driver binary cannot host the topology and refuses a
  configuration that selects it.
- **Supervisor token delivery.** The gateway renews the token at half its
  lifetime (the `gateway_jwt` extension-token TTL, 15 minutes by default,
  bounded to one hour) and the coordinator retries a failed delivery until it
  succeeds or a newer token supersedes it. The driver's part is the write: it
  replaces the `token` key of the chart-created
  `shared_supervisor.token_secret_name` Secret in `service_namespace`, which
  the supervisor Pod mounts, and names a missing Secret or a denied patch in
  the retried error.
- **Create and start.** The driver creates a per-sandbox egress allowance
  `os-shared-control-<id>` from the workload Pod to the Pods the shared
  supervisor's Service selects, on the runtime port, binds its UID and
  resourceVersion into the boundary evidence, and builds the instance's
  registration (route, sandbox name, main process spec and agent image from
  the Sandbox resource, the provisioned runtime descriptor, the generation's
  launch credentials, its proxy CA, and the current trace context). The
  coordinator validates and encodes it, persists the launch material through
  the driver into the generation's `os-supervisor-<id>-<generation>` Secret (key
  `instance.json`, owned by the workload Pod), and then assigns the instance
  before the driver releases the workload Pod. Assignment does not wait for
  the supervisor, so create still returns before the gateway persists the
  generation. The runtime identity's last component is the instance route,
  which no Pod UID can equal, so `authenticate_sandbox` cannot vouch for a
  shared generation.
- **Readiness.** A shared generation is available while the coordinator
  reports its instance as supervised and accepted by the gateway and the
  driver finds its fence and egress allowance. An instance the supervisor has
  reconciled past and does not host, hosts for another sandbox, or reports as
  ended is unavailable, and reconciliation suspends the workload. A
  disconnected supervisor is unknown and a supervisor that has not yet
  reconciled to the assignment is degraded; neither suspends anything.
  Bootstrap completion waits on the same verdict within the bootstrap grace.
- **Stop and delete.** The driver withdraws the instance before suspending or
  deleting the workload, and the generation cleanup deletes its launch
  Secret. Every reconciliation also recovers the desired set from the Sandbox
  resources that may run: the driver begins the recovery before it lists
  them, lists the shared generations that may run with their routes, and
  reads each launch Secret's bytes on request; the coordinator reuses current
  assignments, decodes and binds persisted material to the recorded route and
  sandbox, keeps the previous set when any read fails, and refuses a list
  that raced a lifecycle edit. Instances of deleted Sandboxes and of stops
  made while the gateway was down are withdrawn, and a restarted gateway
  recovers its assignments before it sends anything.
- **Isolation.** The supervisor token is a profile of its own, separate from
  every instance's credentials; the gateway refuses it on every other RPC and
  refuses every other identity on the assignment stream, and ends a stream
  when the token that opened it expires. Sandboxes cannot reach the stream,
  and the routing preface only selects which generation-pinned TLS identity
  the supervisor demands.

The topology does not support upstream proxies or provider SPIFFE identity, and
the shared supervisor is a single point of failure for the sandboxes it hosts.
Shared sandbox instances export no supervisor OTLP traces or OCSF events; the driver
warns at startup when the gateway configures that export.
When the setting is removed, reconciliation suspends shared generations, and a
restart creates the dedicated generation's boundary Service the shared one never
had.

## Sandbox Resource

The driver works with the `agents.x-k8s.io` `Sandbox` custom resource. It
detects the served Sandbox API at runtime, caches the selected API version for
the gateway process, and uses `v1beta1` when available before falling back to
`v1alpha1`. Restart the gateway after an in-place Agent Sandbox upgrade so the
driver can detect served API versions again. Driver events map Kubernetes object
state and platform events into the shared compute-driver protobuf surface used
by the gateway.

Kubernetes API calls use explicit timeouts so gRPC handlers do not block
indefinitely when the API server is slow or unavailable. The request client's
timeout starts when each request is sent, so time a pooled connection spends
idle does not shorten it. Resource and Event
watches recover in place with API-friendly backoff after transient watcher
errors, avoiding a gateway-side watch restart and its associated watch gap.

## Workspace Persistence

Sandbox pods use a PVC-backed `/sandbox` workspace. An init container seeds the
PVC from the image's original `/sandbox` contents on first start and writes a
sentinel so subsequent starts skip the copy.

This is a stopgap persistence model. It preserves user files across pod
rescheduling but duplicates the base workspace and does not automatically apply
image updates to existing PVCs. Future snapshotting should replace it.

Stop preserves the Agent Sandbox resource and workspace PVC while stopping
its pod. The driver sets `spec.operatingMode: Suspended` for `v1beta1` or
`spec.replicas: 0` for `v1alpha1`. Start sets `Running` or one replica for the
same resource, so the replacement pod mounts the existing claim. Delete is the
only lifecycle operation that removes the Sandbox resource and its owned
storage. The driver confirms the stop from both the published `Suspended`
condition and deletion of the backing pod. Legacy `v1alpha1` controllers omit
a usable stopped condition, so pod deletion alone confirms their stop.

The workspace PVC size defaults to `workspace_default_storage_size`. Set
`workspace_storage_class` to pin the PVC to a specific `StorageClass`; an empty
value omits `storageClassName` so the cluster's default `StorageClass` applies.
Clusters with no default `StorageClass` must set this, otherwise the PVC stays
`Pending` and the sandbox never starts. Both fields can also be supplied at
runtime via `OPENSHELL_K8S_WORKSPACE_DEFAULT_STORAGE_SIZE` and
`OPENSHELL_K8S_WORKSPACE_STORAGE_CLASS`. Both apply only to the workspace PVC
that OpenShell provisions automatically; they have no effect when a `driver_config`
mount attaches an existing PVC under `/sandbox`, which skips the default PVC.

## Credentials, TLS, and Relay

Both Pods set `automountServiceAccountToken: false`. The supervisor receives an
explicit audience-bound projected token for the one-shot `IssueSandboxToken`
exchange. The driver verifies that token and returns an opaque runtime identity
derived from the namespace, immutable Sandbox resource UID, and supervisor Pod
UID. Restart requires exactly one matching Sandbox resource and preserves its
namespace and UID while rotating the supervisor Pod UID. The gateway requires
the authenticated identity to match the durable binding before returning the
generation-bound session JWT used by the supervisor. The sandbox Pod receives
neither token. For HTTPS gateway connections, the supervisor reads only the
CA from the configured TLS Secret. Shared mode projects `ca.crt` directly;
managed and operator modes stage only the CA into the supervisor bootstrap
Secret. User client certificates and private keys are not mounted into either Pod.

The gateway uses the supervisor relay for connect, exec, logs, and file sync.
Sandbox Pods do not need direct external ingress for SSH.

The driver sends the canonical main-process specification only to the
supervisor. The supervisor passes admitted launch state over the protected
channel. Provider environment updates apply to future exec sessions.

## Container Security Context

The sandbox, trusted bootstrap init container, and supervisor request no added
Linux capability. They run as the same numeric non-root identity, disable
privilege escalation, drop all capabilities, and inherit `RuntimeDefault`
seccomp. The sandbox and agent must use the same complete UID, GID, and
supplementary-group identity because the capability-free sandbox cannot change
credentials after launch and must inspect its same-identity descendants.

The workload Pod does not share host network, PID, IPC, or process namespaces.
The driver uses a scheduling gate to inspect the admitted Pod and bind its UID
into the bootstrap claims before kubelet starts it.

Lifecycle RPCs and runtime reconciliation share a per-sandbox mutation gate
across clones of the driver. Reconciliation skips busy sandboxes and refreshes
the Sandbox CR under that gate before cleanup, so a stopped or stopping LIST
snapshot cannot delete a supervisor created by a concurrent restart in the same
driver instance. The gate preserves concurrency across sandboxes; it does not
provide distributed exclusion between separate gateway or driver processes.

## GPU Support

When a sandbox requests GPU support, the driver checks node allocatable capacity
for `nvidia.com/gpu` and requests the configured GPU count in the workload spec.
When no count is set, the driver requests one GPU resource. The sandbox image
must provide the user-space libraries needed by the agent workload.

## Driver Config

Following RFC 0006, this driver accepts the selected
`SandboxTemplate.driver_config.kubernetes` block as
`DriverSandboxTemplate.driver_config`. The Kubernetes driver owns the
nested schema and currently accepts:

- `pod.node_selector`
- `pod.tolerations`
- `pod.runtime_class_name`
- `pod.priority_class_name`
- `containers.agent.resources.requests`
- `containers.agent.resources.limits`
- `containers.agent.volume_mounts[].name`
- `containers.agent.volume_mounts[].mount_path`
- `containers.agent.volume_mounts[].sub_path`
- `containers.agent.volume_mounts[].read_only`
- `volumes[].name`
- `volumes[].persistent_volume_claim.claim_name`
- `volumes[].persistent_volume_claim.read_only`

Nested keys inside the `kubernetes` block use snake_case. The top-level
`driver_config` envelope is keyed by driver names, so `kubernetes` is not part
of the nested schema.

Set this through the CLI with the public driver-keyed envelope. The gateway
forwards only the `kubernetes` object to this driver:

```shell
openshell sandbox create \
  --driver-config-json '{"kubernetes":{"pod":{"runtime_class_name":"kata-containers","node_selector":{"pool":"gpu"}}}}' \
  -- claude
```

Resource keys use native Kubernetes resource names and quantity strings. The
parser renders the keys listed above and rejects unknown fields.
`pod.runtime_class_name` maps to PodSpec `runtimeClassName` and overrides the
driver's configured `default_runtime_class_name`; the typed public
`SandboxTemplate.runtime_class_name` still takes precedence when set. Use the
public `--gpu` flag for the default GPU request, pass a count to `--gpu` for
counted GPU requests, and use `driver_config` only for additional driver-owned
resource details.

Use PVC volumes to mount existing Kubernetes PersistentVolumeClaims into the
agent container. PVC volumes and mounts default to read-only unless
`read_only: false` is set explicitly. Read-write access requires
`read_only: false` on both the PVC volume and each writable mount. The driver
rejects duplicate volume names, invalid DNS-1123 volume labels or PVC claim
subdomain names, mounts that reference unknown volumes, non-normalized or
protected mount paths, and absolute or parent-traversing `sub_path` values.

Any explicit driver-config mount under `/sandbox` disables the driver's
default `/sandbox` workspace PVC injection for that sandbox. Only the explicit
mount paths persist through the external PVC; other `/sandbox` paths come from
the current sandbox image.

```shell
openshell sandbox create \
  --driver-config-json '{
    "kubernetes": {
      "volumes": [{
        "name": "user-data",
        "persistent_volume_claim": {
          "claim_name": "pvc-user-data-123",
          "read_only": false
        }
      }],
      "containers": {
        "agent": {
          "volume_mounts": [
            {
              "name": "user-data",
              "mount_path": "/sandbox/.openshell/workspace",
              "sub_path": "workspace",
              "read_only": false
            },
            {
              "name": "user-data",
              "mount_path": "/sandbox/.openshell/memory",
              "sub_path": "memory",
              "read_only": false
            }
          ]
        }
      }
    }
  }' \
  -- claude
```
