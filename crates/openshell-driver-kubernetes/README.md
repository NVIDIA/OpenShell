# openshell-driver-kubernetes

Kubernetes-backed compute driver for OpenShell cluster deployments.

The driver uses the Kubernetes API to create, delete, fetch, and watch sandbox
custom resources. It runs in-process with the gateway server and supports three
workspace namespace modes via `workspace_mode`:

- **Shared** (default): All sandboxes render into a single static namespace.
  Resource names use `{workspace}--{name}` for collision avoidance.
- **Managed**: The driver auto-creates/deletes a K8s namespace per workspace
  (`openshell-{gateway_id}-{workspace_name}`), creates a ServiceAccount in each,
  and copies OpenShift SCC annotations from the gateway namespace when present.
- **Operator**: Workspace names map 1:1 to pre-provisioned namespaces discovered
  through exactly one source: either a label selector
  (`operator_namespace_label`) or a drop-in allowlist file
  (`operator_namespace_file`). Sandbox creation fails closed if the workspace
  namespace is not in the current allowlist. Workspace deletion only removes
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
this driver. Kubernetes owns scheduling and pod lifecycle. The driver always
uses the proxy-pod topology. The workload Pod runs `openshell-sandbox`, while a
separate Deployment runs `openshell-supervisor`.

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

The driver creates an empty-egress `NetworkPolicy` before it releases the
workload Pod. A second rule permits only the paired supervisor Pod to reach the
sandbox TLS port. The supervisor has normal egress for gateway, DNS, and
policy-approved upstream connections. Set
`proxy_pod.network_policy_enforced = true` only after verifying that the cluster
CNI enforces ingress and egress `NetworkPolicy` for sandbox namespaces.

Each sandbox generation uses two immutable bootstrap Secrets. A trusted init
container stages the sandbox bootstrap into memory, and the sandbox removes it
before starting untrusted code. The other Secret is mounted only by the
supervisor. The TLS channel binds the namespace, Sandbox CR, workload Pod,
supervisor Deployment, and egress policy identities. Stop deletes the workload
Pod and scales the supervisor to zero. Start rotates both Secrets and the
supervisor Deployment before creating a new workload Pod. Delete retains the
egress fence until workload deletion is confirmed.

Kubernetes policies are additive, and the API does not attest that the CNI
enforces them. Keep sandbox namespaces administrative: untrusted principals
must not create permissive policies, create Pods, read bootstrap Secrets, or
spoof the pair labels.

## Sandbox Resource

The driver works with the `agents.x-k8s.io` `Sandbox` custom resource. It
detects the served Sandbox API at runtime, caches the selected API version for
the gateway process, and uses `v1beta1` when available before falling back to
`v1alpha1`. Restart the gateway after an in-place Agent Sandbox upgrade so the
driver can detect served API versions again. Driver events map Kubernetes object
state and platform events into the shared compute-driver protobuf surface used
by the gateway.

Kubernetes API calls use explicit timeouts so gRPC handlers do not block
indefinitely when the API server is slow or unavailable. Resource and Event
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
exchange. The driver verifies that token and the gateway returns the
sandbox-scoped JWT used by the supervisor session. The sandbox Pod receives
neither token.

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
