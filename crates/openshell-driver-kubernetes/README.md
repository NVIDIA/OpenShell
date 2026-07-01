# openshell-driver-kubernetes

Kubernetes-backed compute driver for OpenShell cluster deployments.

The driver uses the Kubernetes API to create, delete, fetch, and watch sandbox
custom resources in the configured namespace. It runs in-process with the
gateway server.

## Runtime Model

The gateway stores platform state and delegates sandbox workload creation to
this driver. Kubernetes owns scheduling and pod lifecycle. The
`openshell-sandbox` supervisor inside each workload owns agent isolation,
credential injection, policy polling, logs, and the gateway relay.

## Sandbox Resource

The driver works with the `agents.x-k8s.io` `Sandbox` custom resource. It
detects the served Sandbox API at runtime, caches the selected API version for
the gateway process, and uses `v1beta1` when available before falling back to
`v1alpha1`. Restart the gateway after an in-place Agent Sandbox upgrade so the
driver can detect served API versions again. Driver events map Kubernetes object
state and platform events into the shared compute-driver protobuf surface used
by the gateway.

Kubernetes API calls use explicit timeouts so gRPC handlers do not block
indefinitely when the API server is slow or unavailable.

## Workspace Persistence

Sandbox pods use a PVC-backed `/sandbox` workspace. An init container seeds the
PVC from the image's original `/sandbox` contents on first start and writes a
sentinel so subsequent starts skip the copy.

This is a stopgap persistence model. It preserves user files across pod
rescheduling but duplicates the base workspace and does not automatically apply
image updates to existing PVCs. Future snapshotting should replace it.

## Credentials, TLS, and Relay

The driver injects gateway callback configuration, sandbox identity, TLS client
material, and the supervisor SSH socket path into the workload. Driver-owned
values must override image-provided environment variables.

Sandbox pods run as `service_account_name` and keep
`automountServiceAccountToken: false`. The only Kubernetes token exposed to the
supervisor is an explicit, audience-bound projected token mounted at
`/var/run/secrets/openshell/token` for the one-shot `IssueSandboxToken`
bootstrap exchange.

The gateway uses the supervisor relay for connect, exec, and file sync. Sandbox
pods do not need direct external ingress for SSH.

## Container Security Context

The driver grants the sandbox agent container the Linux capabilities the
supervisor needs for namespace setup and policy enforcement. It can also request
a Kubernetes AppArmor profile through `app_armor_profile`.

Supported values are `Unconfined`, `RuntimeDefault`, and
`Localhost/<profile-name>`. An empty or unset value omits
`securityContext.appArmorProfile`. Helm deployments default sandbox agent
containers to `Unconfined` because runtime/default AppArmor profiles can block
the supervisor's network namespace mount setup on AppArmor-enabled nodes.

## GPU Support

When a sandbox requests GPU support, the driver checks node allocatable capacity
for `nvidia.com/gpu` and requests the configured GPU count in the workload spec.
When no count is set, the driver requests one GPU resource. The sandbox image
must provide the user-space libraries needed by the agent workload.

## Driver Config POC

The RFC 0005 POC accepts the selected `SandboxTemplate.driver_config.kubernetes`
block as `DriverSandboxTemplate.driver_config`. The Kubernetes driver owns the
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
POC parser renders the keys listed above and rejects unknown fields.
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
