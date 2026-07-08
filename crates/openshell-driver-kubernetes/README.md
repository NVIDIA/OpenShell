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

The default `combined` supervisor topology grants the sandbox agent container
the Linux capabilities the supervisor needs for namespace setup and process,
filesystem, and network policy enforcement.

The `sidecar` supervisor topology moves pod-level network setup into a root init
container and runs the long-lived network sidecar as a non-root UID with no
added Linux capabilities. The agent container also runs as the resolved sandbox
UID/GID with `allowPrivilegeEscalation: false` and `capabilities.drop: ["ALL"]`.
In this mode OpenShell preserves gateway session and SSH behavior, but the
process supervisor does not perform root-to-sandbox privilege dropping or
supervisor identity mount isolation. It still applies Landlock filesystem policy
and child seccomp filters where the kernel/runtime supports them. Network
endpoint and L7 policy remain enforced by the network sidecar, and
sidecar pods use a shared process namespace so the network sidecar can resolve
process/binary identity through `/proc/<entrypoint-pid>`.

Sidecar mode keeps gateway credentials in the network sidecar. The agent
container does not mount the projected service-account token used for sandbox
token bootstrap, does not mount the sandbox client TLS secret, and does not get
gateway callback environment variables. The process supervisor receives policy
and provider environment state from the sidecar over a local control socket in
the shared sidecar state volume.

The driver can request a Kubernetes AppArmor profile through
`app_armor_profile`.

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
