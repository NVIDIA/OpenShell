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

Set `default_runtime_class_name` in the driver config to assign a default Kubernetes
RuntimeClass, such as `gvisor` or a Kata Containers RuntimeClass, to sandbox
pods. Per-sandbox template `runtime_class_name` values override the driver
default. When `default_runtime_class_name` is configured, the driver validates
that the cluster has that RuntimeClass during startup so a missing runtime fails
fast instead of surfacing later as pod sandbox creation errors. Per-sandbox
RuntimeClass overrides are validated during sandbox
admission/create. As a short-term compatibility escape hatch, the driver can set
`privileged = true` deployment-wide; the driver maps that to
`podTemplate.spec.containers[0].securityContext.privileged` for all sandbox pod
containers. Use it only for trusted clusters that require privileged pod
admission because it weakens the container boundary.

Kubernetes deployments default to `supervisor_role = "workload"` and
`network_enforcement_mode = "soft-proxy"`. In this mode the supervisor runs the
proxy, policy reload, relay, and agent lifecycle without creating a Linux
network namespace; proxy-aware traffic is enforced, but direct socket egress is
not kernel-blocked. Set `network_enforcement_mode = "supervisor-netns"` to use
the existing netns/veth/nft path when the sandbox pod has the required Linux
capabilities. Set `network_enforcement_mode = "external-enforcer"` to try the
node-enforcer topology; the workload supervisor registers with a node-side
enforcer, which installs coarse pod-netns egress rules while dynamic endpoint
policy stays inside the proxy.

## Sandbox Resource

The driver works with the `agents.x-k8s.io/v1alpha1` `Sandbox` custom resource.
Driver events map Kubernetes object state and platform events into the shared
compute-driver protobuf surface used by the gateway.

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
for `nvidia.com/gpu` and requests one GPU resource in the workload spec. The
sandbox image must provide the user-space libraries needed by the agent
workload.

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
POC parser renders the keys listed above and ignores unknown fields.
`pod.runtime_class_name` maps to PodSpec `runtimeClassName` and overrides the
driver's configured `default_runtime_class_name`; the typed public
`SandboxTemplate.runtime_class_name` still takes precedence when set. Use the
public `gpu` flag for the default GPU request and `driver_config` only for
additional driver-owned resource details.
