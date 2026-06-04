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
