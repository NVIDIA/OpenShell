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

## Warm Pools

When `warm_pool.enabled` is set, the driver pre-declares one operator-owned
`SandboxTemplate` + `SandboxWarmPool` per configured pool (extension CRDs
`extensions.agents.x-k8s.io/v1alpha1`) and satisfies a matching `CreateSandbox`
by creating a `SandboxClaim` that binds a pre-warmed pod (~0.1s) instead of
cold-creating a `Sandbox`. Only the trusted `default_image` with no per-request
template or env overrides is pooled; everything else takes the cold path.

The pooled `SandboxTemplate` bakes the shared pod blueprint (image, mTLS mount,
projected SA token, supervisor sideload, capabilities, runtimeClass, optional
read-only shared data volume) but carries **no per-sandbox identity**. The
template sets `networkPolicyManagement: Unmanaged` — OpenShell enforces egress
itself (supervisor proxy + Landlock), and the controller's default `Managed`
mode would otherwise impose a rule-less, default-deny `NetworkPolicy` that blocks
the pod's own egress to the gateway. The writable `/sandbox` workspace is an
ephemeral `emptyDir` seeded from the image: single-use and fail-safe (the kubelet
reclaims it with the pod, so there is nothing to orphan). Claims set
`shutdownPolicy: Delete` so teardown cascades to the bound `Sandbox`/Pod, and a
claimed pod is never returned to the pool.

### Identity and policy on the warm path

A pooled pod boots **before** its claim assigns an identity, so the supervisor
cannot fetch a per-sandbox policy or assert a sandbox-id at startup. Instead it:

- boots on the image's **baseline policy** (Landlock is applied once at process
  start and cannot be loosened later, so the baseline is what a pooled pod
  enforces);
- runs with `OPENSHELL_SANDBOX_ID` unset, skipping identity-gated startup;
- establishes its relay session with an empty `hello.sandbox_id`; the gateway
  derives the identity from the gateway-minted JWT obtained via
  `IssueSandboxToken` (resolved server-side from the claim-injected
  `openshell.io/sandbox-id` annotation + the durable claim mapping). The
  supervisor retries the bootstrap at a steady cadence until the claim binds.

Because a pooled pod can only enforce the baseline policy, a `CreateSandbox`
request that carries a **custom policy** is never warm-pooled — the gateway sets
`DriverSandboxSpec.disallow_warm_pool`, and such requests take the cold path so
their policy is applied faithfully (no silent downgrade). Claim `env` injection
is likewise disallowed.

The driver surfaces a warm sandbox to the gateway by watching `SandboxClaim`s
(correlated to the gateway sandbox-id via the `openshell.ai/sandbox-id` label it
stamps on each claim) and returns the bound claim's `(name, uid)` so the gateway
can record the durable claim → sandbox-id mapping used by the auth re-anchor.

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
POC parser renders the keys listed above and rejects unknown fields.
`pod.runtime_class_name` maps to PodSpec `runtimeClassName` and overrides the
driver's configured `default_runtime_class_name`; the typed public
`SandboxTemplate.runtime_class_name` still takes precedence when set. Use the
public `gpu` flag for the default GPU request and `driver_config` only for
additional driver-owned resource details.
