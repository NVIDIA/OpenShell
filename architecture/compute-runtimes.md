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

## Runtime Summary

| Runtime | Best fit | Sandbox boundary | Notes |
|---|---|---|---|
| Docker | Local development with Docker available. | Container plus nested sandbox namespace. | Uses host networking so loopback gateway endpoints work from the supervisor. |
| Podman | Rootless or single-machine deployments. | Container plus nested sandbox namespace. | Uses the Podman REST API, OCI image volumes, and CDI GPU devices when available. |
| Kubernetes | Cluster deployment through Helm. | Pod plus nested sandbox namespace. | Uses Kubernetes API objects, service accounts, secrets, PVC-backed workspace storage, and GPU resources. |
| VM | Experimental microVM isolation. | Per-sandbox libkrun VM. | Gateway spawns `openshell-driver-vm` as a subprocess over a Unix socket. |

Runtime-specific implementation notes belong in the driver crate README:

- `crates/openshell-driver-docker/README.md`
- `crates/openshell-driver-podman/README.md`
- `crates/openshell-driver-kubernetes/README.md`
- `crates/openshell-driver-vm/README.md`

## Supervisor Delivery

The supervisor must be available inside each sandbox workload:

| Runtime | Delivery model |
|---|---|
| Docker | Bind-mounted or extracted supervisor binary configured by the gateway. |
| Podman | Read-only OCI image volume containing the supervisor binary. |
| Kubernetes | Sandbox pod image or pod template configuration. |
| VM | Embedded in the guest rootfs bundle. |

Driver-controlled environment variables must override sandbox image or template
values for sandbox ID, sandbox name, gateway endpoint, relay socket path, TLS
paths, and command metadata.

## Images

The gateway image and Helm chart are built from this repository. Sandbox images
are maintained separately in the OpenShell Community repository or supplied by
users.

Custom sandbox images must include the agent runtime and any system
dependencies, but they should not need to include the gateway. GPU-capable
images must include the user-space libraries required by the workload. The
runtime still owns GPU device injection.

## Deployment Shape

Kubernetes deployments use the Helm chart under `deploy/helm/openshell`.
Standalone local deployments start the gateway with a selected runtime such as
Docker, Podman, or VM. The CLI can register multiple gateways and switch between
them without changing the sandbox architecture.

When runtime infrastructure changes, validate the relevant sandbox e2e path and
update the matching driver README if a maintainer-facing constraint changes.
