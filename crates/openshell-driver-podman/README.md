# openshell-driver-podman

The Podman compute driver runs inside the gateway and uses the native libpod
REST API over a Unix socket. Each sandbox has two independent containers:

- `openshell-sandbox` owns the agent process in the workload container.
- `openshell-supervisor` evaluates policy, holds gateway credentials, and
  proxies approved egress in a separate companion container.

The driver provisions placement, identity, credentials, transport, and lifecycle.
The shared isolation interface supplies exec, attach, signal, terminate, binary
identity, DNS, TCP, and loopback-forwarding semantics.

## Runtime posture

| Property | Workload | Supervisor |
|---|---|---|
| UID/GID | Pinned non-root workload identity | Same mapped identity |
| Capabilities | Drop all; add none | Drop all; add none |
| Seccomp | Runtime default plus sandbox-installed filters | Runtime default |
| Network | `none`; loopback only | Podman host network |
| Gateway JWT and upstream credentials | Never mounted | Podman secrets |
| User volumes and CDI devices | Workload only | Never mounted |
| Channel | Private named volume, writable | Same volume, read-only |

Podman creates the namespaces and volume ownership before the workload runs.
Rootless operation uses the operator's Podman service and subordinate-ID
configuration; it does not require adding capabilities to either container.
The supervisor joins the workload's **user namespace only** to preserve UID/GID
mapping for shared-volume access. PID, mount, and network namespaces remain
separate. The channel volume uses shared SELinux relabeling (`:z`).

Before starting either container, the driver uploads volume-relative archives
directly to the channel and workspace volume destinations. A rootfs upload on a
stopped Podman container does not populate nested named volumes. Restart restores
only the channel bootstrap into the existing channel volume, preserving the
workspace. The workload starts before the supervisor so its user namespace exists
when the supervisor joins it; a stopped supervisor resolves that namespace again
on its next start.

The runtime must pass the sandbox's unprivileged enforcement probe, including
nested seccomp notification and Landlock. Unsupported runtime defaults fail
closed; do not switch to an unconfined profile or add capabilities.

## Protected channel and network enforcement

```text
agent -> openshell-sandbox === authenticated gRPC / private UDS === supervisor -> network
         network=none           TCP, DNS, control streams         policy + gateway JWT
```

The workload has no external interface or published port. Seccomp socket
mediation carries TCP and DNS through one authenticated gRPC connection.
DNS remains supervisor-mediated; general UDP is unsupported. The driver sets
`net.ipv4.ip_unprivileged_port_start=0` in the isolated workload network
namespace so the sandbox's loopback DNS relay can bind port 53 without a
capability. No nftables or nested network namespace setup runs in the sandbox.

The channel contains the sandbox bootstrap and sandbox-side TLS identity only.
Supervisor private keys and the runtime descriptor stay in the supervisor's private filesystem.
Landlock denies agent access to the top-level `/.openshell` control hierarchy.
The driver verifies Podman's reported `network=none` fence before launch and
restart. `host.containers.internal` and callback networking apply to the
supervisor, not the agent.

Gateway callbacks use the existing sandbox JWT and optional configured mTLS
bundle. The sandbox/supervisor channel always uses its separate, per-sandbox
mutual TLS material. These are distinct authentication relationships.

## Identity and trusted binaries

Both workload and supervisor images are pinned by immutable image ID. The
driver reads account files from a stopped workload-image container; it never
executes the image to resolve an account. Policy identity fields override OCI
`USER` independently. Named users/groups resolve against that image, including
supplementary groups. Root and unresolved identities fail before provisioning.
Images must not prepopulate the reserved `/.openshell` hierarchy; this prevents
image-controlled symlinks from aliasing private control state into user mounts.

`sandbox_runtime_image` supplies the statically linked musl
`/openshell-sandbox` binary. Podman's read-only image volume delivers it to the
workload; user-namespace modes that cannot use image volumes retain the trusted
binary extraction path. `supervisor_image` supplies the dynamically linked
glibc `/openshell-supervisor` binary outside the workload. Image and request
environment belong to agent children, never the supervisor process.

## Lifecycle and readiness

Create builds both stopped containers and stages the private archives before
starting either container. The sandbox does not execute the agent until the
supervisor authenticates and confirms the common boundary contract. Failed
creation removes only containers created by that attempt, then cleans up
driver-owned volumes and secrets.

Stop retains both containers, workspace, channel, and secrets. Start restores
the consumed sandbox bootstrap from a copy in the supervisor's private
filesystem, verifies the fence, and starts the same pair. A failed supervisor
start stops the workload. Delete removes the companion first, then the workload,
channel, workspace, and driver-owned secrets. User-owned volumes are retained.

Only workload containers appear in sandbox list/watch results. Readiness uses
the supervisor's private health socket; there is no shell, legacy marker, or
TCP-listener shortcut. Watch reconciliation and supervisor exit/removal events
stop a running workload whose companion is unavailable. The gateway also
requires the authenticated supervisor session before publishing Ready.

## Mounts, GPUs, and configuration

User `bind`, `volume`, `tmpfs`, and `image` mounts and CDI GPU selection remain
native Podman features and apply only to the workload. Bind mounts require the
operator's `enable_bind_mounts` opt-in. Reserved control paths and the workspace
root cannot be replaced. User-owned volumes are never created or deleted.

See [gateway configuration](../../docs/reference/gateway-config.mdx) for
operator settings and [NETWORKING.md](NETWORKING.md) for callback networking.
The supervisor uses Podman's host network and owns the upstream proxy settings.
`health_check_interval_secs=0` uses a one-second check rather than disabling
the readiness check required by this architecture.

Gateway OTLP configuration continues to export compute-driver spans under the
`openshell-driver-podman` service, preserving gateway trace context.
