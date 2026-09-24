# openshell-driver-docker

Docker-backed compute driver for local and remote OpenShell gateways.

The driver uses `bollard` to manage sandbox resources through the configured
Docker API socket. When `socket_path` is unset, it selects the first standard
local socket that responds to an API ping. An explicitly selected Docker driver
falls back to `/var/run/docker.sock` when no candidate responds.

When the gateway configures `[openshell.gateway.otlp]`, the in-process driver
exports spans to the same OTLP/gRPC collector as
`openshell-driver-docker`. The standalone driver accepts
`OPENSHELL_OTLP_ENDPOINT`, continues W3C trace context from gateway RPC
metadata, and flushes spans during graceful shutdown.

## Runtime Model

Caller driver config is disabled by default. Existing volumes require
administrator-controlled approval labels; raw bind mounts have no supported
label resolver and are denied under enforcement. GPU devices are temporarily
exempt. Inspect labels again before launch, restart, and during reconciliation.
See [resource admission configuration](../../docs/reference/gateway-config.mdx#external-resource-admission).

The driver creates two containers for each sandbox:

- `openshell-sandbox` is PID 1 in the workload container. It owns the workload
  process tree, seccomp notification broker, mandatory Landlock baseline,
  binary identity, exec/signal/wait/PTY operations, and loopback forwarding.
- `openshell-supervisor` runs in a separate companion container. It owns the
  gateway session, policy engine, credentials, interception CA, SSH relay, L7
  inspection, DNS policy, and external upstream connections.

Both containers are non-root, request no capabilities, and set
no-new-privileges. A shared named volume carries the authenticated Unix socket
and sandbox bootstrap material. A second supervisor-only volume carries the
supervisor JWT and gateway client credentials and is never mounted into the
workload.

The workload uses `network_mode=none`. Its seccomp user-notification broker
mediates every supported TCP and DNS operation, attributes it to the calling
binary, and sends the request across the private channel. The supervisor
authorizes the request before it opens an upstream connection. Docker's absent
workload network is the mandatory outer fence if mediation fails or is
bypassed. The trusted supervisor companion uses Docker host networking, where
it reaches the gateway's primary loopback listener and originates approved
egress.

The driver copies trusted runtime bytes from the configured supervisor image
through the Docker archive API. No workload launch depends on a host bind
mount or a tool supplied by the workload image, so the same path works with
local, remote, and VM-backed Docker daemons.

## Identity and Workspace

Before creating the workload, the driver pins the image ID and reads its
passwd/group databases through a stopped metadata container. It resolves the
admitted policy identity, or the image `Config.User` fallback, into one exact
non-root UID, primary GID, and supplementary-group set. Docker launches
`openshell-sandbox` with that identity, and the sandbox uses the same identity
for every canonical and exec process. UID or GID zero and unresolved symbolic
identities are rejected.

An absolute OCI working directory becomes the workspace. An empty, root (`/`),
or explicit `/sandbox` declaration uses `/sandbox`. Any other workdir must
already exist without symlink components. The resolved identity must be able to
traverse every parent and write and enter the workdir; OpenShell does not
change its ownership or mode.

Image `VOLUME` declarations and user mounts must not cover the workdir, one of
its parents, or the reserved `/.openshell` runtime/channel tree. OpenShell asks
the kernel to validate access under the final identity, so POSIX ACL and host
LSM decisions remain authoritative.

## Container Contract

| Setting | Purpose |
|---|---|
| Exact non-root `user` and `group_add` | Gives sandbox and workload the same immutable UID/GID/group identity required for capability-free observation. |
| `cap_drop = ALL`, no `cap_add`, no-new-privileges | Prevents either container from acquiring Linux capabilities. |
| Docker default seccomp and AppArmor profiles | Retains runtime hardening; startup confirmation fails closed if nested seccomp notification is unavailable. |
| `network_mode = none` on the workload | Removes direct external routes. |
| `network_mode = host` on the supervisor | Lets the trusted supervisor reach the gateway's primary loopback listener and originate approved upstream connections. |
| `restart_policy = no` | Keeps canonical main-process exit terminal. |
| `PidsLimit` | Applies the configured sandbox PID budget. Omit `sandbox_pids_limit` to use OpenShell's default. Explicit zero is invalid. |
| Private named volumes | One carries the authenticated sandbox/supervisor channel. The other is mounted only into the supervisor and contains its JWT and private gateway credentials. |
| In-memory `/run/openshell-supervisor-ca` tmpfs | Holds only the public supervisor CA certificate and trust bundle without making all of `/run` writable. |
| CDI GPU request | Assigns the exact validated CDI devices requested by driver config or count-based selection. |
| CDI workload projection | For GPU sandboxes only, embeds selected device metadata in the protected boundary config and mounts Docker daemon CDI spec directories read-only into the workload. |

## Stop, Start, and Delete

Stop terminates the supervisor companion and stops the workload container
without removing it. Docker retains the workload writable layer and attached
volumes. Start stages a fresh sandbox bootstrap bundle, restarts that workload,
and creates a new supervisor companion. A durably stopped sandbox stays stopped
across gateway restarts.

Delete force-removes both containers, the driver-owned runtime volumes, and the
host-private runtime descriptor. Missing or altered descriptor and channel resources
fail closed; the driver does not run an older combined-supervisor layout.

## CDI GPU Metadata

Docker remains the source of truth for GPU injection. The driver selects opaque
CDI device IDs from `driver_config.cdi_devices` or the daemon's discovered CDI
inventory, then passes the same IDs to Docker with a CDI `DeviceRequest`.

For a GPU sandbox, the driver writes those IDs and projected CDI spec directory
paths to a versioned context in the protected workload boundary configuration.
It bind-mounts the daemon-reported spec directories read-only into the workload.
The sandbox runtime resolves the selected devices in that mount namespace before
it launches agent processes and derives Landlock paths and supplemental groups
from CDI `containerEdits`. A missing context or spec directory fails workload
startup closed. Non-GPU sandboxes receive no CDI context or spec mounts.

## Driver Config Mounts

The gateway forwards the `docker` block from `--driver-config-json`. Supported
mount types are:

- `bind`: an absolute daemon-host path, allowed only when
  `[openshell.drivers.docker].enable_bind_mounts = true` and label admission
  is explicitly disabled.
- `volume`: an existing named volume. The driver never creates or removes a
  user-supplied volume. Bind-backed local volumes require
  `enable_bind_mounts = true`.
- `tmpfs`: an in-memory filesystem with optional size and mode.

Host bind mounts are disabled by default because they expose daemon-host paths
to sandbox requests. User bind and volume mounts are read-only by default.
Targets must be absolute, normalized paths and cannot overlap the workspace
root or OpenShell control paths.

Example:

```shell
docker volume create openshell-work

openshell sandbox create \
  --driver-config-json '{"docker":{"mounts":[{"type":"volume","source":"openshell-work","target":"/sandbox/work"}]}}' \
  -- claude
```

## Runtime Image

`sandbox_runtime_image` contains the statically linked musl
`/openshell-sandbox` binary. The driver extracts that binary as bytes and
stages it into the stopped workload. `supervisor_image` contains the
dynamically linked glibc `/openshell-supervisor` binary that runs in the
host-networked supervisor container. Release and gateway image builds bake
matching image tags into the binary.

## Gateway session and TLS

`OPENSHELL_ENDPOINT` and gateway authentication material are injected only into
the supervisor companion. The workload never receives the sandbox JWT, gateway
client TLS key, policy authority, or interception CA private key.

When no endpoint is configured, the supervisor connects to
`127.0.0.1:<gateway-port>`. Set `grpc_endpoint` when the gateway is not on the
Docker daemon host. A configured HTTPS server certificate must include the
endpoint host in its subject alternative names.

The driver publishes host loopback as the backend address for
`host.openshell.internal`. Policy DNS resolves that reserved name through the
mediated path, so policies can reach host services without a Docker bridge,
container DNS alias, or another gateway listener.

Docker Engine on Linux supports host networking directly. Docker Desktop
requires host networking to be enabled in Settings and does not support it
when Enhanced Container Isolation is enabled.

The supervisor owns these security-critical variables:

- `OPENSHELL_ENDPOINT`
- `OPENSHELL_SANDBOX_ID`
- `OPENSHELL_SANDBOX`
- `OPENSHELL_SANDBOX_TOKEN_FILE`
- `OPENSHELL_SSH_SOCKET_PATH`
- `OPENSHELL_MAIN_PROCESS_SPEC`
- TLS path variables when HTTPS is enabled

Template and sandbox environment is encoded in the protected bootstrap and
exposed only to workload children. Workload input cannot override
security-critical supervisor variables.
