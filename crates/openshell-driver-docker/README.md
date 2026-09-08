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

The driver creates two containers for each sandbox:

- `openshell-sandbox` is PID 1 in the workload container. It owns the workload
  process tree, seccomp notification broker, mandatory Landlock baseline,
  binary identity, exec/signal/wait/PTY operations, and loopback forwarding.
- `openshell-supervisor` runs in a separate companion container. It owns the
  gateway session, policy engine, credentials, interception CA, SSH relay, L7
  inspection, DNS policy, and external upstream connections.

Both containers are non-root, request no capabilities, and set
no-new-privileges. They share only a driver-created Docker named volume. The
volume carries an authenticated Unix socket and immutable bootstrap material;
it is writable by the sandbox and read-only in the supervisor.

The workload uses `network_mode=none`. Its seccomp user-notification broker
mediates every supported TCP and DNS operation, attributes it to the calling
binary, and sends the request across the private channel. The supervisor
authorizes the request before it opens an upstream connection. Docker's absent
workload network is the mandatory outer fence if mediation fails or is
bypassed. Only the supervisor companion joins the managed bridge network.

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
| `network_mode = none` on the workload | Removes direct external routes. The supervisor companion alone has bridge networking. |
| `restart_policy = no` | Keeps canonical main-process exit terminal. |
| `PidsLimit` | Applies the configured sandbox PID budget. Set `sandbox_pids_limit = 0` to use the runtime default. |
| Private named volume | Carries a per-generation mutual-TLS sandbox/supervisor channel without sharing daemon-host paths. The sandbox consumes its server key at startup; only the supervisor receives the client key. |
| In-memory `/run` tmpfs | Supplies writable runtime state without changing the workload image root filesystem. |
| CDI GPU request | Assigns the exact validated CDI devices requested by driver config or count-based selection. |

## Stop, Start, and Delete

Stop terminates the supervisor companion and stops the workload container
without removing it. Docker retains the workload writable layer and attached
volumes. Start stages a fresh sandbox bootstrap bundle, restarts that workload,
and creates a new supervisor companion. A durably stopped sandbox stays stopped
across gateway restarts.

Delete force-removes both containers, the driver-owned channel volume, and the
host-private topology record. Missing or altered topology and channel resources
fail closed; the driver does not run an older combined-supervisor layout.

## Driver Config Mounts

The gateway forwards the `docker` block from `--driver-config-json`. Supported
mount types are:

- `bind`: an absolute daemon-host path, allowed only when
  `[openshell.drivers.docker].enable_bind_mounts = true`.
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

`supervisor_image` must contain `/openshell-sandbox` and
`/openshell-supervisor`. The driver extracts the sandbox binary as bytes and
stages it into the stopped workload. It starts the supervisor binary directly
in the companion container. Release and gateway image builds bake a matching
supervisor image tag into the binary.

## Callback and TLS

`OPENSHELL_ENDPOINT` and gateway authentication material are injected only into
the supervisor companion. The workload never receives the sandbox JWT, gateway
client TLS key, policy authority, or interception CA private key.

When no endpoint is configured, the driver derives
`host.openshell.internal:<gateway-port>`. Native Linux uses the managed bridge
gateway. Docker Desktop and compatible VM-backed daemons use Docker's
`host-gateway` route. A configured HTTPS server certificate must include the
endpoint host in its subject alternative names.

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
