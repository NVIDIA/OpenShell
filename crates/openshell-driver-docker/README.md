# openshell-driver-docker

Docker-backed compute driver for local OpenShell gateways.

The driver manages sandbox containers through the local Docker daemon with the
`bollard` client. It is intended for developer environments where Docker is
already available and running Kubernetes would be unnecessary.

The driver connects to `[openshell.drivers.docker].socket_path` when configured.
Otherwise, it uses the first standard local Docker socket that responds to an
API ping, which is the same selection mechanism used by gateway auto-detection.
An explicitly selected Docker driver falls back to `/var/run/docker.sock` when
no candidate responds.

## Runtime Model

The gateway runs as a host process. The Docker driver creates one container per
sandbox and starts the `openshell-sandbox` supervisor inside that container. The
supervisor then creates the nested sandbox namespace for the agent process.

Docker containers join an OpenShell-managed bridge network. The driver injects
`host.openshell.internal` and `host.docker.internal` so supervisors have stable
names for reaching the gateway host. On Docker Desktop, Colima, Rancher
Desktop, OrbStack, and macOS-hosted gateways, those names use Docker's
`host-gateway` alias. On native Linux Docker, the gateway also binds the bridge
gateway IP so containers can call back to the host process.

## Container Contract

The driver-controlled container settings are part of the sandbox security
contract:

| Setting | Purpose |
|---|---|
| `user = "0"` | The supervisor needs root inside the container to prepare namespaces, mounts, Landlock, and seccomp. |
| `network_mode = openshell` | Places the supervisor on the managed Docker bridge network. |
| `cap_add` | Grants supervisor-only capabilities required for namespace setup and process inspection. |
| `apparmor=unconfined` | Avoids Docker's default profile blocking required mount operations. |
| `restart_policy = unless-stopped` | Keeps managed sandboxes resumable across daemon or gateway restarts. |
| `PidsLimit` | Enforces the sandbox PID budget at the Docker cgroup layer. Set `[openshell.drivers.docker].sandbox_pids_limit = 0` to inherit the Docker/runtime default. |
| CDI GPU request | Uses opaque `driver_config.cdi_devices` values when set; otherwise selects the requested count of NVIDIA CDI GPUs in round-robin order when daemon CDI support is detected. Docker daemon `/info` can permit `nvidia.com/gpu=all` as a WSL2 all-only compatibility fallback, where it counts as one selectable device. Exact CDI device lists must not contain duplicates and must match the effective GPU count. |

The agent child process does not retain these supervisor privileges.

## Agent Identity

`[openshell.drivers.docker].identity_source` selects the identity for agent
children. It accepts `image` or `fixed` and defaults to `image`. Image mode
requires the sandbox image to declare a non-root OCI `USER`; there is no
implicit `10001:10001` fallback. Fixed mode requires both `fixed_uid` and
`fixed_gid`, each in the inclusive range `1000` through `2000000000`. Fixed
fields are invalid in image mode.

The driver applies the image pull policy, inspects the final image, and carries
its raw OCI `Config.User` and immutable image ID into provisioning. The
container uses the immutable ID as its rootfs image while `user = "0"` keeps
the supervisor privileged. Only agent children drop to the resolved identity.

Image identity accepts named, numeric, and mixed `user:group` OCI forms. A
named user or group must resolve uniquely from the image's regular
`/etc/passwd` or `/etc/group` file. A numeric UID without a group uses the
matching passwd entry's primary GID. A numeric pair such as `USER 1234:1235`
requires no account entries. OpenShell rejects a missing `USER`, an unknown or
ambiguous name, an accountless numeric UID without a group, and any declaration
that resolves to UID or GID 0.

Agent children receive `HOME=/sandbox`, no supplementary groups, and the
declared user name in `USER` and `LOGNAME` when one is available. Numeric and
fixed identities use the numeric UID for presentation. OpenShell does not
modify `/etc/passwd` or `/etc/group`.

The supervisor persists the resolved source, immutable image ID, UID, GID, and
empty supplementary group list. The gateway exposes this record in sandbox
status, and the supervisor emits it as an OCSF configuration-state event.
Restarts reuse the persisted identity instead of resolving a mutable tag or
changed account file again.

## Driver Config Mounts

The gateway forwards the `docker` block from `--driver-config-json` to this
driver. The driver accepts user-supplied `mounts` entries with these Docker
mount types:

- `bind`: mounts an absolute host path when `[openshell.drivers.docker]`
  has `enable_bind_mounts = true`. It also requires fixed identity mode.
- `volume`: mounts an existing Docker named volume. The driver validates that
  the volume exists before provisioning and never creates or removes it.
  Docker local-driver volumes created with bind options are treated as host
  bind mounts and require `enable_bind_mounts = true`. All creator-selected
  named volumes require fixed identity mode.
- `tmpfs`: mounts an in-memory filesystem with optional `options`,
  `size_bytes`, and `mode`.

Host bind mounts are disabled by default because they expose gateway host
paths to sandbox requests. Image mounts are not part of the Docker
driver-config schema. The driver still uses internal bind mounts for
OpenShell-owned supervisor, token, and TLS material.

Image identity mode rejects creator-selected bind and named-volume mounts,
even when `enable_bind_mounts = true`. It permits `tmpfs` and the driver-owned
per-sandbox workspace volume. Use fixed mode for external or shared storage
that expects an operator-controlled UID and GID.

Docker `bind` mounts accept `source`, `target`, optional `read_only`, and an
optional `selinux_label` of `shared` (applies `:z`) or `private` (applies
`:Z`) for SELinux-enforcing hosts. Docker `volume` mounts may include
`subpath`. User-supplied bind and volume mounts are read-only by default; set
`read_only: false` to make them writable. Mount `source`, `target`, and
`subpath` values must not contain surrounding whitespace. Mount targets must be
absolute container paths and must not replace the workspace root (`/sandbox`)
or overlap OpenShell supervisor files, `/etc/openshell`, `/etc/openshell-tls`,
or `/run/netns`.

Example named-volume usage:

```toml
[openshell.drivers.docker]
identity_source = "fixed"
fixed_uid = 1000
fixed_gid = 1000
```

```shell
docker volume create openshell-work

openshell sandbox create \
  --driver-config-json '{"docker":{"mounts":[{"type":"volume","source":"openshell-work","target":"/sandbox/work"}]}}' \
  -- claude
```

## Supervisor Binary Resolution

The Docker driver bind-mounts a host-side Linux `openshell-sandbox` binary into
each sandbox container. Resolution order is:

1. `supervisor_bin` in `[openshell.drivers.docker]`.
2. `supervisor_image` in `[openshell.drivers.docker]`, extracting
   `/openshell-sandbox` from that image.
3. A sibling `openshell-sandbox` next to the running `openshell-gateway` binary.
4. A local Linux cargo target build for the Docker daemon architecture.
5. The release-matched default supervisor image, extracting `/openshell-sandbox`.

Release and Docker-image gateway builds bake the matching supervisor image tag
into the binary at compile time. The default Docker supervisor image is not
`:latest` unless a custom build explicitly sets that tag.

## Callback and TLS

`OPENSHELL_ENDPOINT` is injected from the gateway's configured gRPC endpoint.
When no endpoint is configured, the driver uses
`host.openshell.internal:<gateway-port>` with the appropriate HTTP or HTTPS
scheme. Set `host_gateway_ip` only when the host has an explicit, locally
assigned address that containers should use for callbacks; package-managed
macOS gateways should leave it unset.

For HTTPS endpoints, the server certificate must include the endpoint host as a
subject alternative name. Docker sandboxes also need the client TLS bundle
mounted into the container and exposed with:

- `OPENSHELL_TLS_CA`
- `OPENSHELL_TLS_CERT`
- `OPENSHELL_TLS_KEY`

HTTP endpoints reject TLS material because the supervisor would not use it.

## Environment Ownership

The driver merges template environment and sandbox spec environment first, then
overwrites security-critical keys:

- `OPENSHELL_ENDPOINT`
- `OPENSHELL_SANDBOX_ID`
- `OPENSHELL_SANDBOX`
- `OPENSHELL_SSH_SOCKET_PATH`
- `OPENSHELL_SANDBOX_COMMAND`
- TLS path variables when HTTPS is enabled

Do not allow sandbox images or templates to override these values.
