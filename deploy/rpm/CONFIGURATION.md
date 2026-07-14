# OpenShell Gateway Configuration (RPM)

Configuration reference for the OpenShell gateway when installed via
the RPM package on Fedora and RHEL systems.

For first-time setup, see QUICKSTART.md. For troubleshooting, see
TROUBLESHOOTING.md.

## Default configuration

The RPM ships a default TOML configuration template at
`/usr/share/openshell-gateway/gateway.toml.default`. On first start of
`openshell-gateway.service`, the systemd unit copies this template to
`~/.config/openshell/gateway.toml` if no config file exists there yet.

The default keeps the listener on loopback while leaving compute driver
selection automatic:

```toml
[openshell]
version = 1

[openshell.gateway]
bind_address = "127.0.0.1:17670"
```

The loopback default avoids exposing the gateway on host network interfaces.
Rootless Podman sandbox containers cannot reach host loopback from their
network namespace. Configure `bind_address = "0.0.0.0:17670"` before creating
Podman-backed sandboxes.

When `compute_drivers` is unset, the gateway auto-detects Kubernetes, then a
reachable Podman socket, then Docker. Set `compute_drivers = ["docker"]` or
`compute_drivers = ["podman"]` to require a specific container runtime.

The RPM does not include the VM driver. To use VM-backed sandboxes, download
the matching `openshell-driver-vm` release artifact, install the binary in a
conventional libexec directory (or set `driver_dir` to its location), and
select it explicitly:

```toml
[openshell.gateway]
compute_drivers = ["vm"]

[openshell.drivers.vm]
grpc_endpoint = "https://host.containers.internal:17670"
```

The gateway never auto-detects VM support. If it cannot find the binary, the
startup error lists every directory it searched.

### Customizing the configuration

Use the gateway config command to select a driver or update the listener. For
example, pin Docker:

```shell
openshell-gateway config set 'openshell.gateway.compute_drivers=["docker"]'
systemctl --user restart openshell-gateway
```

Pass another dotted `KEY=VALUE` argument to update more fields atomically. Set
`openshell.gateway.compute_drivers=[]` to restore automatic driver selection.
The command preserves comments and unrelated settings. You can also edit
`~/.config/openshell/gateway.toml` directly. The template at
`/usr/share/openshell-gateway/gateway.toml.default` is not read at runtime
and is not overwritten by RPM upgrades.

To apply environment variable overrides that persist across upgrades without
editing the TOML file, add them to `~/.config/openshell/gateway.env`:

```shell
# Example: restrict to loopback only
OPENSHELL_BIND_ADDRESS=127.0.0.1
```

To override the path to the TOML config file entirely:

```shell
# In ~/.config/openshell/gateway.env
OPENSHELL_GATEWAY_CONFIG=/path/to/custom/gateway.toml
```

For one-off service overrides that persist across package upgrades:

```shell
systemctl --user edit openshell-gateway
```

## TLS (mTLS)

The RPM enables mutual TLS by default. The gateway requires a valid
client certificate for all API connections and listens on
`127.0.0.1:17670` by default (see "Default configuration" above).

### Auto-generated certificates

On first start, the systemd user service runs
`openshell-gateway generate-certs --output-dir ~/.local/state/openshell/tls --server-san host.openshell.internal`
to generate certificates with `rcgen` (the same routine the CLI uses for
local mTLS bundles). The unit sets `OPENSHELL_LOCAL_TLS_DIR` to that path and
uses the same value for certificate generation and gateway startup. To use a
custom bundle location, set `OPENSHELL_LOCAL_TLS_DIR` in
`~/.config/openshell/gateway.env` before starting the service.

| File | Purpose | Location |
|------|---------|----------|
| CA certificate | Root of trust | `~/.local/state/openshell/tls/ca.crt` |
| CA private key | Signs server and client certs | `~/.local/state/openshell/tls/ca.key` |
| Server certificate | Gateway TLS identity | `~/.local/state/openshell/tls/server/tls.crt` |
| Server private key | Gateway TLS key | `~/.local/state/openshell/tls/server/tls.key` |
| Client certificate | CLI and sandbox identity | `~/.local/state/openshell/tls/client/tls.crt` |
| Client private key | CLI and sandbox key | `~/.local/state/openshell/tls/client/tls.key` |

Client certificates are also copied to the CLI auto-discovery directory:

```
~/.config/openshell/gateways/openshell/mtls/
  ca.crt
  tls.crt
  tls.key
```

The CLI automatically discovers these certificates when connecting to a
gateway on `localhost` or `127.0.0.1`.

### Server certificate SANs

The auto-generated server certificate includes these Subject Alternative
Names:

- `localhost`
- `openshell`
- `openshell.openshell.svc`
- `openshell.openshell.svc.cluster.local`
- `host.containers.internal`
- `host.docker.internal`
- `host.openshell.internal`
- `127.0.0.1`

To connect from a remote machine, you need externally-managed
certificates with additional SANs. See "Remote CLI access" in
TROUBLESHOOTING.md.

### Using externally-managed certificates

To use certificates from an external CA or cert-manager:

1. Place the server cert, key, and CA cert on the filesystem.

1. Edit `~/.config/openshell/gateway.toml`:

   ```toml
   [openshell.gateway.tls]
   cert_path = "/path/to/server/tls.crt"
   key_path = "/path/to/server/tls.key"
   client_ca_path = "/path/to/ca.crt"
   ```

1. Place the client cert where the CLI expects it:

   ```
   ~/.config/openshell/gateways/openshell/mtls/
     ca.crt
     tls.crt
     tls.key
   ```

### Rotating certificates

Delete the TLS state directory and restart the gateway:

```shell
rm -rf ~/.local/state/openshell/tls
systemctl --user restart openshell-gateway
```

The gateway regenerates the PKI on next start.

### Disabling TLS

> **WARNING:** With TLS disabled, the gateway API has no authentication.
> Keep the bind address on `127.0.0.1`, or place the gateway behind a
> TLS-terminating reverse proxy that enforces its own authentication.

To disable TLS (not recommended for production):

1. Edit `~/.config/openshell/gateway.toml`:

   ```toml
   [openshell.gateway]
   disable_tls = true
   ```

1. Remove or comment out the `guest_tls_*` entries in
   `~/.config/openshell/gateway.toml` if they are set.

1. Restart the gateway.

## Sandbox TLS

When mTLS is enabled, the Podman driver bind-mounts the client
certificates into each sandbox container so the supervisor process can
establish an mTLS connection back to the gateway.

The following TOML fields control the host-side paths of the client
certificates that are mounted into sandbox containers:

```toml
[openshell.gateway]
guest_tls_ca = "/home/user/.local/state/openshell/tls/ca.crt"
guest_tls_cert = "/home/user/.local/state/openshell/tls/client/tls.crt"
guest_tls_key = "/home/user/.local/state/openshell/tls/client/tls.key"
```

Inside the container, the supervisor reads them from:

- `/etc/openshell/tls/client/ca.crt`
- `/etc/openshell/tls/client/tls.crt`
- `/etc/openshell/tls/client/tls.key`

On SELinux-enabled systems, the Podman driver automatically applies the
`:z` relabel option to these bind mounts. No manual SELinux
configuration is required.

## Configuration reference

> **Upgrading from a previous release?** See the
> ["Migrating from gateway.env"](TROUBLESHOOTING.md#migrating-from-gatewayenv)
> section in TROUBLESHOOTING.md for the env-to-TOML mapping and notes on
> the default port, bind address, and database path changes.

Gateway and driver settings have local runtime defaults. The gateway reads
`~/.config/openshell/gateway.toml` when that file exists. Set
`OPENSHELL_GATEWAY_CONFIG` in the launch environment to use a different file.

Use `systemctl --user edit openshell-gateway` for service environment
overrides that persist across package upgrades.

### Gateway settings

| TOML option | Default | Description |
|-------------|---------|-------------|
| `bind_address` | `127.0.0.1:17670` | Address for the gRPC/HTTP API. Rootless Podman requires `0.0.0.0:17670`. |
| `compute_drivers` | unset | The gateway auto-detects Kubernetes, then a reachable Podman socket, then Docker. VM requires explicit selection. |
| `default_image` | `ghcr.io/nvidia/openshell-community/sandboxes/base:latest` | Default sandbox image. |
| `supervisor_image` | `ghcr.io/nvidia/openshell/supervisor:latest` | Supervisor image mounted into Podman sandboxes. |
| `guest_tls_ca`, `guest_tls_cert`, `guest_tls_key` | auto-generated paths | Client TLS material bind-mounted into sandbox containers. |
| `[openshell.gateway.tls]` paths | auto-generated paths | Server TLS certificate, key, and client CA. |
| `disable_tls` | unset | Set to `true` to disable TLS. |

The database URL is not accepted in TOML. When `OPENSHELL_DB_URL` is unset,
the gateway uses `sqlite:$XDG_STATE_HOME/openshell/gateway/openshell.db`.

### Driver TOML settings

Create `~/.config/openshell/gateway.toml` when you need to customize driver
settings. For example, pin Podman explicitly:

```toml
[openshell]
version = 1

[openshell.gateway]
bind_address = "0.0.0.0:17670"
compute_drivers = ["podman"]
default_image = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"

[openshell.drivers.podman]
image_pull_policy = "missing"
network_name = "openshell"
stop_timeout_secs = 10
```

### Image management

The gateway pulls container images automatically on first sandbox
creation. The default pull policy is `missing`, which means images are
pulled once and then cached by Podman.

To update cached images:

```shell
podman pull ghcr.io/nvidia/openshell/supervisor:latest
podman pull ghcr.io/nvidia/openshell-community/sandboxes/base:latest
```

Or set `image_pull_policy = "always"` in
`[openshell.drivers.podman]` to pull on every sandbox creation.

To pin specific image versions instead of `:latest`:

```shell
supervisor_image = "ghcr.io/nvidia/openshell/supervisor:v0.0.37"
default_image = "ghcr.io/nvidia/openshell-community/sandboxes/base:v0.0.37"
```

For air-gapped environments:

1. On a connected machine, pull and save the images:

   ```shell
   podman pull ghcr.io/nvidia/openshell/supervisor:latest
   podman pull ghcr.io/nvidia/openshell-community/sandboxes/base:latest
   podman save -o supervisor.tar ghcr.io/nvidia/openshell/supervisor:latest
   podman save -o sandbox.tar ghcr.io/nvidia/openshell-community/sandboxes/base:latest
   ```

1. Transfer the tarballs to the air-gapped host and load them:

   ```shell
   podman load -i supervisor.tar
   podman load -i sandbox.tar
   ```

1. Set pull policy to `never`:

   ```toml
   [openshell.drivers.podman]
   image_pull_policy = "never"
   ```

## File locations

| Purpose | Path |
|---------|------|
| Gateway binary | `/usr/bin/openshell-gateway` |
| CLI binary | `/usr/bin/openshell` |
| Systemd user unit | `/usr/lib/systemd/user/openshell-gateway.service` |
| Default TOML config template (read-only) | `/usr/share/openshell-gateway/gateway.toml.default` |
| Active gateway TOML configuration | `~/.config/openshell/gateway.toml` |
| Optional environment variable overrides | `~/.config/openshell/gateway.env` |
| TLS certificates | `~/.local/state/openshell/tls/` |
| CLI client certs | `~/.config/openshell/gateways/openshell/mtls/` |
| Gateway database | `~/.local/state/openshell/gateway/openshell.db` |
