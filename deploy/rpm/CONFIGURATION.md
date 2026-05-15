# OpenShell Gateway Configuration (RPM)

Configuration reference for the OpenShell gateway when installed via
the RPM package on Fedora and RHEL systems.

For first-time setup, see QUICKSTART.md. For troubleshooting, see
TROUBLESHOOTING.md.

## TLS (mTLS)

The RPM enables mutual TLS by default. The gateway requires a valid
client certificate for all API connections and listens on
`127.0.0.1:17670` by default.

### Auto-generated certificates

On first start, the gateway's `ExecStartPre` runs
`openshell-gateway generate-certs --output-dir <state-dir>/openshell/tls`,
which generates the certificates with `rcgen` (the same routine the CLI
uses for local mTLS bundles):

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

Gateway and driver settings live in
`~/.config/openshell/gateway.toml`, which is generated on first
start. The systemd unit launches the gateway with that file unless
`OPENSHELL_GATEWAY_CONFIG` is set.

Use `systemctl --user edit openshell-gateway` for service environment
overrides that persist across package upgrades.

### Gateway settings

| TOML option | Default | Description |
|-------------|---------|-------------|
| `bind_address` | `127.0.0.1:17670` | Address for the gRPC/HTTP API. |
| `compute_drivers` | unset | When unset, the gateway auto-detects Kubernetes, then Podman, then Docker. Set `compute_drivers = ["podman"]` to force Podman. |
| `default_image` | `ghcr.io/nvidia/openshell-community/sandboxes/base:latest` | Default sandbox image. |
| `supervisor_image` | RPM build image tag | Supervisor image mounted into Podman sandboxes. |
| `guest_tls_ca`, `guest_tls_cert`, `guest_tls_key` | auto-generated paths | Client TLS material bind-mounted into sandbox containers. |
| `[openshell.gateway.tls]` paths | auto-generated paths | Server TLS certificate, key, and client CA. |
| `disable_tls` | unset | Set to `true` to disable TLS. |

The database URL is not accepted in TOML. The unit passes
`--db-url sqlite://$XDG_STATE_HOME/openshell/gateway.db` unless
`OPENSHELL_DB_URL` is set.

### Driver TOML settings

The generated `gateway.toml` contains the RPM's Podman settings but does not
select a driver:

```toml
[openshell]
version = 1

[openshell.gateway]
bind_address = "127.0.0.1:17670"
# Leave unset to auto-detect the compute driver.
# compute_drivers = ["podman"]
default_image = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
supervisor_image = "ghcr.io/nvidia/openshell/supervisor:latest"
guest_tls_ca = "/home/user/.local/state/openshell/tls/ca.crt"
guest_tls_cert = "/home/user/.local/state/openshell/tls/client/tls.crt"
guest_tls_key = "/home/user/.local/state/openshell/tls/client/tls.key"

[openshell.gateway.tls]
cert_path = "/home/user/.local/state/openshell/tls/server/tls.crt"
key_path = "/home/user/.local/state/openshell/tls/server/tls.key"
client_ca_path = "/home/user/.local/state/openshell/tls/ca.crt"

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
| PKI bootstrap | `openshell-gateway generate-certs` (run from `ExecStartPre`) |
| Config generator script | `/usr/libexec/openshell/init-gateway-config.sh` |
| TLS certificates | `~/.local/state/openshell/tls/` |
| CLI client certs | `~/.config/openshell/gateways/openshell/mtls/` |
| Gateway database | `~/.local/state/openshell/gateway.db` |
| Gateway TOML configuration | `~/.config/openshell/gateway.toml` |
