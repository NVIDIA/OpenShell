# OpenShell Gateway Configuration (RPM)

Configuration reference for the OpenShell gateway when installed via
the RPM package on Fedora and RHEL systems.

For first-time setup, see QUICKSTART.md. For troubleshooting, see
TROUBLESHOOTING.md.

## TLS (mTLS)

The RPM enables mutual TLS by default. The gateway requires a valid
client certificate for all API connections, protecting the API even
though it listens on all interfaces (`0.0.0.0`).

### Auto-generated certificates

On first start, the `init-pki.sh` script generates certificates using
OpenSSL:

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

1. Edit `~/.config/openshell/gateway.env` or use
   `systemctl --user edit openshell-gateway` to override:

   ```shell
   OPENSHELL_TLS_CERT=/path/to/server/tls.crt
   OPENSHELL_TLS_KEY=/path/to/server/tls.key
   OPENSHELL_TLS_CLIENT_CA=/path/to/ca.crt
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

> **WARNING:** The RPM gateway binds to all interfaces (`0.0.0.0`) by
> default. With TLS disabled, the gateway API is exposed to the entire
> network with **no authentication**. Any host that can reach the
> gateway port has full access, including the ability to create
> sandboxes, execute arbitrary code, and access configured credentials.
> Only disable TLS when the gateway is behind a TLS-terminating reverse
> proxy that enforces its own authentication. When disabling TLS without
> a reverse proxy, restrict `OPENSHELL_BIND_ADDRESS` to `127.0.0.1`.

To disable TLS (not recommended for production):

1. Edit `~/.config/openshell/gateway.env`:

   ```shell
   OPENSHELL_DISABLE_TLS=true
   ```

1. Comment out the `OPENSHELL_TLS_*` and `OPENSHELL_PODMAN_TLS_*`
   variables if they are set.

1. Restart the gateway.

## Sandbox TLS

When mTLS is enabled, the Podman driver bind-mounts the client
certificates into each sandbox container so the supervisor process can
establish an mTLS connection back to the gateway.

The following environment variables control the host-side paths of the
client certificates that are mounted into sandbox containers:

| Variable | Description |
|----------|-------------|
| `OPENSHELL_PODMAN_TLS_CA` | CA certificate (host path) |
| `OPENSHELL_PODMAN_TLS_CERT` | Client certificate (host path) |
| `OPENSHELL_PODMAN_TLS_KEY` | Client private key (host path) |

Inside the container, the supervisor reads them from:

- `/etc/openshell/tls/client/ca.crt`
- `/etc/openshell/tls/client/tls.crt`
- `/etc/openshell/tls/client/tls.key`

On SELinux-enabled systems, the Podman driver automatically applies the
`:z` relabel option to these bind mounts. No manual SELinux
configuration is required.

## Configuration reference

All settings are controlled via environment variables. The user unit
reads from `~/.config/openshell/gateway.env` (generated on first start)
and from `Environment=` directives in the systemd unit.

Values in `gateway.env` override the unit defaults. Use
`systemctl --user edit openshell-gateway` to add overrides that persist
across package upgrades.

### Gateway settings

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSHELL_BIND_ADDRESS` | `0.0.0.0` | IP address to bind all listeners to. The default exposes the gateway on all interfaces; mTLS must remain enabled to prevent unauthenticated access. Set to `127.0.0.1` for local-only access. |
| `OPENSHELL_SERVER_PORT` | `8080` | Port for the gRPC/HTTP API |
| `OPENSHELL_HEALTH_PORT` | `0` (disabled) | Port for unauthenticated health endpoints (`/healthz`, `/readyz`). Set to a non-zero value to enable. |
| `OPENSHELL_METRICS_PORT` | `0` (disabled) | Port for Prometheus metrics (`/metrics`). Set to a non-zero value to enable. |
| `OPENSHELL_LOG_LEVEL` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `OPENSHELL_DRIVERS` | `podman` | Compute driver (`podman`, `docker`, `kubernetes`) |
| `OPENSHELL_DB_URL` | `sqlite://$XDG_STATE_HOME/openshell/gateway.db` | SQLite database URL for state persistence |
| `OPENSHELL_SSH_HANDSHAKE_SECRET` | (auto-generated) | Shared secret for sandbox SSH authentication |
| `OPENSHELL_DISABLE_GATEWAY_AUTH` | (unset) | Set to `true` to skip mTLS client certificate checks |

### TLS settings

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSHELL_TLS_CERT` | (auto-generated path) | Server TLS certificate |
| `OPENSHELL_TLS_KEY` | (auto-generated path) | Server TLS private key |
| `OPENSHELL_TLS_CLIENT_CA` | (auto-generated path) | CA for client certificate verification |
| `OPENSHELL_DISABLE_TLS` | (unset) | Set to `true` to disable TLS |
| `OPENSHELL_PODMAN_TLS_CA` | (auto-generated path) | CA cert mounted into sandbox containers |
| `OPENSHELL_PODMAN_TLS_CERT` | (auto-generated path) | Client cert mounted into sandbox containers |
| `OPENSHELL_PODMAN_TLS_KEY` | (auto-generated path) | Client key mounted into sandbox containers |

### Sandbox settings

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSHELL_SUPERVISOR_IMAGE` | `ghcr.io/nvidia/openshell/supervisor:latest` | Supervisor binary OCI image |
| `OPENSHELL_SANDBOX_IMAGE` | `ghcr.io/nvidia/openshell-community/sandboxes/base:latest` | Default sandbox base image |
| `OPENSHELL_SANDBOX_IMAGE_PULL_POLICY` | `missing` | Image pull policy: `always`, `missing`, `never`, `newer` |

### Podman driver settings

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSHELL_PODMAN_SOCKET` | `$XDG_RUNTIME_DIR/podman/podman.sock` | Podman API Unix socket path |
| `OPENSHELL_NETWORK_NAME` | `openshell` | Podman bridge network name for sandbox containers |
| `OPENSHELL_STOP_TIMEOUT` | `10` | Container stop timeout in seconds (SIGTERM then SIGKILL) |

### Image management

The gateway pulls container images automatically on first sandbox
creation. The default pull policy is `missing`, which means images are
pulled once and then cached by Podman.

To update cached images:

```shell
podman pull ghcr.io/nvidia/openshell/supervisor:latest
podman pull ghcr.io/nvidia/openshell-community/sandboxes/base:latest
```

Or set `OPENSHELL_SANDBOX_IMAGE_PULL_POLICY=always` to pull on every
sandbox creation.

To pin specific image versions instead of `:latest`:

```shell
OPENSHELL_SUPERVISOR_IMAGE=ghcr.io/nvidia/openshell/supervisor:v0.0.37
OPENSHELL_SANDBOX_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/base:v0.0.37
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

   ```shell
   OPENSHELL_SANDBOX_IMAGE_PULL_POLICY=never
   ```

## File locations

| Purpose | Path |
|---------|------|
| Gateway binary | `/usr/bin/openshell-gateway` |
| CLI binary | `/usr/bin/openshell` |
| Systemd user unit | `/usr/lib/systemd/user/openshell-gateway.service` |
| PKI bootstrap script | `/usr/libexec/openshell/init-pki.sh` |
| Env generator script | `/usr/libexec/openshell/init-gateway-env.sh` |
| TLS certificates | `~/.local/state/openshell/tls/` |
| CLI client certs | `~/.config/openshell/gateways/openshell/mtls/` |
| Gateway database | `~/.local/state/openshell/gateway.db` |
| Gateway configuration | `~/.config/openshell/gateway.env` |
