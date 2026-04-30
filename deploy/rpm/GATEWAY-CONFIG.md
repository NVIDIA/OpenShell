# OpenShell Gateway Configuration (RPM)

This document covers the configuration of the OpenShell gateway when
installed via the RPM package on Fedora and RHEL systems.

## Quick start

```shell
# Enable and start the gateway (rootless Podman, mTLS enabled):
systemctl --user enable --now openshell-gateway

# Verify the gateway is running:
openshell sandbox list

# Make the service persist across reboots without an active login:
sudo loginctl enable-linger $USER
```

On first start, the gateway auto-generates:

- A self-signed PKI bundle (CA, server cert, client cert) for mTLS
- An SSH handshake secret for sandbox authentication

No manual certificate setup is required.

## TLS (mTLS)

The RPM enables mutual TLS by default. The gateway requires a valid
client certificate for all API connections, protecting the API even
though it listens on all interfaces (`0.0.0.0`).

### Auto-generated certificates

On first start, the `init-pki.sh` script generates certificates using
OpenSSL:

| File | Purpose | Location (user unit) |
|------|---------|---------------------|
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

### Using externally-managed certificates

To use certificates from an external CA or cert-manager:

1. Place the server cert, key, and CA cert on the filesystem
1. Edit `/etc/sysconfig/openshell-gateway` (system unit) or use
   `systemctl --user edit openshell-gateway` (user unit) to override:

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

To disable TLS (not recommended for production):

1. Edit the sysconfig file or use a systemd override:

```shell
OPENSHELL_DISABLE_TLS=true
```

1. Remove or comment out the `OPENSHELL_TLS_*` and
   `OPENSHELL_PODMAN_TLS_*` variables.

1. Restart the gateway.

With TLS disabled, the gateway has no authentication. Any host that can
reach the gateway port has full access to the API.

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

## Configuration reference

All settings are controlled via environment variables. The system unit
reads from `/etc/sysconfig/openshell-gateway`. The user unit reads from
`~/.config/openshell/gateway.env` and systemd `Environment=` directives.

### Gateway settings

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSHELL_BIND_HOST` | `0.0.0.0` | IP address to bind all listeners to |
| `OPENSHELL_SERVER_PORT` | `8080` | Port for the gRPC/HTTP API |
| `OPENSHELL_DRIVERS` | `podman` | Compute driver (`podman`, `docker`, `kubernetes`) |
| `OPENSHELL_DB_URL` | (varies) | SQLite database URL for state persistence |
| `OPENSHELL_SSH_HANDSHAKE_SECRET` | (auto-generated) | Shared secret for sandbox SSH authentication |

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
| `OPENSHELL_SUPERVISOR_IMAGE` | `ghcr.io/.../supervisor:latest` | Supervisor binary OCI image |
| `OPENSHELL_SANDBOX_IMAGE` | `ghcr.io/.../sandboxes/base:latest` | Default sandbox base image |

## File locations

### User unit (systemctl --user)

| Purpose | Path |
|---------|------|
| Gateway binary | `/usr/bin/openshell-gateway` |
| CLI binary | `/usr/bin/openshell` |
| Systemd unit | `/usr/lib/systemd/user/openshell-gateway.service` |
| PKI bootstrap script | `/usr/libexec/openshell/init-pki.sh` |
| TLS certificates | `~/.local/state/openshell/tls/` |
| CLI client certs | `~/.config/openshell/gateways/openshell/mtls/` |
| Gateway database | `~/.local/state/openshell/gateway.db` |
| SSH handshake secret | `~/.config/openshell/gateway.env` |

### System unit (systemctl)

| Purpose | Path |
|---------|------|
| Systemd unit | `/usr/lib/systemd/system/openshell-gateway.service` |
| Configuration | `/etc/sysconfig/openshell-gateway` |
| TLS certificates | `/var/lib/openshell/tls/` |
| Gateway database | `/var/lib/openshell/gateway.db` |
