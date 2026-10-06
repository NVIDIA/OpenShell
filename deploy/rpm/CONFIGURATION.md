# Ryno Gateway Configuration (RPM)

Configuration reference for the Ryno gateway when installed via
the RPM package on Fedora and RHEL systems.

For first-time setup, see QUICKSTART.md. For troubleshooting, see
TROUBLESHOOTING.md.

## Default configuration

The RPM ships a default TOML configuration template at
`/usr/share/ryno-gateway/gateway.toml.default`. On first start of
`ryno-gateway.service`, the systemd unit copies this template to
`~/.config/ryno/gateway.toml` if no config file exists there yet.

The defaults are tuned for rootless Podman use:

```toml
[ryno]
version = 2

[ryno.gateway]
compute_driver = "podman"
```

The RPM does not override `bind_address`. The primary listener uses the
built-in `127.0.0.1:17670` default. Host-networked Podman supervisors connect
to this same loopback listener, so the gateway does not expose another host
interface.

`compute_driver = "podman"` pins the compute driver to Podman. Without
this, the gateway auto-detects in order: Kubernetes, Podman, Docker. Pinning
prevents unexpected driver selection if Docker is also installed on the host.

### Customizing the configuration

Edit `~/.config/ryno/gateway.toml` directly. The package-owned template at
`/usr/share/ryno-gateway/gateway.toml.default` is not read at runtime and
may change during an RPM upgrade. The active user copy is preserved. During a
schema-v2 upgrade, the service replaces only the recognized package-generated
v1 copy; it never rewrites an edited configuration. Before generating
certificates or starting the gateway, the service runs
`ryno-gateway config preflight` against the effective configuration and
stops if validation fails.

To apply environment variable overrides that persist across upgrades without
editing the TOML file, add them to `~/.config/ryno/gateway.env`:

```shell
# Example: explicitly expose the primary listener on one host interface
RYNO_BIND_ADDRESS=192.168.1.10
```

To override the path to the TOML config file entirely:

```shell
# In ~/.config/ryno/gateway.env
RYNO_GATEWAY_CONFIG=/path/to/custom/gateway.toml
```

For one-off service overrides that persist across package upgrades:

```shell
systemctl --user edit ryno-gateway
```

## TLS (mTLS)

The RPM enables mTLS user authentication by default. CLI clients present a valid
client certificate; supervisors use the gateway CA and sandbox-scoped bearer tokens. Its primary listener uses
`127.0.0.1:17670`; Podman supervisor sessions use that same listener.

### Auto-generated certificates

On first start, the systemd user service runs
`ryno-gateway generate-certs --output-dir ~/.local/state/ryno/tls --server-san host.ryno.internal`
to generate certificates with `rcgen` (the same routine the CLI uses for
local mTLS bundles). The unit sets `RYNO_LOCAL_TLS_DIR` to that path and
uses the same value for certificate generation and gateway startup. To use a
custom bundle location, set `RYNO_LOCAL_TLS_DIR` in
`~/.config/ryno/gateway.env` before starting the service.

| File | Purpose | Location |
|------|---------|----------|
| CA certificate | Root of trust | `~/.local/state/ryno/tls/ca.crt` |
| CA private key | Signs server and client certs | `~/.local/state/ryno/tls/ca.key` |
| Server certificate | Gateway TLS identity | `~/.local/state/ryno/tls/server/tls.crt` |
| Server private key | Gateway TLS key | `~/.local/state/ryno/tls/server/tls.key` |
| Client certificate | CLI and sandbox identity | `~/.local/state/ryno/tls/client/tls.crt` |
| Client private key | CLI and sandbox key | `~/.local/state/ryno/tls/client/tls.key` |

Client certificates are also copied to the CLI auto-discovery directory:

```
~/.config/ryno/gateways/ryno/mtls/
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
- `ryno`
- `ryno.ryno.svc`
- `ryno.ryno.svc.cluster.local`
- `host.containers.internal`
- `host.docker.internal`
- `host.ryno.internal`
- `127.0.0.1`

To connect from a remote machine, you need externally-managed
certificates with additional SANs. See "Remote CLI access" in
TROUBLESHOOTING.md.

### Using externally-managed certificates

To use certificates from an external CA or cert-manager:

1. Place the server cert, key, and CA cert on the filesystem.

1. Edit `~/.config/ryno/gateway.toml`:

   ```toml
   [ryno.gateway.tls]
   cert_path = "/path/to/server/tls.crt"
   key_path = "/path/to/server/tls.key"
   client_ca_path = "/path/to/ca.crt"
   ```

1. Place the client cert where the CLI expects it:

   ```
   ~/.config/ryno/gateways/ryno/mtls/
     ca.crt
     tls.crt
     tls.key
   ```

### Rotating certificates

Delete the TLS state directory and restart the gateway:

```shell
rm -rf ~/.local/state/ryno/tls
systemctl --user restart ryno-gateway
```

The gateway regenerates the PKI on next start.

### Disabling TLS

> **WARNING:** With TLS disabled, the gateway API has no authentication.
> Keep the bind address on `127.0.0.1`, or place the gateway behind a
> TLS-terminating reverse proxy that enforces its own authentication.

To disable TLS (not recommended for production):

1. Edit `~/.config/ryno/gateway.toml`:

   ```toml
   [ryno.gateway]
   disable_tls = true
   ```

1. Remove or comment out the `guest_tls_*` entries in
   `~/.config/ryno/gateway.toml` if they are set.

1. Restart the gateway.

## Sandbox TLS

When TLS is enabled, the Podman driver bind-mounts the gateway CA into each
supervisor container to authenticate the gateway. Supervisors authenticate their
RPCs with sandbox-scoped bearer tokens. The user client certificate and private
key are not mounted into supervisor or workload containers.

The following TOML field controls the host-side CA path:

```toml
[ryno.gateway]
guest_tls_ca = "/home/user/.local/state/ryno/tls/ca.crt"
```

Inside the supervisor container, the CA is mounted at
`/etc/ryno/tls/client/ca.crt`.

On SELinux-enabled systems, the Podman driver automatically applies the
`:z` relabel option to these bind mounts. No manual SELinux
configuration is required.

## Configuration reference

> **Upgrading from a previous release?** See the
> ["Migrating from gateway.env"](TROUBLESHOOTING.md#migrating-from-gatewayenv)
> section in TROUBLESHOOTING.md for the env-to-TOML mapping and notes on
> the default port, bind address, and database path changes.

Gateway and driver settings have local runtime defaults. The gateway reads
`~/.config/ryno/gateway.toml` when that file exists. Set
`RYNO_GATEWAY_CONFIG` in the launch environment to use a different file.

Use `systemctl --user edit ryno-gateway` for service environment
overrides that persist across package upgrades.

### Gateway settings

| TOML option | Default | Description |
|-------------|---------|-------------|
| `bind_address` | `127.0.0.1:17670` (gateway default) | Address for the primary gRPC/HTTP API listener. |
| `compute_driver` | `"podman"` (RPM default) | When unset, the gateway auto-detects Kubernetes, then Podman, then Docker. The RPM default pins to Podman; legacy `compute_drivers` lists are rejected. |
| `[ryno.drivers.podman].default_image` | `nvcr.io/nvidia/base/ubuntu:24.04` | Default sandbox image. |
| `[ryno.drivers.podman].sandbox_runtime_image` | `ghcr.io/nvidia/ryno/sandbox:latest` | Static musl sandbox runtime image mounted into Podman workloads. |
| `[ryno.drivers.podman].supervisor_image` | `ghcr.io/nvidia/ryno/supervisor:latest` | Dynamic glibc supervisor image used outside the workload. |
| `[ryno.gateway].guest_tls_ca` | auto-generated path | Gateway CA injected into the selected local driver for supervisor-to-gateway TLS. Sandbox identity uses a bearer token. |
| `[ryno.gateway.tls]` paths | auto-generated paths | Server TLS certificate, key, and client CA. |
| `disable_tls` | unset | Set to `true` to disable TLS. |

The database URL is not accepted in TOML. When `RYNO_DB_URL` is unset,
the gateway uses `sqlite:$XDG_STATE_HOME/ryno/gateway/ryno.db`.
The SQLite database runs in WAL mode with `synchronous=FULL` (SSH session
issuance alone uses `NORMAL`), so
`ryno.db-wal` and `ryno.db-shm` sit next to it and must be kept
together with it; back it up with `sqlite3 ryno.db ".backup <copy>"`.

### Driver TOML settings

Create `~/.config/ryno/gateway.toml` when you need to customize driver
settings:

```toml
[ryno]
version = 2

[ryno.gateway]
compute_driver = "podman"

[ryno.drivers.podman]
network_name = "ryno"
default_image = "nvcr.io/nvidia/base/ubuntu:24.04"
image_pull_policy = "if_not_present"
health_check_interval_secs = 10
stop_timeout_secs = 10
```

### Image management

The gateway pulls container images automatically on first sandbox
creation. The default pull policy is `if_not_present`, which means images are
pulled once and then cached by Podman.

To update cached images:

```shell
podman pull ghcr.io/nvidia/ryno/supervisor:latest
podman pull nvcr.io/nvidia/base/ubuntu:24.04
```

Or set `image_pull_policy = "always"` in
`[ryno.drivers.podman]` to pull on every sandbox creation.

To pin specific image versions instead of `:latest`, set these values in
`[ryno.drivers.podman]`:

```toml
sandbox_runtime_image = "ghcr.io/nvidia/ryno/sandbox:v0.0.37"
supervisor_image = "ghcr.io/nvidia/ryno/supervisor:v0.0.37"
default_image = "nvcr.io/nvidia/base/ubuntu:24.04"
```

For air-gapped environments:

1. On a connected machine, pull and save the images:

   ```shell
   podman pull ghcr.io/nvidia/ryno/supervisor:latest
   podman pull nvcr.io/nvidia/base/ubuntu:24.04
   podman save -o supervisor.tar ghcr.io/nvidia/ryno/supervisor:latest
   podman save -o sandbox.tar nvcr.io/nvidia/base/ubuntu:24.04
   ```

1. Transfer the tarballs to the air-gapped host and load them:

   ```shell
   podman load -i supervisor.tar
   podman load -i sandbox.tar
   ```

1. Set pull policy to `never`:

   ```toml
   [ryno.drivers.podman]
   image_pull_policy = "never"
   ```

## File locations

| Purpose | Path |
|---------|------|
| Gateway binary | `/usr/bin/ryno-gateway` |
| CLI binary | `/usr/bin/ryno` |
| Systemd user unit | `/usr/lib/systemd/user/ryno-gateway.service` |
| Default TOML config template (read-only) | `/usr/share/ryno-gateway/gateway.toml.default` |
| Active gateway TOML configuration | `~/.config/ryno/gateway.toml` |
| Optional environment variable overrides | `~/.config/ryno/gateway.env` |
| TLS certificates | `~/.local/state/ryno/tls/` |
| CLI client certs | `~/.config/ryno/gateways/ryno/mtls/` |
| Gateway database | `~/.local/state/ryno/gateway/ryno.db` |
