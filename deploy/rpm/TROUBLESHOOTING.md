# Ryno RPM Troubleshooting

Troubleshooting guide, CLI compatibility notes, remote access setup,
and upgrade procedures for the RPM deployment.

## CLI compatibility

The RPM installs the gateway as a systemd user service. On a standard RPM
install the gateway auto-detects Podman because the package depends on it.
The published online docs and some CLI commands assume a Docker/K3s
deployment model. This section clarifies which commands work, which do not,
and what to use instead.

### Commands that work normally

All sandbox, provider, policy, and settings commands
communicate with the gateway over gRPC and work identically regardless
of deployment mode:

```
ryno status
ryno sandbox create|list|get|delete|connect|exec
ryno logs <sandbox>
ryno provider create|list|get|update|delete
ryno policy get|set|update|list|prove
ryno provider list
ryno sandbox provider list <sandbox>
ryno settings get|set
ryno forward start|stop|list
ryno term
ryno gateway add|select|info|list|remove
```

### Gateway lifecycle

Gateway service lifecycle is owned by systemd for RPM deployments. Use
systemd commands directly:

| Task | Command |
|------|---------|
| Start gateway | `systemctl --user start ryno-gateway` |
| Stop gateway | `systemctl --user stop ryno-gateway` |
| Restart gateway | `systemctl --user restart ryno-gateway` |
| Check status | `systemctl --user status ryno-gateway` |
| View logs | `journalctl --user -u ryno-gateway` |
| Follow logs | `journalctl --user -u ryno-gateway -f` |
| Remove CLI registration | `ryno gateway remove [name]` |

### Building from local Dockerfiles

Build the image with Podman, then reference it directly:

```shell
podman build -t localhost/my-sandbox:latest ./my-dir
ryno sandbox create --from localhost/my-sandbox:latest
```

## Remote CLI access

The auto-generated server certificate only includes SANs for
`localhost`, `127.0.0.1`, and Podman-internal names. To connect from a
different machine, choose one of the following approaches.

### Option 1: SSH tunnel (simplest)

Forward the gateway port over SSH and connect via localhost:

```shell
# On the remote CLI machine:
ssh -L 17670:127.0.0.1:17670 user@gateway-host

# In another terminal on the same machine:
# Copy the client certs from the gateway host first:
scp -r user@gateway-host:~/.config/ryno/gateways/ryno/mtls/ \
    ~/.config/ryno/gateways/ryno/mtls/

ryno gateway add --local https://127.0.0.1:17670
ryno status
```

### Option 2: Externally-managed certificates

Generate certificates that include the server's hostname or IP in the
SANs. See "Using externally-managed certificates" in CONFIGURATION.md.
Then change `bind_address` in
`~/.config/ryno/gateway.toml` to the interface the remote CLI
can reach, for example `192.168.1.10:17670`, and restart the gateway.

After placing the server and client certs, register from the remote
CLI:

```shell
# Copy client certs to the remote CLI machine
mkdir -p ~/.config/ryno/gateways/ryno/mtls/
cp ca.crt tls.crt tls.key ~/.config/ryno/gateways/ryno/mtls/

ryno gateway add --local https://<gateway-hostname>:17670
```

### Firewall

For remote access, open the gateway port in firewalld:

```shell
sudo firewall-cmd --add-port=17670/tcp --permanent
sudo firewall-cmd --reload
```

For localhost-only access (the default use case), no firewall changes
are needed. Loopback traffic is not filtered by firewalld.

mTLS prevents unauthenticated access even when the port is open to the
network.

## Common issues

### "No active gateway"

The CLI cannot find a registered gateway. This happens when the
gateway is running but has not been registered with the CLI.

```shell
ryno gateway add --local https://127.0.0.1:17670
```

### Gateway fails to start

Check the journal for error details:

```shell
journalctl --user -u ryno-gateway --no-pager -n 50
```

Common causes:

**cgroups v1 detected.** The Podman driver requires cgroups v2.
Check the version:

```shell
stat -fc %T /sys/fs/cgroup
```

Expected output: `cgroup2fs`. If it shows `tmpfs`, enable cgroups v2:

```shell
sudo grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=1"
sudo reboot
```

**Podman socket not available.** Ensure socket activation is enabled:

```shell
systemctl --user enable --now podman.socket
systemctl --user status podman.socket
```

**TLS certificate errors.** If certs are corrupted, regenerate them:

```shell
rm -rf ~/.local/state/ryno/tls
systemctl --user restart ryno-gateway
```

### Sandbox creation fails

**subuid/subgid missing.** Rootless Podman requires subordinate
UID/GID ranges. If the journal shows warnings about `/etc/subuid` or
container creation fails:

```shell
grep $USER /etc/subuid /etc/subgid
# If empty:
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER
```

**Image pull failure.** Verify ghcr.io is reachable:

```shell
podman pull nvcr.io/nvidia/base/ubuntu:24.04
```

### Images not updating

The default image pull policy is `if_not_present` -- images are pulled once
and cached. To update:

```shell
podman pull nvcr.io/nvidia/base/ubuntu:24.04
podman pull ghcr.io/nvidia/ryno/supervisor:latest
```

Or set `image_pull_policy = "always"` in
`~/.config/ryno/gateway.toml` and restart the gateway.

### Gateway stops on logout

Enable lingering so the service survives logout:

```shell
sudo loginctl enable-linger $USER
```

## SELinux

No SELinux configuration is required on stock Fedora or RHEL. The
Podman driver automatically applies the `:z` relabel option to TLS
bind mounts when SELinux is detected, allowing sandbox containers to
read the certificates through the MAC policy.

## Upgrading

After upgrading the RPM packages:

```shell
sudo dnf update ryno ryno-gateway
systemctl --user restart podman.socket
systemctl --user restart ryno-gateway
```

The SQLite database schema is auto-migrated on startup. Running
sandboxes are stopped during the restart.

Restarting `podman.socket` after a package upgrade is recommended: if the
unit file changed on disk during the upgrade, the running socket may become
non-functional until restarted, causing the gateway to fail with a
connection error on `/run/user/<uid>/podman/podman.sock`. The gateway
retries briefly on startup, but a stale socket will not recover on its own.

Package upgrades preserve edited `~/.config/ryno/gateway.toml` files. On
the schema-v2 upgrade, the user service replaces only an exact copy of the v1
file previously seeded by the RPM. If you edited that file, migrate it manually
before restarting the service; direct `dnf` or `rpm` upgrades do not use the
breaking-upgrade guard in `install.sh`. See the
[Gateway Configuration File](https://docs.nvidia.com/ryno/latest/how-it-works/gateways/configuration#migrate-to-schema-version-2)
for the field-by-field migration steps. New gateway process options are listed
in CONFIGURATION.md and `ryno-gateway --help`.

To pick up new container images after an upgrade:

```shell
podman pull ghcr.io/nvidia/ryno/supervisor:latest
podman pull nvcr.io/nvidia/base/ubuntu:24.04
```

### Migrating a TLS-enabled local driver to schema version 2

Docker, Podman, and VM supervisors authenticate the gateway with its CA and
authenticate RPCs with sandbox bearer tokens. Package-managed installs use the
CA generated under `~/.local/state/ryno/tls`, so the RPM default requires
no additional TOML. If you override the listener with custom `--tls-cert` and
`--tls-key` inputs and do not use that managed CA, configure `guest_tls_ca` under
`[ryno.gateway]`. Remove the retired `guest_tls_cert` and `guest_tls_key`
fields. The gateway fails at startup if the required CA is missing. Omit
`guest_tls_ca` when TLS is disabled.

### Migrating from gateway.env

Previous releases generated `~/.config/ryno/gateway.env` on first
start and used it to configure the gateway at launch. The gateway now
starts from built-in runtime defaults and reads
`~/.config/ryno/gateway.toml` when that file exists.

If you have a `gateway.env` file it is still honored: the systemd unit
reads it via `EnvironmentFile` on every start. You can leave it in place
or delete it. New installs no longer generate one.

To migrate settings to TOML, create `~/.config/ryno/gateway.toml`
and map the relevant variables:

| Environment variable | TOML equivalent |
|---|---|
| `RYNO_BIND_ADDRESS=A` + `RYNO_SERVER_PORT=P` | `bind_address = "A:P"` under `[ryno.gateway]` |
| `RYNO_COMPUTE_DRIVER=podman` | `compute_driver = "podman"` under `[ryno.gateway]` |
| `RYNO_DISABLE_TLS=true` | `disable_tls = true` under `[ryno.gateway]` |
| `RYNO_TLS_CERT=PATH` | `cert_path = "PATH"` under `[ryno.gateway.tls]` |
| `RYNO_TLS_KEY=PATH` | `key_path = "PATH"` under `[ryno.gateway.tls]` |
| `RYNO_TLS_CLIENT_CA=PATH` | `client_ca_path = "PATH"` under `[ryno.gateway.tls]` |
| `RYNO_DB_URL=URL` | env-only — not accepted in TOML; keep in env or drop-in override |
| `RYNO_LOG_LEVEL=debug` | env-only — keep as `Environment=RYNO_LOG_LEVEL=debug` in a drop-in |

Other breaking changes in this release:

- **Default port changed from 8080 to 17670.** If you registered the
  gateway at `https://127.0.0.1:8080`, re-register it:

  ```shell
  ryno gateway add --local https://127.0.0.1:17670
  ```

- **Default bind address changed from `0.0.0.0` to `127.0.0.1`.** If
  you relied on network-accessible access without an explicit bind
  address, bind the specific reachable interface in
  `~/.config/ryno/gateway.toml`:

  ```toml
  [ryno.gateway]
  bind_address = "192.168.1.10:17670"
  ```

  Also update your firewall rule if applicable:

  ```shell
  sudo firewall-cmd --remove-port=8080/tcp --permanent
  sudo firewall-cmd --add-port=17670/tcp --permanent
  sudo firewall-cmd --reload
  ```

- **Database path changed** from `~/.local/state/ryno/gateway.db`
  to `~/.local/state/ryno/gateway/ryno.db`. Existing gateway
  state (registered sandboxes, etc.) is not migrated automatically. To
  preserve state across the upgrade, move the file before restarting:

  ```shell
  mkdir -p ~/.local/state/ryno/gateway
  mv ~/.local/state/ryno/gateway.db \
     ~/.local/state/ryno/gateway/ryno.db
  ```
