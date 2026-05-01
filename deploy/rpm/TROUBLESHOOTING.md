# OpenShell RPM Troubleshooting

Troubleshooting guide, CLI compatibility notes, remote access setup,
and upgrade procedures for the RPM deployment.

## CLI compatibility

The RPM installs the gateway as a systemd user service with the Podman
compute driver. The published online docs and some CLI commands assume
a Docker/K3s deployment model. This section clarifies which commands
work, which do not, and what to use instead.

### Commands that work normally

All sandbox, provider, policy, inference, and settings commands
communicate with the gateway over gRPC and work identically regardless
of deployment mode:

```
openshell status
openshell sandbox create|list|get|delete|connect|exec
openshell logs <sandbox>
openshell provider create|list|get|update|delete
openshell policy get|set|update|list|prove
openshell inference set|get|update
openshell settings get|set
openshell forward start|stop|list
openshell term
openshell gateway add|select|info
openshell gateway destroy     (removes CLI registration only)
```

### Commands that do not apply

These commands manage Docker container lifecycle and are not applicable
to the RPM/systemd deployment. Use the systemd equivalents instead.

| CLI command | RPM alternative |
|-------------|-----------------|
| `openshell gateway start` | `systemctl --user start openshell-gateway` |
| `openshell gateway stop` | `systemctl --user stop openshell-gateway` |
| `openshell doctor check` | `systemctl --user status openshell-gateway` |
| `openshell doctor logs` | `journalctl --user -u openshell-gateway` |
| `openshell doctor logs --tail` | `journalctl --user -u openshell-gateway -f` |
| `openshell doctor exec` | Not applicable (no K3s container) |

### Building from local Dockerfiles

`openshell sandbox create --from ./Dockerfile` builds via Docker and
pushes into K3s containerd. With the Podman driver, build the image
with Podman and reference it directly:

```shell
podman build -t my-sandbox ./my-dir
openshell sandbox create --from localhost/my-sandbox
```

## Remote CLI access

The auto-generated server certificate only includes SANs for
`localhost`, `127.0.0.1`, and Podman-internal names. To connect from a
different machine, choose one of the following approaches.

### Option 1: SSH tunnel (simplest)

Forward the gateway port over SSH and connect via localhost:

```shell
# On the remote CLI machine:
ssh -L 8080:127.0.0.1:8080 user@gateway-host

# In another terminal on the same machine:
# Copy the client certs from the gateway host first:
scp -r user@gateway-host:~/.config/openshell/gateways/openshell/mtls/ \
    ~/.config/openshell/gateways/openshell/mtls/

openshell gateway add --local https://127.0.0.1:8080
openshell status
```

### Option 2: Externally-managed certificates

Generate certificates that include the server's hostname or IP in the
SANs. See "Using externally-managed certificates" in CONFIGURATION.md.

After placing the server and client certs, register from the remote
CLI:

```shell
# Copy client certs to the remote CLI machine
mkdir -p ~/.config/openshell/gateways/openshell/mtls/
cp ca.crt tls.crt tls.key ~/.config/openshell/gateways/openshell/mtls/

openshell gateway add --local https://<gateway-hostname>:8080
```

### Firewall

For remote access, open the gateway port in firewalld:

```shell
sudo firewall-cmd --add-port=8080/tcp --permanent
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
openshell gateway add --local https://127.0.0.1:8080
```

### Gateway fails to start

Check the journal for error details:

```shell
journalctl --user -u openshell-gateway --no-pager -n 50
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
rm -rf ~/.local/state/openshell/tls
systemctl --user restart openshell-gateway
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
podman pull ghcr.io/nvidia/openshell-community/sandboxes/base:latest
```

### Images not updating

The default image pull policy is `missing` -- images are pulled once
and cached. To update:

```shell
podman pull ghcr.io/nvidia/openshell-community/sandboxes/base:latest
podman pull ghcr.io/nvidia/openshell/supervisor:latest
```

Or set `OPENSHELL_SANDBOX_IMAGE_PULL_POLICY=always` in
`~/.config/openshell/gateway.env` and restart the gateway.

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
sudo dnf update openshell openshell-gateway
systemctl --user restart openshell-gateway
```

The SQLite database schema is auto-migrated on startup. Running
sandboxes are stopped during the restart.

The `gateway.env` file is not overwritten during upgrades. The
`init-gateway-env.sh` script is idempotent and only generates the file
on first start. New configuration options from newer versions can be
added manually by referencing CONFIGURATION.md or running
`openshell-gateway --help`.

To pick up new container images after an upgrade:

```shell
podman pull ghcr.io/nvidia/openshell/supervisor:latest
podman pull ghcr.io/nvidia/openshell-community/sandboxes/base:latest
```
