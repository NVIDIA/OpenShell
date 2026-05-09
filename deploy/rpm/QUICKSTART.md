# OpenShell RPM Quick Start

Get from `dnf install` to a running sandbox in five minutes.

## Prerequisites

### Podman (rootless)

The gateway uses rootless Podman for sandbox containers. Verify
Podman is installed and the cgroup version is v2:

```shell
podman --version
podman info --format '{{.Host.CgroupsVersion}}'
```

The cgroup version must be `v2`. If it reports `v1`, enable the
unified cgroup hierarchy and reboot:

```shell
sudo grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=1"
sudo reboot
```

### Subordinate UID/GID ranges

Rootless containers require subordinate UID/GID mappings:

```shell
grep $USER /etc/subuid /etc/subgid
```

If empty, add entries:

```shell
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER
```

### Podman socket

The gateway communicates with Podman over its API socket. Enable
socket activation:

```shell
systemctl --user enable --now podman.socket
```

### Network access

The gateway pulls container images from ghcr.io on first sandbox
creation. Ensure the host can reach ghcr.io over HTTPS (port 443).

For air-gapped environments, pre-load images with `podman pull` and
set `OPENSHELL_SANDBOX_IMAGE_PULL_POLICY=never` in
`~/.config/openshell/gateway.env`. See CONFIGURATION.md for details.

## Start the gateway

```shell
systemctl --user enable --now openshell-gateway
```

On first start, the gateway automatically generates:

- A self-signed PKI bundle (CA, server cert, client cert) for mTLS
- An SSH handshake secret for sandbox authentication
- A commented configuration file at `~/.config/openshell/gateway.env`

> **Note:** The gateway binds to all interfaces (`0.0.0.0`) by default.
> Mutual TLS (mTLS) is enabled automatically on first start, requiring a
> valid client certificate for every connection. Do not disable TLS
> without restricting the bind address to `127.0.0.1`. See
> CONFIGURATION.md for details.

Verify the service is running:

```shell
systemctl --user status openshell-gateway
```

## Register the gateway with the CLI

The CLI needs to know where the gateway is. Register it:

```shell
openshell gateway add --local https://127.0.0.1:8080
```

This discovers the pre-provisioned mTLS certificates at
`~/.config/openshell/gateways/openshell/mtls/` and sets the gateway
as active.

Verify the connection:

```shell
openshell status
```

## Persist across reboots

By default, user services stop when you log out. To keep the gateway
running after logout and across reboots:

```shell
sudo loginctl enable-linger $USER
```

Without this, the gateway and all running sandboxes are killed when
your login session ends. This is required for any headless or
production use.

## Create your first sandbox

Set your API key in the environment, then create a sandbox:

```shell
export ANTHROPIC_API_KEY=sk-...
openshell sandbox create -- claude
```

The CLI detects the agent, prompts to create a credential provider
from your local environment, pulls the sandbox image from ghcr.io,
and connects you to the running sandbox.

Other agents:

```shell
openshell sandbox create -- opencode
openshell sandbox create -- codex
```

## Set up providers manually

If you prefer to configure providers before creating sandboxes:

```shell
# Create a provider from a local environment variable
openshell provider create --name anthropic --type anthropic --from-existing

# Or supply the credential directly
openshell provider create --name openai --type openai \
  --credential OPENAI_API_KEY=sk-...

# List configured providers
openshell provider list
```

## Configure inference routing (optional)

To route inference requests through a specific provider and model:

```shell
openshell inference set --provider openai --model gpt-4
openshell inference get
```

## Next steps

- See CONFIGURATION.md for TLS settings, environment variables, and
  file locations.
- See TROUBLESHOOTING.md for CLI compatibility notes, remote access,
  and common issues.
- Run `man openshell` for the CLI reference.
- Run `man openshell-gateway` for the gateway daemon reference.
