# Building a snap package

OpenShell snap packages are defined by `snap/snapcraft.yaml` and built with
Snapcraft from source.

The helper task under `tasks/` still stages the same payload from pre-built
binaries when you want to inspect the snap root or produce local artifacts.

## Prerequisites

- Linux on `amd64` or `arm64`
- `snap` from `snapd`
- `snapcraft`
- KVM access for the VM driver — `/dev/kvm` reachable from your user

## Build with Snapcraft

Build the snap from source with the project manifest:

```shell
snapcraft pack
```

The manifest builds the Rust binaries inside Snapcraft, installs the CLI,
gateway, sandbox supervisor, and VM driver into the snap, and keeps the same
runtime environment as the current deployment logic.

## Staged helper flow

The helper task under `tasks/` still stages the same payload from pre-built
binaries when you want to inspect the snap root or produce local artifacts.

For that flow, install `mise` and build:

- `openshell`
- `openshell-gateway`
- `openshell-sandbox`

## Build helper binaries

Build the release binaries used by the staged helper flow:

```shell
mise run build:rust:snap
```

This convenience target builds the CLI with `bundled-z3`, the gateway, and
`openshell-sandbox` for the supervisor binary the VM driver injects into
sandbox guests.

## Pack the snap

Run the packaging hook through mise:

```shell
VERSION="$(uv run python tasks/scripts/release.py get-version --snap)"

OPENSHELL_CLI_BINARY="$PWD/target/release/openshell" \
OPENSHELL_GATEWAY_BINARY="$PWD/target/release/openshell-gateway" \
OPENSHELL_DOCKER_SUPERVISOR_BINARY="$PWD/target/release/openshell-sandbox" \
OPENSHELL_SNAP_VERSION="$VERSION" \
OPENSHELL_OUTPUT_DIR=artifacts \
  mise run package:snap
```

The artifact is written to `artifacts/openshell_${VERSION}_${ARCH}.snap`. The
packaging hook fails before `snap pack` if `openshell-sandbox` is missing or not
executable.

## Stage without packing

To inspect the snap root without running `snap pack`:

```shell
VERSION="$(uv run python tasks/scripts/release.py get-version --snap)"

OPENSHELL_CLI_BINARY="$PWD/target/release/openshell" \
OPENSHELL_GATEWAY_BINARY="$PWD/target/release/openshell-gateway" \
OPENSHELL_DOCKER_SUPERVISOR_BINARY="$PWD/target/release/openshell-sandbox" \
OPENSHELL_SNAP_VERSION="$VERSION" \
  mise run package:snap:stage
```

The staged root is written to `artifacts/snap-root`.

## Commands in the snap

The snap exposes the CLI:

- `openshell`

It also defines a system service.

- `openshell.gateway`

The gateway service uses `refresh-mode: endure` so snap refreshes do not restart
it while sandboxes are active. Restart the service manually when you are ready
to move the gateway to the refreshed snap revision.

The gateway app starts through a small wrapper that pins snap-specific
defaults: an on-disk SQLite database, a loopback HTTP listener at
`http://127.0.0.1:17670`, plaintext (no TLS), trusted-local user access for
that loopback endpoint, and the `vm` compute driver. The wrapper keeps the
service's XDG state and runtime directories under `$SNAP_COMMON` so the daemon
never depends on inherited host paths such as `/run/user/<uid>`. Before the
gateway starts, it also ensures the local sandbox JWT bundle exists under snap
state so sandbox supervisors can authenticate back to the gateway.

## Interfaces

The `openshell` CLI app plugs:

- `home`
- `network`
- `ssh-keys`
- `system-observe`

The `openshell.gateway` service plugs:

- `docker`
- `kvm`
- `log-observe`
- `network`
- `network-bind`
- `ssh-keys`
- `system-observe`

## Connecting after install

On first install, the snap's install hook seeds a system-level gateway entry
named `local-vm` pointing at the snap-managed loopback HTTP endpoint, and
marks it active. The CLI discovers this through `OPENSHELL_SYSTEM_GATEWAY_DIR`,
so a fresh snap is usable without any manual `openshell gateway add`.

```shell
openshell status
openshell sandbox create --name demo
openshell sandbox connect demo
```

`openshell gateway list` will show the `local-vm` entry. Per-user gateway
registrations (made with `openshell gateway add`) shadow the system entry on
name collision, so an operator wanting a different default does not need to
remove anything.

## Using user-managed gateway registrations

The snap declares a `dot-config-openshell` personal-files interface for
`~/.config/openshell`, and the CLI runs with `XDG_CONFIG_HOME` pointed at that
real home-directory config root. That keeps user-managed registrations and
imported mTLS bundles in the same location as other package formats, including
flows like the Kubernetes guide that write client TLS material into
`~/.config/openshell/gateways/<name>/mtls/`.

## Connecting Docker (optional)

The snap also declares the Docker interface. Connecting it lets the gateway
talk to a host Docker daemon if you want to switch the compute driver from
`vm` to `docker`:

```shell
sudo snap connect openshell:docker docker:docker-daemon
sudo snap set openshell drivers=docker
```

The Docker snap exposes the Docker daemon through the connected `docker`
so no `DOCKER_HOST` override is required. The OpenShell snap requires the
Docker snap because it relies on the `docker:docker-daemon` slot; it does not
work with Docker installed from a Debian package or Docker's upstream
packages.
