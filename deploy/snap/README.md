# Building a snap package

OpenShell snap packages are defined by the root `snapcraft.yaml` and built with
Snapcraft from source.

The helper task under `tasks/` still stages the same payload from pre-built
binaries when you want to inspect the snap root or produce local artifacts.

## Prerequisites

- Linux on `amd64` or `arm64`
- `snap` from `snapd`
- `snapcraft`
- Docker from the Docker snap (`sudo snap install docker`)

## Build with Snapcraft

Build the snap from source with the root manifest:

```shell
snapcraft pack
```

The manifest builds the Rust binaries inside Snapcraft, installs the CLI,
gateway, and sandbox supervisor into the snap, and keeps the same runtime
environment as the current deployment logic.

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
`openshell-sandbox` for the Docker driver to bind-mount into sandbox containers.

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

It also defines a system service running the gateway with the Docker driver.

- `openshell.gateway`

The gateway service uses `refresh-mode: endure` so snap refreshes do not restart
it while sandboxes are active. Restart the service manually when you are ready
to move the gateway to the refreshed snap revision.

`openshell-sandbox` is staged next to `openshell-gateway` as the Docker
supervisor binary. The gateway app passes it to the in-process Docker driver
through `OPENSHELL_DOCKER_SUPERVISOR_BIN=$SNAP/bin/openshell-sandbox`. The
service stores its gateway database under `$SNAP_COMMON`.

## Interfaces

The `openshell` CLI app plugs:

- `home`
- `network`
- `ssh-keys`
- `system-observe`

The `openshell.gateway` service plugs:

- `docker`
- `log-observe`
- `network`
- `network-bind`
- `ssh-keys`
- `system-observe`

## Start a Docker gateway from the snap

The snapped gateway talks to Docker through the Docker snap's
`docker:docker-daemon` slot. The snap declares `default-provider: docker` on
its Docker plug so snapd can install the Docker snap when OpenShell is
installed. Connect the interface before using the Docker driver:

```shell
sudo snap connect openshell:docker docker:docker-daemon
sudo snap connect openshell:log-observe
sudo snap connect openshell:system-observe
sudo snap connect openshell:ssh-keys
```

The gateway uses Docker's default Unix socket location. The Docker snap exposes
that socket through the connected `docker` interface, so no `DOCKER_HOST`
override is required. The OpenShell snap still requires the Docker snap because
it relies on the `docker:docker-daemon` slot; it does not work with Docker
installed from a Debian package or Docker's upstream packages.

The service runs the gateway with the Docker driver enabled:

```shell
openshell.gateway \
  --drivers docker \
  --disable-tls \
  --port 17670 \
  --db-url "sqlite:$SNAP_COMMON/gateway.db?mode=rwc" \
  --docker-supervisor-bin "$SNAP/bin/openshell-sandbox" \
  --docker-network-name openshell-snap \
  --sandbox-namespace docker-snap \
  --sandbox-image ghcr.io/nvidia/openshell-community/sandboxes/base:latest \
  --sandbox-image-pull-policy IfNotPresent \
  --grpc-endpoint http://host.openshell.internal:17670
```

This stores the gateway SQLite database at
`/var/snap/openshell/common/gateway.db`.

## Connect with the OpenShell CLI

Register the snap-run gateway as a local plaintext gateway:

```shell
openshell gateway add http://127.0.0.1:17670 --local --name snap-docker
openshell gateway select snap-docker
openshell status
```

Then use normal sandbox commands:

```shell
openshell sandbox create --name demo
openshell sandbox connect demo
```

To avoid changing the default gateway, pass the gateway name per command:

```shell
openshell --gateway snap-docker status
openshell --gateway snap-docker sandbox create --name demo
```
