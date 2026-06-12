# OpenShell Apple Container Driver

This crate implements the OpenShell compute driver for Apple's `container` CLI.
It creates local macOS sandboxes as Linux containers inside Apple Container
lightweight VMs.

The driver intentionally shells out to the installed `container` CLI instead of
linking Swift or XPC APIs directly. Apple Container's public, supported operator
surface is the CLI, and the CLI exposes machine-readable JSON for the state that
OpenShell needs:

- `container system status --format json`
- `container list --all --format json`
- `container network list --format json`

The gateway must run on macOS with Apple Container installed and running. Set
`compute_drivers = ["apple-container"]` in `[openshell.gateway]`; the gateway
does not auto-detect this driver.

When `grpc_endpoint` is empty, the driver builds the supervisor callback URL
from `host_callback_host` and the gateway bind port. The default callback host
is `host.container.internal`, which Apple Container resolves inside the guest
VM. The gateway also listens on the Apple Container default network gateway
address discovered from `container network list --format json`.

Apple Container accepts integer CPU counts. OpenShell therefore rejects
per-sandbox CPU limits such as `500m` or `1.5` that cannot be passed to
`container run --cpus`.
