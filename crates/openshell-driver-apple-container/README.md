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
`compute_driver = "apple-container"` in `[openshell.gateway]`; the gateway
does not auto-detect this driver.

When `grpc_endpoint` is empty, the driver builds the supervisor callback URL
from `host_callback_host` and the gateway bind port. The default callback host
is `host.container.internal`, which Apple Container resolves inside the guest
VM. The gateway also listens on the Apple Container default network gateway
address discovered from `container network list --format json`.

Apple Container accepts integer CPU counts. OpenShell therefore rejects
per-sandbox CPU limits such as `500m` or `1.5` that cannot be passed to
`container run --cpus`.

## Building the Linux supervisor binary

The driver bind-mounts `supervisor_bin_dir` into the sandbox guest at
`/opt/openshell/bin`. That directory must contain a **Linux** build of
`openshell-sandbox` for the guest's architecture; shipping the macOS binary
fails the launch with `Exec format error`.

On an Apple Silicon host, cross-compile for the ARM64 guest:

```sh
rustup target add aarch64-unknown-linux-musl
brew install filosottile/musl-cross/musl-cross
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc \
  cargo build --release -p openshell-sandbox --target aarch64-unknown-linux-musl
install -m 0755 target/aarch64-unknown-linux-musl/release/openshell-sandbox \
  /path/to/supervisor-bin/openshell-sandbox
```

(The linker override belongs in `~/.cargo/config.toml` or the `CARGO_TARGET_*`
env var — not the project `.cargo/config.toml`, which is for OpenShell-internal
settings like z3.)
