# openshell-vm

> Status: Legacy. This crate remains in the repository for later deprecation or
> removal, but it is excluded from normal workspace builds, CI, and release
> paths. Active VM sandbox work lives in `crates/openshell-driver-vm`.

MicroVM runtime for OpenShell, powered by [libkrun](https://github.com/containers/libkrun). Boots a lightweight ARM64 Linux VM on macOS (Apple Hypervisor.framework) or Linux (KVM) running a single-node k3s cluster with the OpenShell control plane.

## Current Path

Use `mise run gateway:vm` for the supported per-sandbox VM driver workflow. The
standalone `openshell-vm` tasks and wrappers are intentionally not part of the
normal task surface.

## Prerequisites

- **macOS (Apple Silicon)** or **Linux (aarch64 or x86_64 with KVM)**
- Rust toolchain
- Guest-supervisor cross-compile toolchain (needed on macOS, and on Linux when host arch ≠ guest arch):
  - Matching rustup target: `rustup target add aarch64-unknown-linux-gnu` (or `x86_64-unknown-linux-gnu` for an amd64 guest)
  - `cargo install --locked cargo-zigbuild` and `brew install zig` (or distro equivalent). `build-rootfs.sh` uses `cargo zigbuild` to cross-compile the in-VM `openshell-sandbox` supervisor binary.
- [mise](https://mise.jdx.dev/) task runner
- Docker (for rootfs builds)
- `gh` CLI (for downloading pre-built runtime)

### macOS-Specific

The binary must be codesigned with the Hypervisor.framework entitlement. To
codesign manually:

```bash
codesign --entitlements crates/openshell-vm/entitlements.plist --force -s - target/debug/openshell-vm
```

## Setup

### Download Pre-Built Runtime (Default)

Downloads libkrun, libkrunfw, and gvproxy from the `vm-runtime` GitHub Release for
the active VM driver runtime:

```bash
mise run vm:setup
```

### Build from Source

Compiles the runtime from source (15-45 minutes, needed for custom kernel work):

```bash
FROM_SOURCE=1 mise run vm:setup
```

On macOS this builds a custom libkrunfw (kernel firmware with bridge/netfilter support) via `krunvm`, then builds a portable libkrun. On Linux it builds both natively.

## Build

There is no first-class `mise` build task for the standalone binary. This crate
is no longer part of normal CI or release builds.

## Rootfs

The legacy rootfs scripts are kept with this crate for historical reference.
They are not used by `openshell-driver-vm`, which derives each sandbox guest
rootfs from a container image at create time.

## Run

### Default (Gateway Mode)

Boots the full OpenShell gateway -- k3s + openshell-server + openshell-sandbox:

Run the binary directly after manually building and signing it:

```bash
./target/debug/openshell-vm
```

### Custom Process

Run an arbitrary process inside a fresh VM instead of k3s:

```bash
./target/debug/openshell-vm --exec /bin/sh --vcpus 2 --mem 2048
```

### Execute in a Running VM

Attach to a running VM and run a command:

```bash
./target/debug/openshell-vm exec -- ls /
./target/debug/openshell-vm exec -- sh   # interactive shell
```

### Named Instances

Run multiple isolated VM instances side-by-side:

```bash
./target/debug/openshell-vm --name dev
./target/debug/openshell-vm --name staging
```

Each instance gets its own extracted rootfs under `~/.local/share/openshell/openshell-vm/<version>/instances/<name>/rootfs`.

## CLI Reference

```text
openshell-vm [OPTIONS] [COMMAND]

Options:
  --rootfs <PATH>          Path to aarch64 Linux rootfs directory
  --name <NAME>            Named VM instance (auto-clones rootfs)
  --exec <PATH>            Run a custom process instead of k3s
  --args <ARGS>...         Arguments to the executable
  --env <KEY=VALUE>...     Environment variables
  --workdir <DIR>          Working directory inside the VM [default: /]
  -p, --port <H:G>...     Port mappings (host_port:guest_port)
  --vcpus <N>              Virtual CPUs [default: 4 gateway, 2 exec]
  --mem <MiB>              RAM in MiB [default: 8192 gateway, 2048 exec]
  --krun-log-level <0-5>   libkrun log level [default: 1]
  --net <BACKEND>          Networking: gvproxy, tsi, none [default: gvproxy]
  --reset                  Wipe runtime state before booting

Subcommands:
  prepare-rootfs           Ensure the target rootfs exists
  exec                     Execute a command inside a running VM
```

## Tasks

Standalone `openshell-vm` tasks have been removed from the normal task surface.
The remaining VM tasks (`vm:setup`, `vm:supervisor`, `gateway:vm`, `e2e:vm`,
and `vm:smoke:orphan-cleanup`) support `openshell-driver-vm`.

## Architecture

```text
Host (macOS / Linux)
  openshell-vm binary
    |-- Embedded runtime (libkrun, libkrunfw, gvproxy, rootfs.tar.zst)
    |-- FFI: loads libkrun at runtime via dlopen
    |-- gvproxy: virtio-net networking (real eth0 + DHCP)
    |-- virtio-fs: shares rootfs with guest
    \-- vsock: host-to-guest command execution (port 10777)

Guest VM (aarch64 Linux)
  PID 1: openshell-vm-init.sh
    |-- Mounts filesystems, configures networking
    |-- Sets up bridge CNI, generates PKI
    \-- Execs k3s server
        |-- openshell-server (gateway control plane)
        \-- openshell-sandbox (pod supervisor)
```

## Environment Variables

| Variable | When | Purpose |
|----------|------|---------|
| `OPENSHELL_VM_RUNTIME_COMPRESSED_DIR` | Build time | Path to compressed runtime artifacts |
| `OPENSHELL_VM_RUNTIME_DIR` | Runtime | Override the runtime bundle directory |
| `OPENSHELL_VM_DIAG=1` | Runtime | Enable diagnostic output inside the VM |
| `FROM_SOURCE=1` | `vm:setup` | Build runtime from source instead of downloading |

## Custom Kernel (libkrunfw)

The stock libkrunfw (e.g. from Homebrew) lacks bridge, netfilter, and conntrack support needed for pod networking. OpenShell builds a custom libkrunfw with these enabled.

Build it via the setup command:

```bash
FROM_SOURCE=1 mise run vm:setup
```

See [`runtime/README.md`](runtime/README.md) for details on the kernel config and troubleshooting.

## Testing

Integration tests require a built rootfs and macOS ARM64 with libkrun:

```bash
cargo test -p openshell-vm -- --ignored
```

Individual tests:

```bash
# Full gateway boot test (boots VM, waits for gRPC on port 30051)
cargo test -p openshell-vm gateway_boots -- --ignored

# Run a command inside the VM
cargo test -p openshell-vm gateway_exec_runs -- --ignored

# Exec into a running VM
cargo test -p openshell-vm gateway_exec_attaches -- --ignored
```

Verify kernel capabilities inside a running VM:

```bash
./target/debug/openshell-vm exec -- /srv/check-vm-capabilities.sh
./target/debug/openshell-vm exec -- /srv/check-vm-capabilities.sh --json
```
