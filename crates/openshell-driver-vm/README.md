# openshell-driver-vm

> Status: Experimental. The VM compute driver is under active development and the interface still has VM-specific plumbing that will be generalized.

Standalone libkrun-backed [`ComputeDriver`](../../proto/compute_driver.proto) for OpenShell. The gateway spawns this binary as a subprocess, talks to it over a Unix domain socket with the `openshell.compute.v1.ComputeDriver` gRPC surface, and lets it manage per-sandbox microVMs. The runtime (libkrun + libkrunfw + gvproxy) and the sandbox supervisor are embedded directly in the binary; each sandbox guest rootfs is derived from a configured container image at create time.

## How it fits together

```mermaid
flowchart LR
    subgraph host["Host process"]
        gateway["openshell-server<br/>(compute::vm::spawn)"]
        driver["openshell-driver-vm<br/>├── libkrun (VM)<br/>├── gvproxy (net)<br/>└── openshell-sandbox.zst"]
        gateway <-->|"gRPC over UDS<br/>compute-driver.sock"| driver
    end

    subgraph guest["Per-sandbox microVM"]
        init["/srv/openshell-vm-<br/>sandbox-init.sh"]
        supervisor["/opt/openshell/bin/<br/>openshell-sandbox<br/>(PID 1)"]
        init --> supervisor
    end

    driver -->|"CreateSandbox<br/>boots via libkrun"| guest
    supervisor -.->|"gRPC callback<br/>--grpc-endpoint"| gateway

    client["openshell-cli"] -->|"SSH proxy<br/>127.0.0.1:&lt;port&gt;"| supervisor
    client -->|"CreateSandbox / Watch"| gateway
```

Sandbox guests execute `/opt/openshell/bin/openshell-sandbox` as PID 1 inside the VM. gvproxy exposes a single inbound SSH port (`host:<allocated>` → `guest:2222`) and provides virtio-net egress.

## Quick start (recommended)

```shell
mise run gateway:vm
```

First run takes a few minutes while `mise run vm:setup` stages libkrun/libkrunfw/gvproxy and `mise run vm:supervisor` builds the bundled guest supervisor. Subsequent runs are cached. To keep the Unix socket path under macOS `SUN_LEN`, `mise run gateway:vm` and `start.sh` default the state dir to `/tmp/openshell-vm-driver-dev-$USER-<repo-name>/` (SQLite DB + per-sandbox rootfs + `compute-driver.sock`) unless `OPENSHELL_VM_DRIVER_STATE_DIR` is set.
By default the wrapper names the gateway after the repo directory, writes `OPENSHELL_GATEWAY=<repo-name>` into `.env`, and writes plaintext local gateway metadata under `~/.config/openshell/gateways/<repo-name>/metadata.json` so repo-local `scripts/bin/openshell status` and `sandbox create` resolve to the VM gateway without an extra `gateway select`. When running under `sudo`, the wrapper uses `sudo -u $SUDO_USER` for the registration so the config is written under the invoking user's home directory. Re-runs are idempotent.
If neither `OPENSHELL_SERVER_PORT` nor `GATEWAY_PORT` is set, the wrapper picks a random free local port once and appends `GATEWAY_PORT=<port>` to `.env`. Later runs reuse that port through `mise`'s env loading. If you set `OPENSHELL_SERVER_PORT` explicitly, the wrapper uses it for that run and still fails fast on conflicts.
It also exports `OPENSHELL_DRIVER_DIR=$PWD/target/debug` before starting the gateway so local dev runs use the freshly built `openshell-driver-vm` instead of an older installed copy from `~/.local/libexec/openshell`, `/usr/libexec/openshell`, or `/usr/local/libexec`.

For GPU passthrough (VFIO), pass `-- --gpu` and run with root privileges:

```shell
sudo -E env "PATH=$PATH" mise run gateway:vm -- --gpu
```

See [`architecture/vm-gpu-sandbox-guide.md`](../../architecture/vm-gpu-sandbox-guide.md) for full GPU prerequisites and usage.

Override via environment:

```shell
OPENSHELL_SERVER_PORT=9090 \
crates/openshell-driver-vm/start.sh
```

If you want to pin the project port instead of using the `.env` default:

```shell
GATEWAY_PORT=28080 mise run gateway:vm
```

If you want a custom state-dir suffix instead of the repo-name default, set `OPENSHELL_VM_INSTANCE`:

```shell
GATEWAY_PORT=28081 \
OPENSHELL_VM_INSTANCE=feature-a \
mise run gateway:vm
```

If you want a custom CLI gateway name instead of the repo directory, set `OPENSHELL_VM_GATEWAY_NAME`:

```shell
GATEWAY_PORT=28082 \
OPENSHELL_VM_GATEWAY_NAME=vm-feature-a \
mise run gateway:vm
```

Teardown:

```shell
rm -rf /tmp/openshell-vm-driver-dev-$USER-$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//')
```

## Manual equivalent

If you want to drive the launch yourself instead of using `start.sh`:

```shell
# 1. Stage runtime artifacts + supervisor bundle into target/vm-runtime-compressed/
mise run vm:setup
mise run vm:supervisor          # if openshell-sandbox.zst is not already present

# 2. Build both binaries with the staged artifacts embedded
OPENSHELL_VM_RUNTIME_COMPRESSED_DIR=$PWD/target/vm-runtime-compressed \
  cargo build -p openshell-server -p openshell-driver-vm

# 3. macOS only: codesign the driver for Hypervisor.framework
codesign \
  --entitlements crates/openshell-driver-vm/entitlements.plist \
  --force -s - target/debug/openshell-driver-vm

# 4. Start the gateway with the VM driver
mkdir -p /tmp/openshell-vm-driver-dev-$USER-port-8080
target/debug/openshell-gateway \
  --drivers vm \
  --disable-tls \
  --database-url sqlite:/tmp/openshell-vm-driver-dev-$USER-port-8080/openshell.db \
  --driver-dir $PWD/target/debug \
  --sandbox-image <compatible-image> \
  --grpc-endpoint http://host.containers.internal:8080 \
  --ssh-gateway-host 127.0.0.1 \
  --ssh-gateway-port 8080 \
  --vm-driver-state-dir /tmp/openshell-vm-driver-dev-$USER-port-8080
```

The gateway resolves `openshell-driver-vm` in this order: `--driver-dir`, conventional install locations (`~/.local/libexec/openshell`, `/usr/libexec/openshell`, `/usr/local/libexec/openshell`, `/usr/local/libexec`), then a sibling of the gateway binary.

## Flags

| Flag | Env var | Default | Purpose |
|---|---|---|---|
| `--drivers vm` | `OPENSHELL_DRIVERS` | `kubernetes` | Select the VM compute driver. |
| `--grpc-endpoint URL` | `OPENSHELL_GRPC_ENDPOINT` | — | Required. URL the sandbox guest calls back to. Use a host alias that resolves to the gateway's host from inside the VM (`host.containers.internal` comes from gvproxy DNS; the guest init script also seeds `host.openshell.internal` to `192.168.127.1`). |
| `--vm-driver-state-dir DIR` | `OPENSHELL_VM_DRIVER_STATE_DIR` | `target/openshell-vm-driver` | Per-sandbox rootfs, console logs, and the `compute-driver.sock` UDS. |
| `--driver-dir DIR` | `OPENSHELL_DRIVER_DIR` | unset | Override the directory searched for `openshell-driver-vm`. |
| `--vm-driver-vcpus N` | `OPENSHELL_VM_DRIVER_VCPUS` | `2` | vCPUs per sandbox. |
| `--vm-driver-mem-mib N` | `OPENSHELL_VM_DRIVER_MEM_MIB` | `2048` | Memory per sandbox, in MiB. |
| `--vm-krun-log-level N` | `OPENSHELL_VM_KRUN_LOG_LEVEL` | `1` | libkrun verbosity (0–5). |
| `--vm-tls-ca PATH` | `OPENSHELL_VM_TLS_CA` | — | CA cert for the guest's mTLS client bundle. Required when `--grpc-endpoint` uses `https://`. |
| `--vm-tls-cert PATH` | `OPENSHELL_VM_TLS_CERT` | — | Guest client certificate. |
| `--vm-tls-key PATH` | `OPENSHELL_VM_TLS_KEY` | — | Guest client private key. |

See [`openshell-gateway --help`](../openshell-server/src/cli.rs) for the full flag surface shared with the Kubernetes driver.

## Verifying the gateway

The gateway is auto-registered by `start.sh`. In another terminal:

```shell
./scripts/bin/openshell status
./scripts/bin/openshell sandbox create --name demo --from <compatible-image>
./scripts/bin/openshell sandbox connect demo
```

First sandbox takes 10–30 seconds to boot (image fetch/prepare/cache + libkrun + guest init). If `--from` is omitted, the VM driver uses the gateway's configured default sandbox image. Without either `--from` or `--sandbox-image`, VM sandbox creation fails. Subsequent creates reuse the prepared sandbox rootfs.

## Logs and debugging

Raise log verbosity for both processes:

```shell
RUST_LOG=openshell_server=debug,openshell_driver_vm=debug \
  crates/openshell-driver-vm/start.sh
```

The VM guest's serial console is appended to `<state-dir>/<sandbox-id>/console.log`. The `compute-driver.sock` lives at `<state-dir>/compute-driver.sock`; the gateway removes it on clean shutdown via `ManagedDriverProcess::drop`.

## Prerequisites

- macOS on Apple Silicon, or Linux on aarch64/x86_64 with KVM
- Rust toolchain
- Guest-supervisor cross-compile toolchain (needed on macOS, and on Linux when host arch ≠ guest arch):
  - Matching rustup target: `rustup target add aarch64-unknown-linux-gnu` (or `x86_64-unknown-linux-gnu` for an amd64 guest)
  - `cargo install --locked cargo-zigbuild` and `brew install zig` (or distro equivalent). `vm:supervisor` uses `cargo zigbuild` to cross-compile the in-VM `openshell-sandbox` supervisor binary.
- [mise](https://mise.jdx.dev/) task runner
- Docker-compatible socket on the CLI host when using `openshell sandbox create --from ./Dockerfile` or `--from ./dir`
- `gh` CLI (used by `mise run vm:setup` to download pre-built runtime artifacts)

## Relationship to `openshell-vm`

`openshell-vm` is a separate, legacy crate that runs the **whole OpenShell gateway inside a single VM**. `openshell-driver-vm` is the compute driver called by a host-resident gateway to spawn **per-sandbox VMs**. Both embed libkrun but share no Rust code — the driver vendors its own rootfs handling and runtime loader so `openshell-server` never has to link libkrun.

## TODOs

- The gateway still configures the driver via CLI args; this will move to a gRPC bootstrap call so the driver interface is uniform across backends. See the `TODO(driver-abstraction)` notes in `crates/openshell-server/src/lib.rs` and `crates/openshell-server/src/compute/vm.rs`.
- macOS codesigning is handled by `start.sh`; a packaged release would need signing in CI.
