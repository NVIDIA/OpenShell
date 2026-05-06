# Custom libkrunfw VM Runtime

> Status: Experimental and work in progress (WIP). The VM compute driver is
> under active development and may change.

## Overview

The OpenShell gateway uses [libkrun](https://github.com/containers/libkrun) via the
`openshell-driver-vm` compute driver to boot a lightweight microVM per sandbox.
Each VM runs on Apple Hypervisor.framework (macOS) or KVM (Linux), with the guest
kernel embedded inside `libkrunfw`.

The stock `libkrunfw` from Homebrew ships a minimal kernel without bridge,
netfilter, or conntrack support. That is insufficient for the sandbox supervisor's
per-sandbox network namespace primitives (veth pair + iptables, see
`crates/openshell-sandbox/src/sandbox/linux/netns.rs`). The custom libkrunfw
runtime adds bridge, iptables/nftables, and conntrack support to the guest
kernel.

The driver is spawned by `openshell-gateway` as a subprocess, talks to it over a
Unix domain socket (`compute-driver.sock`) with the
`openshell.compute.v1.ComputeDriver` gRPC surface, and manages per-sandbox
microVMs. The runtime (libkrun + libkrunfw + gvproxy) and the sandbox
supervisor are embedded directly in the driver binary; each sandbox guest
rootfs is derived from a container image at create time.

## Architecture

```mermaid
graph TD
    subgraph Host["Host (macOS / Linux)"]
        GATEWAY["openshell-gateway<br/>(compute::vm::spawn)"]
        DRIVER["openshell-driver-vm<br/>(compute-driver.sock)"]
        EMB["Embedded runtime (zstd)<br/>libkrun · libkrunfw · gvproxy<br/>+ openshell-sandbox.zst"]
        GVP["gvproxy (per sandbox)<br/>virtio-net · DHCP · DNS"]

        GATEWAY <-->|gRPC over UDS| DRIVER
        DRIVER --> EMB
        DRIVER -->|spawns one per sandbox| GVP
    end

    subgraph Guest["Per-sandbox microVM"]
        SBXINIT["/srv/openshell-vm-sandbox-init.sh"]
        SBX["/opt/openshell/bin/openshell-sandbox<br/>(PID 1, supervisor)"]
        SBXINIT --> SBX
    end

    DRIVER -- "fork + krun_start_enter" --> SBXINIT
    GVP -- "virtio-net eth0" --> Guest
    SBX -.->|"outbound ConnectSupervisor<br/>gRPC stream"| GATEWAY
    CLIENT["openshell-cli"] -->|SSH over supervisor relay| GATEWAY
```

The driver spawns **one microVM per sandbox**. Each VM boots directly into
`openshell-sandbox` as PID 1. All gateway ingress — SSH, exec, connect — rides
the supervisor-initiated `ConnectSupervisor` gRPC stream opened from inside the
guest back out to the gateway, so gvproxy is configured with `-ssh-port -1` and
never binds a host-side TCP listener.

## Embedded Runtime

`openshell-driver-vm` embeds the VM runtime libraries and the sandbox
supervisor as zstd-compressed byte arrays, extracting on demand:

```text
~/.local/share/openshell/vm-runtime/<version>/        # libkrun / libkrunfw / gvproxy
├── libkrun.{dylib,so}
├── libkrunfw.{5.dylib,so.5}
└── gvproxy

<state-dir>/sandboxes/<sandbox-id>/rootfs/            # per-sandbox rootfs
```

Old runtime cache versions are cleaned up when a new version is extracted.

### Sandbox rootfs preparation

Each VM sandbox starts from either a registry image fetched directly over OCI or
a local Docker image reference produced by Dockerfile-based `--from` sources.
For local Dockerfile sources, the CLI builds the image on the local Docker
daemon and passes the ordinary image tag through `template.image`. The VM driver
first checks the local Docker daemon for that tag; when present, it exports the
image filesystem and **rewrites that filesystem into a supervisor-only sandbox
guest** before caching it:

- `/srv/openshell-vm-sandbox-init.sh` is installed as the guest entrypoint
- the bundled `openshell-sandbox` binary is copied into
  `/opt/openshell/bin/openshell-sandbox`
- Kubernetes state and manifests are stripped out if the image contains them
- the guest boots directly into `openshell-sandbox` -- no Kubernetes control
  plane, no kube-proxy, no CNI plugins

See `crates/openshell-driver-vm/src/rootfs.rs` for the rewrite logic and
`crates/openshell-driver-vm/scripts/openshell-vm-sandbox-init.sh` for the init
script that gets installed.

### `--internal-run-vm` helper

The driver binary has two modes: the default mode is the gRPC server; when
launched with `--internal-run-vm` it becomes a per-sandbox launcher. The driver
spawns one launcher per sandbox as a subprocess, which in turn starts `gvproxy`
and calls `krun_start_enter` to boot the guest. Keeping the launcher in the
same binary means the driver ships a single artifact for both roles.

When a sandbox sets `template.image` through `openshell sandbox create --from ...`,
the VM driver treats that image as the base guest rootfs source for that
sandbox. When `template.image` is omitted, the gateway fills it from the VM
driver's advertised `default_image`, which matches the gateway's configured
sandbox image. The driver:

- resolves the image on the gateway host without Docker for registry and
  community image refs
- for local Dockerfile sources, the CLI builds through the host Docker socket
  and passes the resulting ordinary Docker tag through `template.image`
- unpacks the image filesystem, injects the VM sandbox init/supervisor files,
  and validates required guest tools such as `bash`, `mount`, `ip`, and `sed`
- caches the prepared guest rootfs under
  `<vm-driver-state-dir>/images/<image-identity>/rootfs.tar`
- extracts a private runtime copy under
  `<vm-driver-state-dir>/sandboxes/<sandbox-id>/rootfs`

The cache key uses an immutable image identity: repo digest for registry images
and the local Docker image ID for images resolved from the local daemon.
Different VM sandboxes can use different base images concurrently because the
shared cache is per image, not global for the driver. Cached prepared rootfs
entries remain on disk until the operator removes them from the VM driver state
directory.

Docker is therefore no longer required for VM sandboxes created from registry or
community image refs. It is only required on the local CLI/gateway host when the
source is a local Dockerfile or build context.

Local Dockerfile sources are treated as trusted local-development inputs for VM
gateways. Remote VM gateways still reject local Dockerfile sources until a
gateway-side artifact validation and transfer boundary is designed.

There is no embedded guest rootfs fallback anymore. VM sandboxes therefore
require either `template.image` or a configured default sandbox image. This is
still replace-the-rootfs semantics, so VM images must remain base-compatible
with the sandbox guest init path. Distroless or `scratch` images are not
expected to work.

The legacy `openshell-vm` crate remains in the repository for later
deprecation, but it is excluded from the normal workspace and release paths.
`openshell-driver-vm` owns active VM runtime build inputs.

## Network Plane

The driver launches a **dedicated `gvproxy` instance per sandbox** to provide the
guest's networking plane:

- virtio-net backend over a Unix SOCK_STREAM (Linux) or SOCK_DGRAM (macOS vfkit)
  socket, which surfaces as `eth0` inside the guest
- DHCP server + default router (192.168.127.1 / 192.168.127.2) for the guest's
  udhcpc client
- DNS for host aliases: the guest init script seeds `/etc/hosts` with
  `host.openshell.internal` → 192.168.127.1, while leaving gvproxy's legacy
  `host.containers.internal` / `host.docker.internal` resolution intact

The `-listen` API socket and the `-ssh-port` forwarder are both intentionally
omitted. After the supervisor-initiated relay migration the driver does not
enqueue any host-side port forwards, and the guest's SSH listener lives on a
Unix socket at `/run/openshell/ssh.sock` inside the VM that is reached over the
outbound `ConnectSupervisor` gRPC stream. Binding a host listener would race
concurrent sandboxes for port 2222 and surface a misleading "sshd is reachable"
endpoint.

The sandbox supervisor's per-sandbox netns (veth pair + iptables) branches off
of this plane. libkrun's built-in TSI socket impersonation would not satisfy
those kernel-level primitives, which is why we need the custom libkrunfw.

## Process Lifecycle Cleanup

`openshell-driver-vm` installs a cross-platform "die when my parent dies"
primitive (`procguard`) in every link of the spawn chain so that killing
`openshell-gateway` (SIGTERM, SIGKILL, or crash) reaps the driver, per-sandbox
launcher, gvproxy, and the libkrun worker:

- Linux: `nix::sys::prctl::set_pdeathsig(SIGKILL)`
- macOS / BSDs: `smol-rs/polling` with `ProcessOps::Exit` on a helper thread
- gvproxy (the one non-Rust child) gets `PR_SET_PDEATHSIG` via `pre_exec` on
  Linux, and is SIGTERM'd from the launcher's procguard cleanup callback on
  macOS

See `crates/openshell-driver-vm/src/procguard.rs` for the implementation and
`tasks/scripts/vm/smoke-orphan-cleanup.sh` (exposed as
`mise run vm:smoke:orphan-cleanup`) for the regression test that covers both
SIGTERM and SIGKILL paths.

## Runtime Provenance

At driver startup the loaded runtime bundle is logged with:

- Library paths and SHA-256 hashes
- Whether the runtime is custom-built or stock
- For custom runtimes: libkrunfw commit, kernel version, build timestamp

This information is sourced from `provenance.json` (generated by the build
script) and makes it straightforward to correlate sandbox VM behavior with a
specific runtime artifact.

## Build Pipeline

```mermaid
graph LR
    subgraph Source["crates/openshell-driver-vm/runtime/"]
        KCONF["kernel/openshell.kconfig<br/>Kernel config fragment"]
    end

    subgraph Linux["Linux CI (build-libkrun.sh)"]
        BUILD_L["Build kernel + libkrunfw.so + libkrun.so"]
    end

    subgraph macOS["macOS CI (build-libkrun-macos.sh)"]
        BUILD_M["Build libkrunfw.dylib + libkrun.dylib"]
    end

    subgraph Output["vm-runtime-&lt;platform&gt;.tar.zst"]
        LIB_SO["libkrunfw.so + libkrun.so + gvproxy<br/>(Linux)"]
        LIB_DY["libkrunfw.dylib + libkrun.dylib + gvproxy<br/>(macOS)"]
    end

    KCONF --> BUILD_L --> LIB_SO
    KCONF --> BUILD_M --> LIB_DY
```

The `vm-runtime-<platform>.tar.zst` artifact is consumed by
`openshell-driver-vm`'s `build.rs`, which embeds the library set into the
binary via `include_bytes!()`. Setting `OPENSHELL_VM_RUNTIME_COMPRESSED_DIR`
at build time (wired up by `tasks/scripts/gateway-vm.sh`, registered as
`mise run gateway:vm`) points the build at the staged artifacts.

## Kernel Config Fragment

The `openshell.kconfig` fragment enables these kernel features on top of the
stock libkrunfw kernel:

| Feature | Key Configs | Purpose |
|---------|-------------|---------|
| Network namespaces | `CONFIG_NET_NS`, `CONFIG_NAMESPACES` | Sandbox netns isolation |
| veth | `CONFIG_VETH` | Sandbox network namespace pairs |
| Bridge device | `CONFIG_BRIDGE`, `CONFIG_BRIDGE_NETFILTER` | Bridge support + iptables visibility into bridge traffic |
| Netfilter framework | `CONFIG_NETFILTER`, `CONFIG_NETFILTER_ADVANCED`, `CONFIG_NETFILTER_XTABLES` | iptables/nftables framework |
| xtables match modules | `CONFIG_NETFILTER_XT_MATCH_CONNTRACK`, `_COMMENT`, `_MULTIPORT`, `_MARK`, `_STATISTIC`, `_ADDRTYPE`, `_RECENT`, `_LIMIT` | Sandbox supervisor iptables rules |
| Connection tracking | `CONFIG_NF_CONNTRACK`, `CONFIG_NF_CT_NETLINK` | NAT state tracking |
| NAT | `CONFIG_NF_NAT` | Sandbox egress DNAT/SNAT |
| iptables | `CONFIG_IP_NF_IPTABLES`, `CONFIG_IP_NF_FILTER`, `CONFIG_IP_NF_NAT`, `CONFIG_IP_NF_MANGLE` | Masquerade and compat |
| nftables | `CONFIG_NF_TABLES`, `CONFIG_NFT_CT`, `CONFIG_NFT_NAT`, `CONFIG_NFT_MASQ`, `CONFIG_NFT_NUMGEN`, `CONFIG_NFT_FIB_IPV4` | nftables path |
| IP forwarding | `CONFIG_IP_ADVANCED_ROUTER`, `CONFIG_IP_MULTIPLE_TABLES` | Sandbox-to-host routing |
| Traffic control | `CONFIG_NET_SCH_HTB`, `CONFIG_NET_CLS_CGROUP` | QoS |
| Cgroups | `CONFIG_CGROUPS`, `CONFIG_CGROUP_DEVICE`, `CONFIG_MEMCG`, `CONFIG_CGROUP_PIDS` | Sandbox resource limits |
| TUN/TAP | `CONFIG_TUN` | CNI plugin compatibility; inherited from the shared kconfig, not exercised by the driver. |
| Dummy interface | `CONFIG_DUMMY` | Fallback networking |
| Landlock | `CONFIG_SECURITY_LANDLOCK` | Sandbox supervisor filesystem sandboxing |
| Seccomp filter | `CONFIG_SECCOMP_FILTER` | Sandbox supervisor syscall filtering |

See `crates/openshell-driver-vm/runtime/kernel/openshell.kconfig` for the full
fragment with inline comments explaining why each option is needed.

## Verification

- **Capability checker** (`check-vm-capabilities.sh`): runs inside a sandbox VM
  to verify kernel capabilities. Produces pass/fail results for each required
  feature.
- **Orphan-cleanup smoke test**: `mise run vm:smoke:orphan-cleanup` asserts
  that killing the gateway leaves zero driver, launcher, gvproxy, or libkrun
  survivors.

## Build Commands

```shell
# One-time setup: download pre-built runtime (~30s)
mise run vm:setup

# Start openshell-gateway with the VM compute driver
mise run gateway:vm

# With custom kernel (optional, adds ~20 min)
FROM_SOURCE=1 mise run vm:setup

# Remove the staged compressed runtime when you need a clean rebuild
rm -rf target/vm-runtime-compressed
```

See `crates/openshell-driver-vm/README.md` for the full driver workflow,
including multi-gateway development, CLI registration, and sandbox creation
examples.

## CI/CD

The driver release path is split between on-demand runtime builds and normal
OpenShell releases:

### Kernel Runtime (`release-vm-kernel.yml`)

Builds the custom libkrunfw (kernel firmware), libkrun (VMM), and gvproxy for
all supported platforms. Run it on demand when the kernel config or pinned
versions change.

| Platform | Runner | Build Method |
|----------|--------|-------------|
| Linux ARM64 | `linux-arm64-cpu8` | Native `build-libkrun.sh` |
| Linux x86_64 | `linux-amd64-cpu8` | Native `build-libkrun.sh` |
| macOS ARM64 | `macos-latest-xlarge` (GitHub-hosted) | `build-libkrun-macos.sh` |

Artifacts: `vm-runtime-{platform}.tar.zst` containing libkrun, libkrunfw,
gvproxy, and provenance metadata. Each platform builds its own libkrunfw and
libkrun natively; the kernel inside libkrunfw is always Linux regardless of
host platform. The workflow publishes GitHub artifact attestations for each
runtime tarball instead of a separate runtime checksum file.

### Driver Binary (`release-dev.yml` / `release-tag.yml`)

Builds the self-contained `openshell-driver-vm` binary for every platform,
with the kernel runtime + bundled sandbox supervisor embedded. Development
driver binaries are published to the rolling `dev` release; tagged driver
binaries are published to the corresponding `v*` release.

The reusable driver workflows pull the current `vm-runtime-<platform>.tar.zst`
from the `vm-runtime` release; their build jobs set
`OPENSHELL_VM_RUNTIME_COMPRESSED_DIR=$PWD/target/vm-runtime-compressed` and
run `cargo build --release -p openshell-driver-vm`. The macOS driver is
cross-compiled via osxcross (no macOS runner needed for the binary build —
only for the kernel build).

macOS driver binaries produced via osxcross are not codesigned. Local
development builds are signed automatically by `tasks/scripts/gateway-vm.sh`
(registered as `mise run gateway:vm`). Release tarball users on macOS must
ad-hoc sign `openshell-driver-vm` before running VM sandboxes.

## Rollout Strategy

1. Custom runtime is embedded by default when building `openshell-driver-vm`
   with `OPENSHELL_VM_RUNTIME_COMPRESSED_DIR` set (wired up by
   `tasks/scripts/gateway-vm.sh`).
2. The sandbox init script validates kernel capabilities at boot and fails
   fast if missing.
3. For development, override with `OPENSHELL_VM_RUNTIME_DIR` to use a local
   directory instead of the extracted cache.
4. In CI, the kernel runtime is pre-built and cached in the `vm-runtime` release.
   Dev and tagged release builds download that runtime, embed it into
   `openshell-driver-vm`, and publish the driver next to `openshell-gateway`.
