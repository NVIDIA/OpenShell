# Custom VM Runtime

> Status: Experimental and work in progress (WIP). VM support is under active development and may change.

## Overview

The OpenShell gateway VM supports two hypervisor backends:

- **libkrun** (default) — lightweight VMM using Apple Hypervisor.framework (macOS) or KVM
  (Linux). The kernel is embedded inside `libkrunfw`. Uses virtio-MMIO device transport and
  gvproxy for user-space networking.
- **cloud-hypervisor** — Linux-only KVM-based VMM used for GPU passthrough (VFIO). Uses
  virtio-PCI device transport, TAP networking, and requires a separate `vmlinux` kernel and
  `virtiofsd` for rootfs access.

Backend selection is automatic: `--gpu` selects cloud-hypervisor, otherwise libkrun is used.
The `--backend` flag provides explicit control (`auto`, `libkrun`, `cloud-hypervisor`).

When `--gpu` is passed, `openshell-vm` automatically binds an eligible GPU to `vfio-pci`
and restores it to the original driver on shutdown. See
[vm-gpu-passthrough.md](vm-gpu-passthrough.md) for the full lifecycle description.

Both backends share the same guest kernel (built from a single `openshell.kconfig` fragment)
and rootfs.

The stock `libkrunfw` from Homebrew ships a minimal kernel without bridge, netfilter, or
conntrack support. This is insufficient for Kubernetes pod networking. The custom kconfig
adds bridge CNI, iptables/nftables, conntrack, and cloud-hypervisor compatibility.

## Architecture

```mermaid
graph TD
    subgraph Host["Host (macOS / Linux)"]
        BIN[openshell-vm binary]
        EMB["Embedded runtime (zstd-compressed)\nlibkrun · libkrunfw · gvproxy · rootfs"]
        CACHE["~/.local/share/openshell/vm-runtime/{version}/"]
        PROV[Runtime provenance logging]
        GVP[gvproxy networking proxy]
        CHV_BIN["cloud-hypervisor · virtiofsd · vmlinux\n(GPU runtime bundle)"]

        BIN --> EMB
        BIN -->|extracts to| CACHE
        BIN --> PROV
        BIN -->|spawns| GVP
    end

    subgraph Guest["Guest VM"]
        INIT["openshell-vm-init.sh (PID 1)"]
        VAL[Validates kernel capabilities]
        CNI[Configures bridge CNI]
        EXECA["Starts exec agent\nvsock port 10777"]
        PKI[Generates mTLS PKI]
        K3S[Execs k3s server]
        EXECPY["openshell-vm-exec-agent.py"]
        CHK["check-vm-capabilities.sh"]

        INIT --> VAL --> CNI --> EXECA --> PKI --> K3S
    end

    BIN -- "libkrun: fork + krun_start_enter" --> INIT
    BIN -- "CHV: cloud-hypervisor API + virtiofsd" --> INIT
    GVP -- "virtio-net (libkrun only)" --> Guest
```

## Embedded Runtime

The openshell-vm binary is fully self-contained, embedding both the VM runtime libraries
and a minimal rootfs as zstd-compressed byte arrays. On first use, the binary extracts
these to XDG cache directories with progress bars:

```
~/.local/share/openshell/vm-runtime/{version}/
├── libkrun.{dylib,so}
├── libkrunfw.{5.dylib,so.5}
└── gvproxy

~/.local/share/openshell/openshell-vm/{version}/instances/<name>/rootfs/
├── usr/local/bin/k3s
├── opt/openshell/bin/openshell-sandbox
├── opt/openshell/manifests/
└── ...
```

When using cloud-hypervisor, an additional runtime bundle is required alongside the
binary:

```
target/debug/openshell-vm.runtime/    (or alongside the installed binary)
├── cloud-hypervisor                   # CHV binary
├── virtiofsd                          # virtio-fs daemon
└── vmlinux                            # extracted guest kernel
```

This bundle is built with `mise run vm:bundle-runtime` and is separate from the
embedded runtime because CHV and virtiofsd are Linux-only and not embedded in the
self-extracting binary.

This eliminates the need for separate bundles or downloads for the default (libkrun)
path — a single ~120MB binary provides everything needed. Old cache versions are
automatically cleaned up when a new version is extracted.

### Hybrid Approach

The embedded rootfs uses a "minimal" configuration:
- Includes: Base Ubuntu, k3s binary, supervisor binary, helm charts, manifests
- Excludes: Pre-loaded container images (~1GB savings)

Container images are pulled on demand when sandboxes are created. First boot takes
~30-60s as k3s initializes; subsequent boots use cached state for ~3-5s startup.

For fully air-gapped environments requiring pre-loaded images, build with:
```bash
mise run vm:rootfs                 # Full rootfs (~2GB, includes images)
mise run vm:build                  # Rebuild binary with full rootfs
```

## Backend Comparison

| | libkrun (default) | cloud-hypervisor |
|---|---|---|
| Platforms | macOS (Hypervisor.framework), Linux (KVM) | Linux (KVM) only |
| Device transport | virtio-MMIO | virtio-PCI |
| Networking | gvproxy (user-space, no root needed) | TAP (requires root/CAP_NET_ADMIN) |
| Rootfs delivery | In-process (krun API) | virtiofsd (virtio-fs daemon) |
| Kernel delivery | Embedded in libkrunfw | Separate `vmlinux` file |
| Console | virtio-console (`hvc0`) | 8250 UART (`ttyS0`) |
| Shutdown | Automatic on PID 1 exit | ACPI poweroff (`poweroff -f`) |
| GPU passthrough | Not supported | VFIO PCI passthrough |
| `--exec` mode | Direct init replacement | Wrapper script with ACPI shutdown |
| CLI flag | `--backend libkrun` | `--backend cloud-hypervisor` or `--gpu` |

### Exec mode differences

With libkrun, when `--exec <cmd>` is used, the command replaces the init process and
the VM exits when PID 1 exits.

With cloud-hypervisor, the VM does not automatically exit when PID 1 terminates. A
wrapper init script is dynamically written to the guest rootfs that mounts necessary
filesystems, executes the user command, captures the exit code, and calls
`poweroff -f` to trigger an ACPI shutdown that cloud-hypervisor detects.

## Network Profile

The VM uses the bridge CNI profile, which requires a custom libkrunfw with bridge and
netfilter kernel support. The init script validates these capabilities at boot and fails
fast with an actionable error if they are missing.

### Bridge Profile

- CNI: bridge plugin with `cni0` interface
- IP masquerade: enabled (iptables-legacy via CNI bridge plugin)
- kube-proxy: enabled (nftables mode)
- Service VIPs: functional (ClusterIP, NodePort)
- hostNetwork workarounds: not required

### Networking by backend

- **libkrun**: Uses gvproxy for user-space virtio-net networking. No root privileges
  needed. Port forwarding is handled via gvproxy configuration.
- **cloud-hypervisor**: Uses TAP networking (requires root or CAP_NET_ADMIN). When
  `--net none` is passed, networking is disabled entirely (useful for `--exec` mode
  tests). gvproxy is not used with cloud-hypervisor.

## Guest Init Script

The init script (`openshell-vm-init.sh`) runs as PID 1 in the guest. After mounting essential filesystems, it performs:

1. **Kernel cmdline parsing** — exports environment variables passed via the kernel command line (`GPU_ENABLED`, `OPENSHELL_VM_STATE_DISK_DEVICE`, `VM_NET_IP`, `VM_NET_GW`, `VM_NET_DNS`). This runs after `/proc` is mounted so `/proc/cmdline` is available.

2. **Cgroup v2 controller enablement** — enables `cpu`, `cpuset`, `memory`, `pids`, and `io` controllers in the root cgroup hierarchy (`cgroup.subtree_control`). k3s/kubelet requires these controllers; the `cpu` controller depends on `CONFIG_CGROUP_SCHED` in the kernel.

3. **Networking** — detects `eth0` and attempts DHCP (via `udhcpc`). On failure, falls back to static IP configuration using `VM_NET_IP` and `VM_NET_GW` from the kernel cmdline (set by the CHV backend for TAP networking). DNS is configured from `VM_NET_DNS` if set, overriding any stale `/etc/resolv.conf` entries.

4. **Capability validation** — verifies required kernel features (bridge networking, netfilter, cgroups) and fails fast with actionable errors if missing.

## Runtime Provenance

At boot, the openshell-vm binary logs provenance metadata about the loaded runtime bundle:

- Library paths and SHA-256 hashes
- Whether the runtime is custom-built or stock
- For custom runtimes: libkrunfw commit, kernel version, build timestamp

This information is sourced from `provenance.json` (generated by the build script)
and makes it straightforward to correlate VM behavior with a specific runtime artifact.

## Build Pipeline

```mermaid
graph LR
    subgraph Source["crates/openshell-vm/runtime/"]
        KCONF["kernel/openshell.kconfig\nKernel config fragment"]
        README["README.md\nOperator documentation"]
    end

    subgraph Linux["Linux CI (build-libkrun.sh)"]
        BUILD_L["Build kernel + libkrunfw.so + libkrun.so"]
    end

    subgraph macOS["macOS CI (build-libkrun-macos.sh)"]
        BUILD_M["Build libkrunfw.dylib + libkrun.dylib"]
    end

    subgraph CHV["Linux CI (build-cloud-hypervisor.sh)"]
        BUILD_CHV["Build cloud-hypervisor + virtiofsd"]
    end

    subgraph Output["target/libkrun-build/"]
        LIB_SO["libkrunfw.so + libkrun.so\n(Linux)"]
        LIB_DY["libkrunfw.dylib + libkrun.dylib\n(macOS)"]
        CHV_OUT["cloud-hypervisor + virtiofsd\n(Linux)"]
        VMLINUX["vmlinux\n(extracted from libkrunfw)"]
    end

    KCONF --> BUILD_L
    BUILD_L --> LIB_SO
    BUILD_L --> VMLINUX
    KCONF --> BUILD_M
    BUILD_M --> LIB_DY
    BUILD_CHV --> CHV_OUT
```

The `vmlinux` kernel is extracted from the libkrunfw build and reused by cloud-hypervisor.
Both backends boot the same kernel — the kconfig fragment includes drivers for both
virtio-MMIO (libkrun) and virtio-PCI (CHV) transports.

## Kernel Config Fragment

The `openshell.kconfig` fragment enables these kernel features on top of the stock
libkrunfw kernel. A single kernel binary is shared by both libkrun and cloud-hypervisor —
backend-specific drivers coexist safely (the kernel probes whichever transport the
hypervisor provides).

| Feature | Key Configs | Purpose |
|---------|-------------|---------|
| Network namespaces | `CONFIG_NET_NS`, `CONFIG_NAMESPACES` | Pod isolation |
| veth | `CONFIG_VETH` | Pod network namespace pairs |
| Bridge device | `CONFIG_BRIDGE`, `CONFIG_BRIDGE_NETFILTER` | cni0 bridge for pod networking, kube-proxy bridge traffic visibility |
| Netfilter framework | `CONFIG_NETFILTER`, `CONFIG_NETFILTER_ADVANCED`, `CONFIG_NETFILTER_XTABLES` | iptables/nftables framework |
| xtables match modules | `CONFIG_NETFILTER_XT_MATCH_CONNTRACK`, `_COMMENT`, `_MULTIPORT`, `_MARK`, `_STATISTIC`, `_ADDRTYPE`, `_RECENT`, `_LIMIT` | kube-proxy and kubelet iptables rules |
| Connection tracking | `CONFIG_NF_CONNTRACK`, `CONFIG_NF_CT_NETLINK` | NAT state tracking |
| NAT | `CONFIG_NF_NAT` | Service VIP DNAT/SNAT |
| iptables | `CONFIG_IP_NF_IPTABLES`, `CONFIG_IP_NF_FILTER`, `CONFIG_IP_NF_NAT`, `CONFIG_IP_NF_MANGLE` | CNI bridge masquerade and compat |
| nftables | `CONFIG_NF_TABLES`, `CONFIG_NFT_CT`, `CONFIG_NFT_NAT`, `CONFIG_NFT_MASQ`, `CONFIG_NFT_NUMGEN`, `CONFIG_NFT_FIB_IPV4` | kube-proxy nftables mode (primary) |
| IP forwarding | `CONFIG_IP_ADVANCED_ROUTER`, `CONFIG_IP_MULTIPLE_TABLES` | Pod-to-pod routing |
| IPVS | `CONFIG_IP_VS`, `CONFIG_IP_VS_RR`, `CONFIG_IP_VS_NFCT` | kube-proxy IPVS mode (optional) |
| Traffic control | `CONFIG_NET_SCH_HTB`, `CONFIG_NET_CLS_CGROUP` | Kubernetes QoS |
| Cgroups | `CONFIG_CGROUPS`, `CONFIG_CGROUP_DEVICE`, `CONFIG_CGROUP_CPUACCT`, `CONFIG_MEMCG`, `CONFIG_CGROUP_PIDS`, `CONFIG_CGROUP_FREEZER` | Container resource limits |
| Cgroup CPU | `CONFIG_CGROUP_SCHED`, `CONFIG_FAIR_GROUP_SCHED`, `CONFIG_CFS_BANDWIDTH` | cgroup v2 `cpu` controller for k3s/kubelet |
| TUN/TAP | `CONFIG_TUN` | CNI plugin support |
| Dummy interface | `CONFIG_DUMMY` | Fallback networking |
| Landlock | `CONFIG_SECURITY_LANDLOCK` | Filesystem sandboxing support |
| Seccomp filter | `CONFIG_SECCOMP_FILTER` | Syscall filtering support |
| PCI / GPU | `CONFIG_PCI`, `CONFIG_PCI_MSI`, `CONFIG_DRM` | GPU passthrough via VFIO |
| Kernel modules | `CONFIG_MODULES`, `CONFIG_MODULE_UNLOAD` | Loading NVIDIA drivers in guest |
| virtio-PCI transport | `CONFIG_VIRTIO_PCI` | cloud-hypervisor device bus (libkrun uses MMIO) |
| Serial console | `CONFIG_SERIAL_8250`, `CONFIG_SERIAL_8250_CONSOLE` | cloud-hypervisor console (`ttyS0`) |
| ACPI | `CONFIG_ACPI` | cloud-hypervisor power management / clean shutdown |
| x2APIC | `CONFIG_X86_X2APIC` | Multi-vCPU support (CHV uses x2APIC MADT entries) |

See `crates/openshell-vm/runtime/kernel/openshell.kconfig` for the full fragment with
inline comments explaining why each option is needed.

## Verification

One verification tool is provided:

1. **Capability checker** (`check-vm-capabilities.sh`): Runs inside the VM to verify
   kernel capabilities. Produces pass/fail results for each required feature.

## Running Commands In A Live VM

The standalone `openshell-vm` binary supports `openshell-vm exec -- <command...>` for a running VM.

- Each VM instance stores local runtime state next to its instance rootfs
- libkrun maps a per-instance host Unix socket into the guest on vsock port `10777`
- `openshell-vm-init.sh` starts `openshell-vm-exec-agent.py` during boot
- `openshell-vm exec` connects to the host socket, which libkrun forwards into the guest exec agent
- The guest exec agent spawns the command, then streams stdout, stderr, and exit status back
- The host-side bootstrap also uses the exec agent to read PKI cert files from the guest
  (via `cat /opt/openshell/pki/<file>`) instead of requiring a separate vsock server

`openshell-vm exec` also injects `KUBECONFIG=/etc/rancher/k3s/k3s.yaml` by default so kubectl-style
commands work the same way they would inside the VM shell.

### Vsock by backend

- **libkrun**: Uses libkrun's built-in vsock port mapping, which transparently
  bridges the guest vsock port to a host Unix socket.
- **cloud-hypervisor**: Uses a vsock exec bridge — a host-side process that
  connects an AF_VSOCK socket to a Unix domain socket, providing the same
  interface to the exec agent.

## Build Commands

```bash
# One-time setup: download pre-built runtime (~30s)
mise run vm:setup

# Build and run (libkrun, default)
mise run vm

# Build embedded binary with base rootfs (~120MB, recommended)
mise run vm:rootfs -- --base              # Build base rootfs tarball
mise run vm:build                          # Build binary with embedded rootfs

# Build with full rootfs (air-gapped, ~2GB+)
mise run vm:rootfs                         # Build full rootfs tarball
mise run vm:build                          # Rebuild binary

# With custom kernel (optional, adds ~20 min)
FROM_SOURCE=1 mise run vm:setup            # Build runtime from source
mise run vm:build                          # Then build embedded binary

# Build cloud-hypervisor runtime bundle (Linux only)
mise run vm:bundle-runtime                 # Builds CHV + virtiofsd + extracts vmlinux

# Run with cloud-hypervisor backend
openshell-vm --backend cloud-hypervisor    # Requires runtime bundle
openshell-vm --gpu                         # Auto-selects CHV with GPU passthrough

# Wipe everything and start over
mise run vm:clean
```

## CI/CD

The openshell-vm build is split into two GitHub Actions workflows that publish to a
rolling `vm-dev` GitHub Release:

### Kernel Runtime (`release-vm-kernel.yml`)

Builds the custom libkrunfw (kernel firmware), libkrun (VMM), gvproxy, cloud-hypervisor,
and virtiofsd for all supported platforms. Runs on-demand or when the kernel config /
pinned versions change.

| Platform | Runner | Build Method |
|----------|--------|-------------|
| Linux ARM64 | `build-arm64` (self-hosted) | `build-libkrun.sh` + `build-cloud-hypervisor.sh` |
| Linux x86_64 | `build-amd64` (self-hosted) | `build-libkrun.sh` + `build-cloud-hypervisor.sh` |
| macOS ARM64 | `macos-latest-xlarge` (GitHub-hosted) | `build-libkrun-macos.sh` (no CHV) |

Artifacts: `vm-runtime-{platform}.tar.zst` containing libkrun, libkrunfw, gvproxy,
and provenance metadata. Linux artifacts additionally include cloud-hypervisor,
virtiofsd, and the extracted `vmlinux` kernel.

Each platform builds its own libkrunfw and libkrun natively. The kernel inside
libkrunfw is always Linux regardless of host platform. cloud-hypervisor and virtiofsd
are Linux-only (macOS does not support VFIO/KVM passthrough).

### VM Binary (`release-vm-dev.yml`)

Builds the self-extracting openshell-vm binary for all platforms. Runs on every push
to `main` that touches VM-related crates.

```mermaid
graph TD
    CV[compute-versions] --> DL[download-kernel-runtime\nfrom vm-dev release]
    DL --> RFS_ARM[build-rootfs arm64]
    DL --> RFS_AMD[build-rootfs amd64]
    RFS_ARM --> VM_ARM[build-vm linux-arm64]
    RFS_AMD --> VM_AMD[build-vm linux-amd64]
    RFS_ARM --> VM_MAC["build-vm-macos\n(osxcross, reuses arm64 rootfs)"]
    VM_ARM --> REL[release-vm-dev\nupload to rolling release]
    VM_AMD --> REL
    VM_MAC --> REL
```

The macOS binary is cross-compiled via osxcross (no macOS runner needed for the binary
build — only for the kernel build). The macOS VM guest is always Linux ARM64, so it
reuses the arm64 rootfs.

macOS binaries produced via osxcross are not codesigned. Users must self-sign:
```bash
codesign --entitlements crates/openshell-vm/entitlements.plist --force -s - ./openshell-vm
```

## Rollout Strategy

1. Custom runtime is embedded by default when building with `mise run vm:build`.
2. The init script validates kernel capabilities at boot and fails fast if missing.
3. For development, override with `OPENSHELL_VM_RUNTIME_DIR` to use a local directory.
4. In CI, kernel runtime is pre-built and cached in the `vm-dev` release. The binary
   build downloads it via `download-kernel-runtime.sh`.
