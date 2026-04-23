# VM GPU Passthrough

> Status: Experimental and work in progress (WIP). GPU passthrough for the VM backend is under active development.

## Overview

OpenShell's VM backend can pass a physical NVIDIA GPU into a microVM using VFIO (Virtual Function I/O). This gives the guest direct access to GPU hardware, enabling CUDA workloads and `nvidia-smi` inside sandboxes without virtualization overhead.

GPU passthrough uses cloud-hypervisor or QEMU (instead of the default libkrun backend) to attach a VFIO device to the VM. The guest sees a real PCI GPU device and loads standard NVIDIA drivers. cloud-hypervisor is preferred; QEMU is used as a fallback when the GPU lacks MSI-X support.

## Architecture

```
Host                          │  Guest (microVM)
──────────────────────────────│───────────────────────────
  NVIDIA GPU (PCI BDF addr)   │  nvidia driver + CUDA
  ↕ bound to vfio-pci         │  ↕
  /dev/vfio/<group>            │  /dev/nvidia*
  ↕                            │  ↕
  CHV or QEMU (VFIO)      ────│→ PCI device visible
  ↕                            │  ↕
  TAP networking               │  k3s + device plugin
  virtiofsd (rootfs)           │  ↕
                               │  sandbox pods (nvidia.com/gpu)
```

### Backend selection

| Flag | Backend | GPU attached? |
|------|---------|---------------|
| (none) | libkrun | No |
| `--gpu` (MSI-X GPU) | cloud-hypervisor | Yes |
| `--gpu` (non-MSI-X GPU) | QEMU | Yes (fallback) |
| `--gpu 0000:41:00.0` | auto (CHV or QEMU based on MSI-X) | Yes |
| `--backend cloud-hypervisor` | cloud-hypervisor | No (force CHV without GPU) |
| `--backend qemu` | QEMU | Optional |

Auto mode (`--backend auto`, the default) selects cloud-hypervisor when `--gpu` is used with an MSI-X-capable GPU, QEMU when `--gpu` is used with a GPU lacking MSI-X, and libkrun otherwise.

### QEMU fallback

QEMU is used when GPU passthrough is requested but the GPU does not support MSI-X (PCI capability `0x11`). cloud-hypervisor's VFIO implementation requires MSI-X; QEMU handles MSI-only devices via its own interrupt remapping layer.

| Aspect | cloud-hypervisor | QEMU |
|--------|-----------------|------|
| VFIO MSI-X | Required | Not required |
| VM control | REST API over Unix socket | Command-line args + QMP |
| Vsock transport | Unix socket + `CONNECT` text protocol | `AF_VSOCK` (kernel `vhost_vsock`) |
| TAP networking | Built-in TAP creation | `-netdev tap` flag |
| Shutdown | REST `vm.shutdown` | `SIGTERM` or QMP `system_powerdown` |

The guest kernel, rootfs, init script, and exec agent are identical across both backends. The host requirements differ: QEMU needs `qemu-system-x86_64` installed on the host (not embedded in the runtime bundle) and the `vhost_vsock` kernel module for vsock exec support.

### Automatic GPU binding

When `--gpu` is passed (with or without a specific PCI address), the launcher automatically prepares the GPU for VFIO passthrough:

1. **Probe** — scans `/sys/bus/pci/devices` for NVIDIA devices (vendor `0x10de`).
2. **Safety checks** — for each candidate GPU, verifies it is safe to claim (see below). If any check fails, the launcher refuses to proceed and exits with an actionable error.
3. **Bind** — unbinds the selected GPU from the `nvidia` driver and binds it to `vfio-pci`. Also binds any IOMMU group peers to `vfio-pci` for group cleanliness.
4. **Launch** — starts cloud-hypervisor with the VFIO device attached and sets `GPU_ENABLED=true` in the guest kernel cmdline.
5. **Rebind on shutdown** — when the VM exits (clean shutdown, Ctrl+C, or crash), the launcher rebinds the GPU back to the `nvidia` driver and clears `driver_override`, restoring host GPU access. Cleanup is guaranteed by a `GpuBindGuard` RAII guard that calls restore on drop, covering normal exit, early return, and panic. Only `SIGKILL` (kill -9) bypasses the guard — see Troubleshooting below for manual recovery.

When a specific PCI address is given (`--gpu 0000:41:00.0`), the launcher targets that exact device. When `--gpu` is used without an address (`auto` mode), the launcher selects the best available GPU using the multi-GPU selection strategy.

### Safety checks

All safety checks are hard failures — if any check fails, the launcher prints an error and exits without binding. The one exception is display-manager-related blocking: when the GPU is held by Xorg or a Wayland compositor, the launcher prompts the user interactively to stop the display manager (see Single-GPU caveats).

| Check | What it detects | Failure behavior |
|-------|----------------|------------------|
| **Display attached** | GPU drives an active DRM framebuffer or is the primary rendering device | Interactive prompt to stop display-manager; error if declined or non-interactive |
| **Active processes** | Processes holding `/dev/nvidia*` file descriptors (CUDA jobs, monitoring) | Error if non-display processes; interactive prompt if only display servers |
| **IOMMU enabled** | `/sys/kernel/iommu_groups/` exists and the GPU has a group assignment | Error: "IOMMU is not enabled — add intel_iommu=on or amd_iommu=on to kernel cmdline" |
| **VFIO modules loaded** | `vfio-pci` and `vfio_iommu_type1` kernel modules are loaded | Error: "vfio-pci kernel module not loaded — run: sudo modprobe vfio-pci" |
| **Permissions** | Write access to sysfs bind/unbind and `/dev/vfio/` | Error: "insufficient permissions — run as root or with CAP_NET_ADMIN" |

### Multi-GPU selection (`--gpu` auto mode)

On hosts with multiple NVIDIA GPUs, the launcher selects a GPU using this priority:

1. **Already on vfio-pci** with a clean IOMMU group — use immediately (no rebind needed).
2. **Idle (no processes, no display)** — preferred for binding.
3. **Skip** GPUs with active displays or running processes.

If no GPU passes all safety checks, the launcher fails with per-device status listing what blocked each GPU.

## Host preparation

The launcher handles GPU driver binding automatically. The host only needs IOMMU and VFIO kernel modules configured.

### 1. Enable IOMMU

IOMMU must be enabled in both BIOS/UEFI and the Linux kernel.

**Intel systems:**

```shell
# Add to kernel command line (e.g. /etc/default/grub GRUB_CMDLINE_LINUX)
intel_iommu=on iommu=pt
```

**AMD systems:**

```shell
# AMD IOMMU is usually enabled by default; verify or add:
amd_iommu=on iommu=pt
```

After editing, run `update-grub` (or equivalent) and reboot. Verify IOMMU is active:

```shell
dmesg | grep -i iommu
# Should show: "DMAR: IOMMU enabled" or "AMD-Vi: AMD IOMMUv2"
```

### 2. Load VFIO kernel modules

```shell
sudo modprobe vfio-pci
sudo modprobe vfio_iommu_type1

# Persist across reboots
echo "vfio-pci" | sudo tee /etc/modules-load.d/vfio-pci.conf
echo "vfio_iommu_type1" | sudo tee /etc/modules-load.d/vfio_iommu_type1.conf
```

### 3. Device permissions

The launcher needs root (or `CAP_NET_ADMIN`) to bind/unbind GPU drivers and configure TAP networking:

```shell
# Option A: run as root (simplest)
sudo openshell-vm --gpu

# Option B: set udev rules for /dev/vfio/ access (still needs sysfs write via root)
echo 'SUBSYSTEM=="vfio", OWNER="root", GROUP="kvm", MODE="0660"' | \
  sudo tee /etc/udev/rules.d/99-vfio.rules
sudo udevadm control --reload-rules
sudo usermod -aG kvm $USER
```

### What the launcher does automatically

When `--gpu` is passed, the launcher performs the following steps that previously required manual intervention:

1. **Identifies NVIDIA GPUs** via sysfs (`/sys/bus/pci/devices/*/vendor`)
2. **Runs safety checks** — display, active processes, IOMMU, VFIO modules (see Safety checks above)
3. **Unbinds from nvidia** — writes to `/sys/bus/pci/devices/<BDF>/driver/unbind`
4. **Sets driver override** — writes `vfio-pci` to `/sys/bus/pci/devices/<BDF>/driver_override`
5. **Binds to vfio-pci** — writes to `/sys/bus/pci/drivers/vfio-pci/bind`
6. **Handles IOMMU group peers** — binds other devices in the same IOMMU group to `vfio-pci`
7. **On shutdown** — reverses all bindings, clears `driver_override`, rebinds to `nvidia`

## Single-GPU caveats

When the host has only one NVIDIA GPU:

- **Display manager prompt.** When the GPU drives an active display or is held by a display server (Xorg, Wayland compositor), the launcher detects this and prompts the user interactively:

  ```text
  WARNING: GPU 0000:2d:00.0 is in use by the display manager.
    Display server processes: Xorg (PID 1234)
    Active display outputs are connected to this GPU.

  Stopping the display manager will terminate your graphical session.
  You will lose access to any open GUI applications.

  The display manager will be restarted automatically when the VM exits.
  Stop display-manager and proceed with GPU passthrough? [y/N]
  ```

  If the user confirms, the launcher runs `systemctl stop display-manager`, waits for Xorg to release the GPU, then proceeds with VFIO binding. A `DisplayManagerGuard` ensures that `systemctl start display-manager` is called when the VM exits (clean shutdown, Ctrl+C, error, or panic). In non-interactive mode (stdin is not a TTY), the prompt is skipped and the launcher exits with an error instructing the user to stop the display manager manually.
- **Recovery is automatic.** When the VM exits (clean shutdown, Ctrl+C, or process crash), the launcher rebinds the GPU to the `nvidia` driver, clears `driver_override`, and restarts the display manager if it was stopped. No manual intervention is needed.
- **Process check.** If non-display CUDA processes are also using the GPU (visible via `/dev/nvidia*` file descriptors), the prompt warns about those processes too. The launcher lists all PIDs and process names so the user can make an informed decision.

## Supported GPUs

GPU passthrough is validated with NVIDIA data center GPUs. Consumer GPUs may work but are not officially supported (NVIDIA restricts GeForce passthrough in some driver versions).

| GPU | Architecture | Compute Capability | Status |
|-----|-------------|-------------------|--------|
| A100 | Ampere | 8.0 | Supported |
| A30 | Ampere | 8.0 | Supported |
| H100 | Hopper | 9.0 | Supported |
| H200 | Hopper | 9.0 | Supported |
| L40 | Ada Lovelace | 8.9 | Supported |
| L40S | Ada Lovelace | 8.9 | Supported |
| L4 | Ada Lovelace | 8.9 | Supported |

## GPU build pipeline

GPU passthrough requires NVIDIA kernel modules compiled against the VM kernel. The full build pipeline is:

```shell
# 1. Build kernel from source (needed for module compilation)
FROM_SOURCE=1 mise run vm:setup

# 2. Compile NVIDIA .ko files against the VM kernel
mise run vm:nvidia-modules

# 3. Build GPU rootfs and inject kernel modules
mise run vm:rootfs -- --base --gpu

# 4. Compile binary and package runtime
mise run vm:build
```

### NVIDIA kernel module build (`vm:nvidia-modules`)

The `build-nvidia-modules.sh` script clones [NVIDIA/open-gpu-kernel-modules](https://github.com/NVIDIA/open-gpu-kernel-modules) at the tag pinned by `NVIDIA_DRIVER_TAG` in `pins.env` and compiles the open kernel modules against the VM kernel source tree produced by `build-libkrun.sh`.

The driver tag must match the exact version of `nvidia-headless-570-open` installed in the guest rootfs. A mismatch causes "API mismatch" errors from `nvidia-smi`. The current pin is `570.211.01`.

The build produces these modules:

| Module | Purpose |
|--------|---------|
| `nvidia.ko` | Core GPU driver |
| `nvidia-uvm.ko` | Unified Virtual Memory (CUDA managed memory) |
| `nvidia-modeset.ko` | Display mode setting |
| `nvidia-drm.ko` | DRM/KMS integration |
| `nvidia-peermem.ko` | GPUDirect RDMA (optional) |

### Module injection (`vm:rootfs --gpu`)

When `build-rootfs.sh` runs with `--gpu`, it:

1. Reads `kernel-version.txt` (exported by `build-libkrun.sh`) to determine the kernel release string.
2. Copies `.ko` files from `target/libkrun-build/nvidia-modules/` into the rootfs at `/lib/modules/<version>/kernel/drivers/video/nvidia/`.
3. Runs `depmod` to generate module dependency metadata so `modprobe` works at boot.

The VM init script loads `nvidia`, `nvidia_uvm`, and `nvidia_modeset` during boot when `GPU_ENABLED=true` is set on the kernel command line.

## CLI usage

### Auto-select GPU

```shell
# openshell-vm binary (VM backend directly)
sudo openshell-vm --gpu

# openshell CLI (gateway deployment — requires VM backend)
OPENSHELL_GATEWAY_BACKEND=vm sudo openshell gateway start --gpu
```

> **Note:** The default gateway backend is Docker (containers). GPU passthrough
> requires the VM backend. Set `OPENSHELL_GATEWAY_BACKEND=vm` (or `microvm`)
> to use the VM path with `openshell gateway start`.

### Specific PCI address (multi-GPU hosts)

```shell
sudo openshell-vm --gpu 0000:41:00.0
```

### Backend selection

The `--backend` flag controls hypervisor selection independently of `--gpu`:

```shell
sudo openshell-vm --gpu                           # auto: CHV if MSI-X, QEMU otherwise
sudo openshell-vm --backend cloud-hypervisor       # explicit CHV, no GPU
sudo openshell-vm --backend qemu                   # explicit QEMU, no GPU
sudo openshell-vm --gpu --backend qemu             # force QEMU with GPU
sudo openshell-vm --backend libkrun                # explicit libkrun (no GPU support)
```

The `chv` alias is accepted as shorthand for `cloud-hypervisor`.

### Diagnostics

When `--gpu` is passed, the launcher runs safety checks before unbinding. If
checks fail, it exits with an actionable error:

```text
$ sudo openshell-vm --gpu
GPU passthrough blocked by safety checks.

  Detected devices:
    0000:41:00.0: has active display outputs
    0000:42:00.0: in use by PIDs: 12345 (python3), 12400 (nvidia-smi)

  No GPU is available for passthrough.
```

On a headless server with an idle GPU, the pre-unbind preparation runs first:

```text
$ sudo openshell-vm --gpu
GPU 0000:41:00.0: disabled nvidia persistence mode
GPU 0000:41:00.0: unloaded nvidia_uvm
GPU 0000:41:00.0: unloaded nvidia_drm
GPU 0000:41:00.0: unloaded nvidia_modeset
GPU 0000:41:00.0: device already unbound after nvidia module cleanup
GPU: binding 0000:41:00.0 for VFIO passthrough
```

On shutdown (Ctrl+C or VM exit), the original driver is restored:

```text
^C
GPU: restoring 0000:41:00.0 (cleanup)
GPU: rebinding 0000:41:00.0 to nvidia
```

## VM Networking (Cloud Hypervisor)

Cloud Hypervisor uses TAP-based networking instead of the gvproxy user-mode networking used by the libkrun backend. This has several implications for connectivity and port forwarding.

### Network topology

```
Host                                   Guest (microVM)
─────────────────────────────────────  ──────────────────────────
  eth0 (or primary NIC)                  eth0 (virtio-net)
  ↕                                      ↕
  iptables MASQUERADE ←── NAT ──→        192.168.249.2/24
  ↕                                      ↕ default gw 192.168.249.1
  vmtap0 (TAP device)                   ↕
  192.168.249.1/24 ←─── L2 bridge ──→   (kernel routes)
                                         ↕
  127.0.0.1:{port} ←── TCP proxy ──→    {port} (k3s NodePort)
```

### How it works

The CHV backend configures networking in three layers:

**1. TAP device and guest IP assignment**

Cloud Hypervisor creates a TAP device on the host side with IP `192.168.249.1/24`. The guest is assigned `192.168.249.2/24` via kernel command line parameters (`VM_NET_IP`, `VM_NET_GW`, `VM_NET_DNS`). The init script reads these from `/proc/cmdline` and uses them as the static fallback when DHCP is unavailable (CHV does not run a DHCP server).

**2. Host-side NAT and IP forwarding**

After booting the VM, the launcher:
- Enables IP forwarding (`/proc/sys/net/ipv4/ip_forward`)
- Adds iptables MASQUERADE rules for the `192.168.249.0/24` subnet
- Adds FORWARD rules to allow traffic to/from the VM

This gives the guest internet access through the host. Rules are cleaned up on VM shutdown.

**3. TCP port forwarding**

Unlike gvproxy (which provides built-in port forwarding), CHV TAP networking requires explicit port forwarding. The launcher starts a userspace TCP proxy for each port mapping (e.g., `30051:30051`). The proxy binds to `127.0.0.1:{host_port}` and forwards connections to `192.168.249.2:{guest_port}`.

### DNS resolution

The launcher detects the host's upstream DNS server using a two-step lookup:

1. Reads `/etc/resolv.conf` and picks the first nameserver that does not start with `127.` (skipping systemd-resolved's `127.0.0.53` stub and other loopback addresses).
2. If all nameservers in `/etc/resolv.conf` are loopback, falls back to `/run/systemd/resolve/resolv.conf` (the upstream resolv.conf maintained by systemd-resolved).
3. If no non-loopback nameserver is found in either file, falls back to `8.8.8.8`.

The resolved DNS server is passed to the guest via `VM_NET_DNS=` on the kernel command line. The init script writes it to `/etc/resolv.conf` inside the guest, unconditionally overriding any stale entries from previous boot cycles.

### Key constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `CHV_TAP_HOST_IP` | `192.168.249.1` | Host side of the TAP device |
| `CHV_TAP_GUEST_IP` | `192.168.249.2` | Guest static IP |
| `CHV_TAP_SUBNET` | `192.168.249.0/24` | Subnet for iptables rules |
| `CHV_TAP_NETMASK` | `255.255.255.0` | Subnet mask in VM payload |

### Differences from libkrun/gvproxy networking

| Feature | libkrun + gvproxy | CHV + TAP |
|---------|------------------|-----------|
| Network mode | User-mode (SLIRP-like) | Kernel TAP device |
| DHCP | Built-in (gvproxy) | None (static IP via cmdline) |
| Guest IP | `192.168.127.2/24` | `192.168.249.2/24` |
| Port forwarding | Built-in (gvproxy `-forward`) | Userspace TCP proxy |
| Privileges | Unprivileged | Root or `CAP_NET_ADMIN` |
| NAT | Handled by gvproxy | iptables MASQUERADE |
| DNS | gvproxy provides | Host resolver passed via cmdline |

### Troubleshooting networking

**"lookup registry-1.docker.io: Try again" (DNS failure)**

The VM cannot resolve DNS. Check:

```shell
# Verify the host DNS is non-loopback
grep nameserver /etc/resolv.conf
# If only 127.0.0.53 (systemd-resolved), find the upstream:
resolvectl status | grep 'DNS Servers'

# Verify iptables rules are in place
sudo iptables -t nat -L POSTROUTING -n -v | grep 192.168.249
sudo iptables -L FORWARD -n -v | grep 192.168.249

# Verify IP forwarding is enabled
cat /proc/sys/net/ipv4/ip_forward
```

**Gateway health check fails (port 30051 unreachable)**

The TCP port forwarder may not have started, or the guest service is not yet listening:

```shell
# Check if the port forwarder is bound on the host
ss -tlnp | grep 30051

# Check if the guest is reachable
ping -c1 192.168.249.2
```

### Host mTLS cache and state disk

The launcher caches mTLS certificates on the host after the first successful boot (warm boot path). If the state disk is deleted or `--reset` is used, the VM generates new PKI that won't match the cached certs. The launcher detects this — when the state disk is freshly created or reset, it clears the stale host mTLS cache and runs the cold-boot PKI fetch path. This prevents `transport error` failures on the gateway health check after a state disk reset.

## Troubleshooting

### "cloud-hypervisor requires MSI-X for VFIO passthrough"

The GPU lacks MSI-X support and `--backend cloud-hypervisor` was explicitly requested. Either use `--backend qemu` or omit the `--backend` flag to let auto-selection pick QEMU as the fallback.

### "no NVIDIA PCI device found"

The host has no NVIDIA GPU installed, or the PCI device is not visible:

```shell
lspci -nn | grep -i nvidia
# If empty, the GPU is not detected at the PCI level
```

### "has active display outputs" / "in use by display manager"

The GPU drives a DRM framebuffer or is held by a display server (Xorg, Wayland compositor). If running interactively, the launcher prompts to stop the display manager. If running non-interactively or the user declines, options:

- Use a different GPU for the monitor (iGPU, secondary card)
- Stop the display manager manually: `sudo systemctl stop display-manager`
- On headless servers, this should not occur — verify with `ls /sys/class/drm/card*/device`

### "in use by PIDs: ..."

Active non-display processes hold `/dev/nvidia*` file descriptors. The check is host-wide (across all NVIDIA GPUs, not per-device). The launcher lists the PIDs and process names. Stop those processes before retrying. If the only processes are display servers (Xorg, gnome-shell, etc.), the launcher will offer to stop the display manager instead.

### "IOMMU not enabled or device has no IOMMU group"

IOMMU must be enabled in both BIOS/UEFI and kernel cmdline. See Host Preparation above.

### "VFIO kernel modules not loaded"

```shell
sudo modprobe vfio-pci
sudo modprobe vfio_iommu_type1
```

### "insufficient sysfs permissions — run as root"

The launcher needs root to write to sysfs bind/unbind paths. Run with `sudo`.

### GPU not rebound after crash

If the launcher process is killed with `SIGKILL` (kill -9), the cleanup handler cannot run and the GPU remains on `vfio-pci`. Manually rebind:

```shell
PCI_ADDR="0000:41:00.0"
echo "$PCI_ADDR" | sudo tee /sys/bus/pci/devices/$PCI_ADDR/driver/unbind
echo "" | sudo tee /sys/bus/pci/devices/$PCI_ADDR/driver_override
echo "$PCI_ADDR" | sudo tee /sys/bus/pci/drivers/nvidia/bind
```

### nvidia driver unbind deadlock (kernel bug)

Some nvidia driver versions deadlock in their sysfs `unbind` handler — the `write()` syscall to `/sys/bus/pci/drivers/nvidia/unbind` never returns. When this happens, the subprocess enters uninterruptible sleep (D state) and becomes unkillable even by `SIGKILL`. The GPU's PCI subsystem state is corrupted and all subsequent PCI operations on the device hang. Only a host reboot clears this state.

This is a kernel/nvidia driver bug, not an openshell-vm issue. Three mitigation layers are in place:

1. **Pre-unbind preparation**: Before the raw sysfs unbind, the launcher disables nvidia persistence mode (`nvidia-smi -pm 0`) and unloads nvidia submodules (`nvidia_uvm`, `nvidia_drm`, `nvidia_modeset`) via `modprobe -r`. This often cascade-removes the base nvidia module entirely, unbinding the device automatically without ever touching the dangerous sysfs path.

2. **Subprocess isolation with timeout**: All sysfs writes (and the nvidia prep commands) run in a subprocess with a timeout (10s for sysfs, 15s for prep). On timeout, the subprocess is killed and dropped without calling `wait()` — preventing the parent process from being dragged into D-state.

3. **Post-timeout verification**: If the unbind subprocess times out but the device is actually unbound at the hardware level (which the nvidia bug can cause — the operation completes but the syscall never returns), the launcher detects this and continues with the VFIO bind.

If you hit this issue repeatedly, check for nvidia driver updates or file a bug with NVIDIA.

### VM boots but `nvidia-smi` fails inside guest

- Verify the GPU rootfs includes NVIDIA drivers: `chroot /path/to/rootfs which nvidia-smi`
- Check that NVIDIA kernel modules load: `openshell-vm exec <name> -- lsmod | grep nvidia`
- Inspect dmesg for NVIDIA driver errors: `openshell-vm exec <name> -- dmesg | grep -i nvidia`

## Related

- [Custom VM Runtime](custom-vm-runtime.md) — building and customizing the libkrun VM runtime
- [System Architecture](system-architecture.md) — overall OpenShell architecture
- Implementation:
  - [`crates/openshell-vfio/src/lib.rs`](../crates/openshell-vfio/src/lib.rs) — GPU binding and VFIO setup
  - [`crates/openshell-vm/src/backend/cloud_hypervisor.rs`](../crates/openshell-vm/src/backend/cloud_hypervisor.rs) — cloud-hypervisor backend
  - [`crates/openshell-vm/src/backend/qemu.rs`](../crates/openshell-vm/src/backend/qemu.rs) — QEMU backend
