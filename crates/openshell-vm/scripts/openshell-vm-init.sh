#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Init script for the openshell-vm microVM. Runs as PID 1 inside the libkrun VM.
#
# Mounts essential virtual filesystems, configures networking, then execs
# k3s server. If the rootfs was pre-initialized by build-rootfs.sh (sentinel
# at /opt/openshell/.initialized), the full manifest setup is skipped and
# k3s resumes from its persisted state (~3-5s startup).

set -euo pipefail

BOOT_START=$(date +%s%3N 2>/dev/null || date +%s)

ts() {
    local now
    now=$(date +%s%3N 2>/dev/null || date +%s)
    local elapsed=$(( (now - BOOT_START) ))
    printf "[%d.%03ds] %s\n" $((elapsed / 1000)) $((elapsed % 1000)) "$*"
}

PRE_INITIALIZED=false
if [ -f /opt/openshell/.initialized ]; then
    PRE_INITIALIZED=true
    ts "pre-initialized rootfs detected (fast path)"
fi

# ── Mount essential filesystems (parallel) ──────────────────────────────
# These are independent; mount them concurrently.

mount -t proc     proc     /proc     2>/dev/null &
mount -t sysfs    sysfs    /sys      2>/dev/null &
mount -t tmpfs    tmpfs    /tmp      2>/dev/null &
mount -t tmpfs    tmpfs    /run      2>/dev/null &
mount -t devtmpfs devtmpfs /dev      2>/dev/null &
wait

# These depend on /dev being mounted.
mkdir -p /dev/pts /dev/shm
mount -t devpts   devpts   /dev/pts  2>/dev/null &
mount -t tmpfs    tmpfs    /dev/shm  2>/dev/null &

# cgroup2 (unified hierarchy) — required by k3s/containerd.
mkdir -p /sys/fs/cgroup
mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null &
wait

ts "filesystems mounted"

# ── Networking ──────────────────────────────────────────────────────────

# Non-critical: hostname is cosmetic.
hostname openshell-vm 2>/dev/null || true

# Ensure loopback is up (k3s binds to 127.0.0.1).
ip link set lo up 2>/dev/null || true

# Detect whether we have a real network interface (gvproxy) or need a
# dummy interface (TSI / no networking).
if ip link show eth0 >/dev/null 2>&1; then
    # gvproxy networking — bring up eth0 and get an IP via DHCP.
    # gvproxy has a built-in DHCP server that assigns 192.168.127.2/24
    # with gateway 192.168.127.1 and configures ARP properly.
    ts "detected eth0 (gvproxy networking)"
    ip link set eth0 up 2>/dev/null || true

    # Use DHCP to get IP and configure routes. gvproxy's DHCP server
    # handles ARP resolution which static config does not.
    if command -v udhcpc >/dev/null 2>&1; then
        # udhcpc needs a script to apply the lease. Use the busybox
        # default script if available, otherwise write a minimal one.
        UDHCPC_SCRIPT="/usr/share/udhcpc/default.script"
        if [ ! -f "$UDHCPC_SCRIPT" ]; then
            mkdir -p /usr/share/udhcpc
            cat > "$UDHCPC_SCRIPT" << 'DHCP_SCRIPT'
#!/bin/sh
case "$1" in
    bound|renew)
        ip addr flush dev "$interface"
        ip addr add "$ip/$mask" dev "$interface"
        if [ -n "$router" ]; then
            ip route add default via $router dev "$interface"
        fi
        if [ -n "$dns" ]; then
            echo -n > /etc/resolv.conf
            for d in $dns; do
                echo "nameserver $d" >> /etc/resolv.conf
            done
        fi
        ;;
esac
DHCP_SCRIPT
            chmod +x "$UDHCPC_SCRIPT"
        fi
        # -f: stay in foreground, -q: quit after obtaining lease,
        # -n: exit if no lease, -T 1: 1s between retries, -t 3: 3 retries
        # -A 1: wait 1s before first retry (aggressive for local gvproxy)
        if ! udhcpc -i eth0 -f -q -n -T 1 -t 3 -A 1 -s "$UDHCPC_SCRIPT" 2>&1; then
            ts "WARNING: DHCP failed, falling back to static config"
            ip addr add 192.168.127.2/24 dev eth0 2>/dev/null || true
            ip route add default via 192.168.127.1 2>/dev/null || true
        fi
    else
        # Fallback to static config if no DHCP client available.
        ts "no DHCP client, using static config"
        ip addr add 192.168.127.2/24 dev eth0 2>/dev/null || true
        ip route add default via 192.168.127.1 2>/dev/null || true
    fi

    # Ensure DNS is configured. DHCP should have set /etc/resolv.conf,
    # but if it didn't (or static fallback was used), provide a default.
    if [ ! -s /etc/resolv.conf ]; then
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 8.8.4.4" >> /etc/resolv.conf
    fi

    # Read back the IP we got (from DHCP or static).
    NODE_IP=$(ip -4 addr show eth0 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]; exit}')
    NODE_IP="${NODE_IP:-192.168.127.2}"
    ts "eth0 IP: $NODE_IP"
else
    # TSI or no networking — create a dummy interface for k3s.
    ts "no eth0 found, using dummy interface (TSI mode)"
    ip link add dummy0 type dummy  2>/dev/null || true
    ip addr add 10.0.2.15/24 dev dummy0  2>/dev/null || true
    ip link set dummy0 up  2>/dev/null || true
    ip route add default dev dummy0  2>/dev/null || true

    NODE_IP="10.0.2.15"
fi

# ── k3s data directories ───────────────────────────────────────────────

mkdir -p /var/lib/rancher/k3s
mkdir -p /etc/rancher/k3s

ROOTFS_CONTAINERD_DIR="/var/lib/rancher/k3s/agent/containerd"
CONTAINERD_DIR="$ROOTFS_CONTAINERD_DIR"

# ── State disk: mount ALL mutable runtime state on the block device ────
#
# The virtio-fs share is the immutable OS image (read-only at runtime).
# All state that changes after first boot lives on an ext4 virtio-blk
# disk (/dev/vda). This gives full filesystem semantics (chown, hard
# links, fsync) and keeps every writable path off the host filesystem.
#
# Directories on the state disk:
#   containerd/          → k3s/agent/containerd  (overlayfs snapshotter)
#   k3s-agent/           → k3s/agent             (kubelet certs, kubeconfigs)
#   k3s-server-db/       → k3s/server/db         (kine SQLite)
#   k3s-server-tls/      → k3s/server/tls        (cluster TLS certs)
#   k3s-server-cred/     → k3s/server/cred       (bootstrap credentials)
#   k3s-server-etc/      → k3s/server/etc        (k3s-generated config)
#   local-path-storage/  → k3s/storage           (PVC data)
#   pki/                 → opt/openshell/pki     (mTLS CA + server/client certs)
#
# Directories that stay on virtio-fs (read-only seeds from build-rootfs.sh):
#   k3s/server/manifests   (k3s auto-deploy manifests, written by init script)
#   k3s/server/static      (k3s bundled charts)
#   k3s/agent/images       (airgap image tarballs, seeded once then on disk)

STATE_DISK_DEVICE="${OPENSHELL_VM_STATE_DISK_DEVICE:-/dev/vda}"
STATE_MOUNT_DIR="/mnt/openshell-state"
STATE_DISK_ACTIVE=false
mkdir -p "$STATE_MOUNT_DIR"

if [ -b "$STATE_DISK_DEVICE" ]; then
    ts "configuring block-backed runtime state on ${STATE_DISK_DEVICE}"
    if ! blkid "$STATE_DISK_DEVICE" >/dev/null 2>&1; then
        mkfs.ext4 -F -L openshell-state "$STATE_DISK_DEVICE" >/dev/null 2>&1
        ts "formatted state disk"
    fi
    mount -t ext4 -o noatime "$STATE_DISK_DEVICE" "$STATE_MOUNT_DIR"

    # ── k3s agent: seed images once, then bind entire agent dir ──────────
    # agent/images contains airgap image tarballs baked into the rootfs.
    # Seed them to the block device on first use so containerd can import
    # them; after that they live on the block device alongside everything else.
    STATE_K3S_AGENT_DIR="${STATE_MOUNT_DIR}/k3s-agent"
    mkdir -p "$STATE_K3S_AGENT_DIR"
    if [ ! -f "${STATE_MOUNT_DIR}/.seeded-agent-images" ]; then
        VIRTIOFS_AGENT_IMAGES="/var/lib/rancher/k3s/agent/images"
        if [ -d "$VIRTIOFS_AGENT_IMAGES" ] && [ -n "$(ls -A "$VIRTIOFS_AGENT_IMAGES" 2>/dev/null)" ]; then
            ts "seeding agent images to block device"
            mkdir -p "${STATE_K3S_AGENT_DIR}/images"
            tar -C "$VIRTIOFS_AGENT_IMAGES" -cf - . | tar -C "${STATE_K3S_AGENT_DIR}/images" -xf -
        fi
        date -u +%Y-%m-%dT%H:%M:%SZ > "${STATE_MOUNT_DIR}/.seeded-agent-images"
    fi
    mkdir -p /var/lib/rancher/k3s/agent
    mount --bind "$STATE_K3S_AGENT_DIR" /var/lib/rancher/k3s/agent

    # ── containerd: bind on top of agent ─────────────────────────────────
    # Seeded from the virtiofs rootfs on first use (overlayfs snapshots,
    # content store, meta.db pre-populated by build-rootfs.sh).
    STATE_CONTAINERD_DIR="${STATE_MOUNT_DIR}/containerd"
    mkdir -p "$STATE_CONTAINERD_DIR"
    if [ ! -f "${STATE_MOUNT_DIR}/.seeded-containerd" ]; then
        if [ -d "$ROOTFS_CONTAINERD_DIR" ] && [ -n "$(ls -A "$ROOTFS_CONTAINERD_DIR" 2>/dev/null)" ]; then
            ts "seeding containerd state to block device"
            tar -C "$ROOTFS_CONTAINERD_DIR" -cf - . | tar -C "$STATE_CONTAINERD_DIR" -xf -
        else
            ts "containerd state is empty; starting fresh"
        fi
        date -u +%Y-%m-%dT%H:%M:%SZ > "${STATE_MOUNT_DIR}/.seeded-containerd"
    fi
    mkdir -p "$ROOTFS_CONTAINERD_DIR"
    mount --bind "$STATE_CONTAINERD_DIR" "$ROOTFS_CONTAINERD_DIR"

    # ── k3s server runtime state ──────────────────────────────────────────
    # server/manifests and server/static stay on virtiofs (written by init
    # script each boot from /opt/openshell/manifests; read-only after that).
    for pair in \
        "k3s-server-db:/var/lib/rancher/k3s/server/db" \
        "k3s-server-tls:/var/lib/rancher/k3s/server/tls" \
        "k3s-server-cred:/var/lib/rancher/k3s/server/cred" \
        "k3s-server-etc:/var/lib/rancher/k3s/server/etc"
    do
        src="${STATE_MOUNT_DIR}/${pair%%:*}"
        dst="${pair#*:}"
        mkdir -p "$src" "$dst"
        mount --bind "$src" "$dst"
    done

    # ── local-path PVC storage ─────────────────────────────────────────────
    mkdir -p "${STATE_MOUNT_DIR}/local-path-storage" /var/lib/rancher/k3s/storage
    mount --bind "${STATE_MOUNT_DIR}/local-path-storage" /var/lib/rancher/k3s/storage

    # ── PKI ────────────────────────────────────────────────────────────────
    # Certs live on the block device; the host reads them via the exec
    # agent (vsock port 10777) instead of polling the virtiofs rootfs path.
    mkdir -p "${STATE_MOUNT_DIR}/pki" /opt/openshell/pki
    mount --bind "${STATE_MOUNT_DIR}/pki" /opt/openshell/pki

    STATE_DISK_ACTIVE=true
    ts "all runtime state mounted from block device"
else
    ts "no block device found; using virtiofs-backed runtime state"
fi

# Clean stale sockets from previous boots. Sockets live in /run (tmpfs)
# and /var/lib/rancher/k3s — they're stale on every boot regardless of
# whether state is on virtiofs or the block device.
find /var/lib/rancher/k3s -name '*.sock' -delete 2>/dev/null || true
find /run -name '*.sock' -delete 2>/dev/null || true
# On the block-device path, node-passwd is regenerated by k3s on each
# start; clear it so k3s doesn't fail node re-registration validation.
rm -f /var/lib/rancher/k3s/server/cred/node-passwd 2>/dev/null || true

# Clean stale containerd runtime state from previous boots.
#
# The rootfs persists across VM restarts via virtio-fs. The overlayfs
# snapshotter now lives on the host-backed state disk when present, so
# snapshot data and meta.db persist across boots. We only clean runtime
# state (shim PIDs, sockets) that becomes stale when the VM restarts.
if [ -d "$CONTAINERD_DIR" ]; then
    # Remove runtime task state (stale shim PIDs, sockets from dead processes).
    rm -rf "${CONTAINERD_DIR}/io.containerd.runtime.v2.task" 2>/dev/null || true
    # Remove sandbox controller shim state. Stale sandbox records cause
    # containerd to reuse network namespaces from previous boots, which
    # already have routes configured. The CNI bridge plugin then fails
    # with "file exists" when adding the default route on retry.
    rm -rf "${CONTAINERD_DIR}/io.containerd.sandbox.controller.v1.shim" 2>/dev/null || true
    # Clean stale ingest temp files from the content store.
    rm -rf "${CONTAINERD_DIR}/io.containerd.content.v1.content/ingest" 2>/dev/null || true
    mkdir -p "${CONTAINERD_DIR}/io.containerd.content.v1.content/ingest"
    # meta.db and overlayfs snapshots persist across boots on virtio-fs.
    # No need to delete meta.db — snapshot metadata remains valid since
    # the snapshotter directory is no longer backed by volatile tmpfs.
    ts "cleaned containerd runtime state (meta.db + snapshots preserved)"
fi
rm -rf /run/k3s 2>/dev/null || true

# Ensure the overlayfs snapshotter directory exists. The snapshotter
# runs directly on virtio-fs, so layer data and snapshot metadata
# persist across VM restarts. This eliminates the need to re-import
# image tarballs and re-extract layers on every boot, significantly
# reducing sandbox creation time.
OVERLAYFS_DIR="${CONTAINERD_DIR}/io.containerd.snapshotter.v1.overlayfs"
mkdir -p "$OVERLAYFS_DIR"
if [ "$STATE_DISK_ACTIVE" = true ]; then
    ts "overlayfs snapshotter on block-backed containerd state"
else
    ts "overlayfs snapshotter on virtio-fs (persistent)"
fi

ts "stale artifacts cleaned"

# ── Clean stale CNI / pod networking state ──────────────────────────────
# The rootfs persists across VM restarts via virtio-fs. Previous pod
# sandboxes leave behind veth pairs, bridge routes, host-local IPAM
# allocations, and network namespaces. If not cleaned, the bridge CNI
# plugin fails with:
#   "failed to add route ... file exists"
# because the default route via cni0 already exists from the prior boot,
# or a stale network namespace already has the route configured.

# Tear down the CNI bridge and its associated routes.
if ip link show cni0 >/dev/null 2>&1; then
    ip link set cni0 down 2>/dev/null || true
    ip link delete cni0 2>/dev/null || true
    ts "deleted stale cni0 bridge"
fi

# Remove any leftover veth pairs (CNI bridge plugin creates vethXXXX).
veths=$(ip -o link show type veth 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 || true)
for veth in $veths; do
    ip link delete "$veth" 2>/dev/null || true
done

# Flush host-local IPAM allocations so IPs can be reassigned cleanly.
rm -rf /var/lib/cni/networks 2>/dev/null || true
rm -rf /var/lib/cni/results 2>/dev/null || true

# Flush any stale CNI-added routes for the pod CIDR. These can conflict
# with routes the bridge plugin tries to add on the next boot.
ip route flush 10.42.0.0/24 2>/dev/null || true

# Clean up stale pod network namespaces from previous boots. Containerd
# creates named netns under /var/run/netns/ for each pod sandbox. If
# these persist across VM restarts, the CNI bridge plugin fails when
# adding routes because the stale netns already has the default route
# configured from the prior boot. Removing all named network namespaces
# forces containerd to create fresh ones.
if [ -d /var/run/netns ]; then
    netns_list=$(ip netns list 2>/dev/null | awk '{print $1}' || true)
    for ns in $netns_list; do
        ip netns delete "$ns" 2>/dev/null || true
    done
fi
# Also clean the netns bind-mount directory used by containerd/CRI.
# Containerd may use /run/netns/ or /var/run/netns/ (same via tmpfs).
rm -rf /run/netns/* 2>/dev/null || true
rm -rf /var/run/netns/* 2>/dev/null || true

ts "stale CNI networking state cleaned"

# ── Network profile detection ───────────────────────────────────────────
# Detect early so manifest patching and k3s flags both use the same value.
#
# "bridge" is the only supported profile. It requires a custom libkrunfw
# with CONFIG_BRIDGE, CONFIG_NETFILTER, CONFIG_NF_NAT built in. If the
# kernel lacks these capabilities the VM cannot run pod networking and we
# fail fast with an actionable error.

NET_PROFILE="bridge"

ts "network profile: ${NET_PROFILE}"

# Validate that the kernel actually has the required capabilities.
_caps_ok=true
if ! ip link add _cap_br0 type bridge 2>/dev/null; then
    echo "ERROR: kernel lacks bridge support (CONFIG_BRIDGE). Use a custom libkrunfw." >&2
    _caps_ok=false
else
    ip link del _cap_br0 2>/dev/null || true
fi
if [ ! -d /proc/sys/net/netfilter ] && [ ! -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    echo "ERROR: kernel lacks netfilter support (CONFIG_NETFILTER). Use a custom libkrunfw." >&2
    _caps_ok=false
fi
if [ "$_caps_ok" = false ]; then
    echo "FATAL: required kernel capabilities missing — cannot configure pod networking." >&2
    echo "See: architecture/custom-vm-runtime.md for build instructions." >&2
    exit 1
fi

# ── Deploy bundled manifests (cold boot only) ───────────────────────────
# On pre-initialized rootfs, manifests are already in place from the
# build-time k3s boot. Skip this entirely for fast startup.

K3S_MANIFESTS="/var/lib/rancher/k3s/server/manifests"
BUNDLED_MANIFESTS="/opt/openshell/manifests"

if [ "$PRE_INITIALIZED" = false ]; then

    mkdir -p "$K3S_MANIFESTS"

    if [ -d "$BUNDLED_MANIFESTS" ]; then
        ts "deploying bundled manifests (cold boot)..."
        for manifest in "$BUNDLED_MANIFESTS"/*.yaml; do
            [ ! -f "$manifest" ] && continue
            cp "$manifest" "$K3S_MANIFESTS/"
        done

        # Remove stale OpenShell-managed manifests from previous boots.
        for existing in "$K3S_MANIFESTS"/openshell-*.yaml \
                        "$K3S_MANIFESTS"/agent-*.yaml; do
            [ ! -f "$existing" ] && continue
            basename=$(basename "$existing")
            if [ ! -f "$BUNDLED_MANIFESTS/$basename" ]; then
                rm -f "$existing"
            fi
        done
    fi

    # Restore helm chart tarballs from staging. A --reset wipes
    # server/static/charts/ but the bundled charts survive in
    # /opt/openshell/charts/.
    BUNDLED_CHARTS="/opt/openshell/charts"
    K3S_CHARTS="/var/lib/rancher/k3s/server/static/charts"
    if [ -d "$BUNDLED_CHARTS" ]; then
        mkdir -p "$K3S_CHARTS"
        cp "$BUNDLED_CHARTS"/*.tgz "$K3S_CHARTS/" 2>/dev/null || true
        ts "helm charts restored from staging"
    fi

    ts "manifests deployed"
else
    ts "skipping manifest deploy (pre-initialized)"
fi

# Patch manifests for VM deployment constraints.
HELMCHART="$K3S_MANIFESTS/openshell-helmchart.yaml"
if [ -f "$HELMCHART" ]; then
    # Use pre-loaded images and a tmp-backed database in the VM.
    sed -i 's|__IMAGE_PULL_POLICY__|IfNotPresent|g' "$HELMCHART"
    sed -i 's|__SANDBOX_IMAGE_PULL_POLICY__|"IfNotPresent"|g' "$HELMCHART"
    sed -i 's|__DB_URL__|"sqlite:/tmp/openshell.db"|g' "$HELMCHART"
    # Clear SSH gateway placeholders (default 127.0.0.1 is correct for local VM).
    sed -i 's|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: ""|g' "$HELMCHART"
    sed -i 's|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g' "$HELMCHART"
    sed -i 's|__DISABLE_GATEWAY_AUTH__|false|g' "$HELMCHART"
    sed -i 's|__DISABLE_TLS__|false|g' "$HELMCHART"
    sed -i 's|hostGatewayIP: __HOST_GATEWAY_IP__|hostGatewayIP: ""|g' "$HELMCHART"
    sed -i '/__CHART_CHECKSUM__/d' "$HELMCHART"
fi

AGENT_MANIFEST="$K3S_MANIFESTS/agent-sandbox.yaml"
if [ -f "$AGENT_MANIFEST" ]; then
    # Bridge CNI: agent-sandbox uses normal pod networking.
    # kube-proxy is enabled so kubernetes.default.svc is reachable
    # via ClusterIP — no need for KUBERNETES_SERVICE_HOST override.
    sed -i '/hostNetwork: true/d' "$AGENT_MANIFEST"
    sed -i '/dnsPolicy: ClusterFirstWithHostNet/d' "$AGENT_MANIFEST"
    ts "agent-sandbox: using pod networking (bridge profile)"
fi

# ── CNI configuration (bridge) ──────────────────────────────────────────
# Uses the bridge CNI plugin with iptables masquerade. Requires
# CONFIG_BRIDGE, CONFIG_NETFILTER, CONFIG_NF_NAT in the VM kernel
# (validated above at boot). kube-proxy uses nftables mode for service
# VIP routing.

CNI_CONF_DIR="/etc/cni/net.d"
CNI_BIN_DIR="/opt/cni/bin"
mkdir -p "$CNI_CONF_DIR" "$CNI_BIN_DIR"

# Enable IP forwarding (required for masquerade).
if ! echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; then
    echo "FATAL: failed to enable IP forwarding — pod networking will not work" >&2
    exit 1
fi

# Enable bridge netfilter call (required for CNI bridge masquerade to
# see bridged traffic).
if [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    if ! echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null; then
        ts "WARNING: failed to enable bridge-nf-call-iptables — CNI masquerade may not work"
    fi
fi

cat > "$CNI_CONF_DIR/10-bridge.conflist" << 'CNICFG'
{
  "cniVersion": "1.0.0",
  "name": "bridge",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni0",
      "isGateway": true,
      "isDefaultGateway": true,
      "ipMasq": true,
      "hairpinMode": true,
      "ipam": {
        "type": "host-local",
        "ranges": [[{ "subnet": "10.42.0.0/24" }]]
      }
    },
    {
      "type": "portmap",
      "capabilities": { "portMappings": true },
      "snat": true
    },
    {
      "type": "loopback"
    }
  ]
}
CNICFG

# Remove any stale legacy ptp config.
rm -f "$CNI_CONF_DIR/10-ptp.conflist" 2>/dev/null || true

ts "bridge CNI configured (cni0 + iptables masquerade)"

# Start the local exec agent before k3s so `openshell-vm exec` works as soon as
# the VM has booted. It only listens on vsock, not on the guest network.
if command -v python3 >/dev/null 2>&1; then
    ts "starting openshell-vm exec agent"
    mkdir -p /run/openshell
    setsid python3 /srv/openshell-vm-exec-agent.py >/run/openshell/openshell-vm-exec-agent.log 2>&1 &
else
    ts "WARNING: python3 missing, openshell-vm exec agent disabled"
fi

# Symlink k3s-bundled CNI binaries to the default containerd bin path.
# k3s extracts its tools to /var/lib/rancher/k3s/data/<hash>/bin/ at startup.
# On cold boot this directory doesn't exist yet (k3s hasn't run), so we
# first try synchronously, then fall back to a background watcher that
# polls until k3s extracts the binaries and creates the symlinks before
# any pods can schedule.
link_cni_binaries() {
    local data_bin="$1"
    # Ensure execute permissions on all binaries. The rootfs may have
    # been built on macOS where virtio-fs or docker export can strip
    # execute bits from Linux ELF binaries.
    chmod +x "$data_bin"/* 2>/dev/null || true
    if [ -d "$data_bin/aux" ]; then
        chmod +x "$data_bin/aux"/* 2>/dev/null || true
    fi
    for plugin in bridge host-local loopback bandwidth portmap; do
        [ -e "$data_bin/$plugin" ] && ln -sf "$data_bin/$plugin" "$CNI_BIN_DIR/$plugin"
    done
}

# Find the k3s data bin dir, excluding temporary extraction directories
# (k3s extracts to <hash>-tmp/ then renames to <hash>/).
find_k3s_data_bin() {
    find /var/lib/rancher/k3s/data -maxdepth 2 -name bin -type d 2>/dev/null \
        | grep -v '\-tmp/' | head -1 || true
}

K3S_DATA_BIN=$(find_k3s_data_bin)
if [ -n "$K3S_DATA_BIN" ]; then
    link_cni_binaries "$K3S_DATA_BIN"
    ts "CNI binaries linked from $K3S_DATA_BIN"
else
    # Cold boot: k3s hasn't extracted binaries yet. Launch a background
    # watcher that polls until the data dir appears (k3s creates it in
    # the first ~2s of startup) and then symlinks the CNI plugins.
    # We exclude -tmp directories to avoid symlinking to the transient
    # extraction path that k3s renames once extraction completes.
    ts "CNI binaries not yet available, starting background watcher"
    setsid sh -c '
        CNI_BIN_DIR="/opt/cni/bin"
        for i in $(seq 1 60); do
            K3S_DATA_BIN=$(find /var/lib/rancher/k3s/data -maxdepth 2 -name bin -type d 2>/dev/null \
                | grep -v "\-tmp/" | head -1)
            if [ -n "$K3S_DATA_BIN" ]; then
                chmod +x "$K3S_DATA_BIN"/* 2>/dev/null || true
                if [ -d "$K3S_DATA_BIN/aux" ]; then
                    chmod +x "$K3S_DATA_BIN/aux"/* 2>/dev/null || true
                fi
                for plugin in bridge host-local loopback bandwidth portmap; do
                    [ -e "$K3S_DATA_BIN/$plugin" ] && ln -sf "$K3S_DATA_BIN/$plugin" "$CNI_BIN_DIR/$plugin"
                done
                echo "[cni-watcher] CNI binaries linked from $K3S_DATA_BIN after ${i}s"
                exit 0
            fi
            sleep 1
        done
        echo "[cni-watcher] ERROR: k3s data bin dir not found after 60s"
    ' &
fi

# Also clean up any flannel config from the k3s-specific CNI directory
# (pre-baked state from the Docker build used host-gw flannel).
rm -f "/var/lib/rancher/k3s/agent/etc/cni/net.d/10-flannel.conflist" 2>/dev/null || true

# ── PKI: generate once, read via exec agent ───────────────────────────
# Certs are generated on first boot and stored at /opt/openshell/pki/.
# With the block-device layout this path is on the state disk, fully
# isolated from the virtiofs host filesystem.
# The host-side bootstrap reads certs via the exec agent (vsock port
# 10777) by running `cat` on each PEM file.

PKI_DIR="/opt/openshell/pki"
if [ ! -f "$PKI_DIR/ca.crt" ]; then
    ts "generating PKI (first boot)..."
    mkdir -p "$PKI_DIR"

    # CA
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$PKI_DIR/ca.key" -out "$PKI_DIR/ca.crt" \
        -days 3650 -nodes -subj "/O=openshell/CN=openshell-ca" 2>/dev/null

    # Server cert with SANs
    cat > "$PKI_DIR/server.cnf" <<EOCNF
[req]
req_extensions = v3_req
distinguished_name = req_dn
prompt = no

[req_dn]
CN = openshell-server

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = openshell
DNS.2 = openshell.openshell.svc
DNS.3 = openshell.openshell.svc.cluster.local
DNS.4 = localhost
DNS.5 = host.docker.internal
IP.1 = 127.0.0.1
EOCNF

    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$PKI_DIR/server.key" -out "$PKI_DIR/server.csr" \
        -nodes -config "$PKI_DIR/server.cnf" 2>/dev/null
    openssl x509 -req -in "$PKI_DIR/server.csr" \
        -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial \
        -out "$PKI_DIR/server.crt" -days 3650 \
        -extensions v3_req -extfile "$PKI_DIR/server.cnf" 2>/dev/null

    # Client cert (must be v3 — rustls rejects v1)
    cat > "$PKI_DIR/client.cnf" <<EOCLIENT
[req]
distinguished_name = req_dn
prompt = no

[req_dn]
CN = openshell-client

[v3_client]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOCLIENT

    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$PKI_DIR/client.key" -out "$PKI_DIR/client.csr" \
        -nodes -config "$PKI_DIR/client.cnf" 2>/dev/null
    openssl x509 -req -in "$PKI_DIR/client.csr" \
        -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial \
        -out "$PKI_DIR/client.crt" -days 3650 \
        -extensions v3_client -extfile "$PKI_DIR/client.cnf" 2>/dev/null

    # Clean up CSRs
    rm -f "$PKI_DIR"/*.csr "$PKI_DIR"/*.cnf "$PKI_DIR"/*.srl

    ts "PKI generated"
else
    ts "existing PKI found, skipping generation"
fi

SSH_HANDSHAKE_SECRET_FILE="${PKI_DIR}/ssh-handshake-secret"
if [ ! -f "$SSH_HANDSHAKE_SECRET_FILE" ]; then
    ts "generating SSH handshake secret (first boot)..."
    head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n' > "$SSH_HANDSHAKE_SECRET_FILE"
    chmod 600 "$SSH_HANDSHAKE_SECRET_FILE"
else
    ts "existing SSH handshake secret found, reusing"
fi

# Write TLS secrets as a k3s auto-deploy manifest. k3s applies any YAML
# in server/manifests/ on startup. We write this on every boot so that:
#   - A --reset (which wipes the kine DB and server/ tree) gets secrets re-applied.
#   - A corrupt kine DB (removed by the host-side corruption check) gets secrets
#     re-applied on the fresh database.
# This is idempotent — k3s checksums manifests and only re-applies on change.
ts "writing TLS secrets manifest..."
mkdir -p "$K3S_MANIFESTS"
CA_CRT_B64=$(base64 -w0 < "$PKI_DIR/ca.crt")
SERVER_CRT_B64=$(base64 -w0 < "$PKI_DIR/server.crt")
SERVER_KEY_B64=$(base64 -w0 < "$PKI_DIR/server.key")
CLIENT_CRT_B64=$(base64 -w0 < "$PKI_DIR/client.crt")
CLIENT_KEY_B64=$(base64 -w0 < "$PKI_DIR/client.key")
SSH_HANDSHAKE_SECRET_B64=$(base64 -w0 < "$SSH_HANDSHAKE_SECRET_FILE")

cat > "$K3S_MANIFESTS/openshell-tls-secrets.yaml" <<EOTLS
---
apiVersion: v1
kind: Namespace
metadata:
  name: openshell
---
apiVersion: v1
kind: Secret
metadata:
  name: openshell-server-tls
  namespace: openshell
type: kubernetes.io/tls
data:
  tls.crt: "${SERVER_CRT_B64}"
  tls.key: "${SERVER_KEY_B64}"
---
apiVersion: v1
kind: Secret
metadata:
  name: openshell-server-client-ca
  namespace: openshell
type: Opaque
data:
  ca.crt: "${CA_CRT_B64}"
---
apiVersion: v1
kind: Secret
metadata:
  name: openshell-client-tls
  namespace: openshell
type: Opaque
data:
  tls.crt: "${CLIENT_CRT_B64}"
  tls.key: "${CLIENT_KEY_B64}"
  ca.crt: "${CA_CRT_B64}"
---
apiVersion: v1
kind: Secret
metadata:
  name: openshell-ssh-handshake
  namespace: openshell
type: Opaque
data:
  secret: "${SSH_HANDSHAKE_SECRET_B64}"
EOTLS
ts "TLS secrets manifest written"

# ── Start k3s ──────────────────────────────────────────────────────────
# Flags tuned for fast single-node startup. Bridge CNI handles pod
# networking; kube-proxy runs in nftables mode for service VIP / ClusterIP
# support.
#
# nftables mode: k3s bundles its own iptables binaries whose MARK target
# doesn't negotiate xt_MARK revision 2 correctly with the libkrun kernel,
# causing --xor-mark failures. nftables mode uses the kernel's nf_tables
# subsystem directly and sidesteps the issue entirely. The kernel is
# configured with CONFIG_NF_TABLES=y and related modules.

K3S_ARGS=(
    --disable=traefik,servicelb,metrics-server
    --disable-network-policy
    --write-kubeconfig-mode=644
    --node-ip="$NODE_IP"
    --kube-apiserver-arg=bind-address=0.0.0.0
    --resolv-conf=/etc/resolv.conf
    --tls-san=localhost,127.0.0.1,10.0.2.15,192.168.127.2
    --flannel-backend=none
    --snapshotter=overlayfs
    --kube-proxy-arg=proxy-mode=nftables
    --kube-proxy-arg=nodeport-addresses=0.0.0.0/0
    # virtio-fs passthrough reports the host disk usage, which is
    # misleading — kubelet sees 90%+ used and enters eviction pressure,
    # blocking image pulls and pod scheduling. Disable all disk-based
    # eviction since the VM shares the host filesystem. Setting
    # thresholds to 0% effectively disables eviction for each signal.
    "--kubelet-arg=eviction-hard=imagefs.available<0%,nodefs.available<0%"
    "--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%"
    --kubelet-arg=image-gc-high-threshold=100
    --kubelet-arg=image-gc-low-threshold=99
    # Increase CRI runtime timeout for large image operations. The first
    # container create after an image import may still be slow if
    # containerd needs to extract layers. 10m is a conservative safety
    # margin; typical operations complete much faster with persistent
    # overlayfs snapshots.
    --kubelet-arg=runtime-request-timeout=10m
)

ts "starting k3s server (bridge CNI + nftables kube-proxy)"

# ── DEBUG: dump nftables rules after k3s has had time to sync ───────────
# Write diagnostic output to a file on the root filesystem (virtio-fs),
# readable from the host at rootfs/opt/openshell/diag.txt.
# The subshell runs detached with its own session (setsid) so it survives
# the exec that replaces this shell with k3s as PID 1.
# Only runs when OPENSHELL_VM_DIAG=1 is set.
if [ "${OPENSHELL_VM_DIAG:-0}" = "1" ]; then
DIAG_FILE="/opt/openshell/diag.txt"
setsid sh -c '
    sleep 60
    DIAG="'"$DIAG_FILE"'"
    # Find the nft binary — glob must be expanded by the shell, not quoted
    for f in /var/lib/rancher/k3s/data/*/bin/aux/nft; do
        [ -x "$f" ] && NFT="$f" && break
    done
    if [ -z "$NFT" ]; then
        echo "ERROR: nft binary not found" > "$DIAG"
        exit 1
    fi
    {
        echo "=== [DIAG $(date +%s)] nft binary: $NFT ==="
        echo "=== [DIAG] nft list tables ==="
        "$NFT" list tables 2>&1
        echo "=== [DIAG] nft list ruleset (kube-proxy) ==="
        "$NFT" list ruleset 2>&1
        echo "=== [DIAG] ss -tlnp ==="
        ss -tlnp 2>&1 || busybox netstat -tlnp 2>&1 || echo "ss/netstat not available"
        echo "=== [DIAG] ip addr ==="
        ip addr 2>&1
        echo "=== [DIAG] ip route ==="
        ip route 2>&1
        echo "=== [DIAG] iptables -t nat -L -n -v ==="
        iptables -t nat -L -n -v 2>&1
        echo "=== [DIAG] kube-proxy healthz ==="
        wget -q -O - http://127.0.0.1:10256/healthz 2>&1 || echo "healthz failed"
        echo "=== [DIAG] conntrack -L ==="
        conntrack -L 2>&1 || echo "conntrack not available"
        echo "=== [DIAG] done ==="
    } > "$DIAG" 2>&1
' &
fi

# ── Clear stale kine bootstrap lock ─────────────────────────────────────
# k3s uses kine with a SQLite backend at state.db. When k3s starts, kine
# sets a bootstrap lock row; if k3s is killed before completing bootstrap
# (SIGKILL, host crash, power loss), the lock persists and the next k3s
# instance hangs forever on:
#   "Bootstrap key already locked — waiting for data to be populated by
#    another server"
#
# We clear the lock row before starting k3s so that a warm boot with
# persistent state.db succeeds. If state.db doesn't exist (first boot or
# --reset), this is a harmless no-op. If state.db is corrupt, sqlite3
# fails silently (|| true) and the host-side corruption check in exec.rs
# will have already removed the file.
KINE_DB="/var/lib/rancher/k3s/server/db/state.db"
if [ -f "$KINE_DB" ]; then
    ts "clearing stale kine bootstrap lock (if any)"
    # If sqlite3 fails (corrupt DB, missing binary), log the failure.
    # The host-side corruption check in exec.rs handles the corrupt case,
    # but we should still know about it.
    if ! sqlite3 "$KINE_DB" "DELETE FROM kine WHERE name LIKE '/bootstrap/%';" 2>/dev/null; then
        ts "WARNING: failed to clear kine bootstrap lock — k3s may hang if DB is corrupt"
    fi
    if ! sqlite3 "$KINE_DB" "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null; then
        ts "WARNING: failed to checkpoint kine WAL"
    fi
fi

exec /usr/local/bin/k3s server "${K3S_ARGS[@]}"
