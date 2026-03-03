#!/bin/sh
# vm-init.sh — Bootstrap script for running k3s inside a libkrun microVM.
#
# When using gvproxy networking (virtio-net), the guest gets a real eth0
# interface. This script configures it via DHCP from gvproxy (which provides
# 192.168.127.0/24 with gateway 192.168.127.1).
#
# The libkrunfw kernel does not include netfilter/iptables, so kube-proxy
# and flannel must be disabled. This is handled by the k3s flags passed
# from the CLI.
#
# This script is injected into the rootfs at extraction time and used as the
# microVM entrypoint instead of running k3s directly.

set -e

# The k3s (rancher) base image doesn't symlink all BusyBox applets.
# Ensure essential commands are available.
BB=/bin/busybox
for cmd in mount mountpoint mkdir cat ip udhcpc; do
    if ! command -v $cmd >/dev/null 2>&1; then
        ln -sf $BB /bin/$cmd 2>/dev/null || true
    fi
done
# Also ensure sbin commands are available for ip/route.
for cmd in ip route; do
    if ! command -v $cmd >/dev/null 2>&1; then
        ln -sf $BB /sbin/$cmd 2>/dev/null || true
    fi
done

echo "[vm-init] Setting up network..."

# The libkrunfw kernel auto-mounts proc, sysfs, devtmpfs, and cgroup2.
# We only need to mount /run (tmpfs for PID files and sockets) and /tmp.
if ! mountpoint -q /run 2>/dev/null; then
    mkdir -p /run
    mount -t tmpfs tmpfs /run
fi
if ! mountpoint -q /tmp 2>/dev/null; then
    mkdir -p /tmp
    mount -t tmpfs tmpfs /tmp
fi

# Enable the loopback interface.
ip link set lo up 2>/dev/null || true

# Configure eth0 via DHCP from gvproxy.
# gvproxy provides DHCP on 192.168.127.0/24:
#   gateway: 192.168.127.1
#   guest:   192.168.127.2
#   DNS:     192.168.127.1
if ip link show eth0 >/dev/null 2>&1; then
    echo "[vm-init] Configuring eth0 via DHCP..."
    ip link set eth0 up

    # BusyBox udhcpc needs a script to apply the lease. Create a minimal one.
    mkdir -p /usr/share/udhcpc
    cat > /usr/share/udhcpc/default.script << 'DHCP_SCRIPT'
#!/bin/sh
case "$1" in
    bound|renew)
        ip addr add "$ip/$mask" dev "$interface" 2>/dev/null || true
        if [ -n "$router" ]; then
            ip route add default via "$router" dev "$interface" 2>/dev/null || true
        fi
        if [ -n "$dns" ]; then
            : > /etc/resolv.conf
            for ns in $dns; do
                echo "nameserver $ns" >> /etc/resolv.conf
            done
        fi
        ;;
esac
DHCP_SCRIPT
    chmod +x /usr/share/udhcpc/default.script

    # Run DHCP (foreground, quit after lease obtained).
    udhcpc -i eth0 -n -q -f -t 5 2>/dev/null || {
        echo "[vm-init] DHCP failed, using static config"
        ip addr add 192.168.127.2/24 dev eth0 2>/dev/null || true
        ip route add default via 192.168.127.1 dev eth0 2>/dev/null || true
        echo "nameserver 192.168.127.1" > /etc/resolv.conf
    }

    GUEST_IP=$(ip -4 addr show eth0 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -1)
    GUEST_IP="${GUEST_IP:-192.168.127.3}"
    echo "[vm-init] Network configured: eth0 = ${GUEST_IP}"
else
    # Fallback: no eth0 (TSI-only mode). Add dummy routing on lo so k3s
    # finds a default route in /proc/net/route.
    echo "[vm-init] No eth0 found, using lo-only fallback..."
    ip addr add 10.0.2.100/32 dev lo 2>/dev/null || true
    ip route add 10.0.2.1/32 dev lo 2>/dev/null || true
    ip route add default via 10.0.2.1 dev lo 2>/dev/null || true
    echo "nameserver 10.0.2.1" > /etc/resolv.conf
    GUEST_IP="10.0.2.100"
    echo "[vm-init] Network configured (fallback): lo = ${GUEST_IP}"
fi

# Set up k3s-specific DNS config.
mkdir -p /etc/rancher/k3s
cp -f /etc/resolv.conf /etc/rancher/k3s/resolv.conf

# k3s uses --data-dir=/run/k3s (tmpfs) to avoid SQLite file locking issues
# on virtio-fs. Ensure the directory exists.
mkdir -p /run/k3s

# ---------------------------------------------------------------------------
# CNI setup
# ---------------------------------------------------------------------------
# When k3s runs with --flannel-backend=none, no CNI plugin is installed.
# Without CNI, the kubelet reports the node as NotReady and no pods can be
# scheduled.
#
# The libkrunfw kernel lacks the bridge module, so the standard bridge CNI
# plugin fails with "operation not supported". Instead, we install a minimal
# "noop" CNI plugin (a shell script) that assigns pod IPs from a static range
# using the host-local IPAM plugin but skips creating any bridge/veth devices.
# This is sufficient for a single-node microVM cluster where we only need:
#   - The node to report Ready
#   - Pods to start (they communicate via the API server, not directly)
#
# The k3s image ships CNI plugin binaries in /bin/. kubelet expects them
# in /opt/cni/bin/ by default.
echo "[vm-init] Setting up CNI..."
mkdir -p /opt/cni/bin

# Symlink the standard plugins we need (loopback for pod lo, host-local for IPAM).
for plugin in loopback host-local; do
    if [ -f "/bin/$plugin" ] && [ ! -f "/opt/cni/bin/$plugin" ]; then
        ln -sf "/bin/$plugin" "/opt/cni/bin/$plugin"
    fi
done

# Create a minimal noop CNI plugin. This shell script satisfies the CNI
# contract without creating any network devices (which the libkrunfw kernel
# can't do — no bridge module). It invokes host-local IPAM to allocate an
# IP, then returns the result. For DEL, it calls IPAM to release the IP.
cat > /opt/cni/bin/noop << 'NOOP_CNI'
#!/bin/sh
# Minimal noop CNI plugin — delegates to host-local IPAM only.
# Reads the network config from stdin, extracts the IPAM section,
# and invokes the host-local plugin to allocate/release IPs.

IPAM_BIN="/opt/cni/bin/host-local"
CONFIG=$(cat)

case "$CNI_COMMAND" in
    ADD)
        # Invoke IPAM to allocate an IP. Pass the full config (host-local
        # reads the ipam section from it).
        IPAM_RESULT=$(echo "$CONFIG" | "$IPAM_BIN")
        IPAM_RC=$?
        if [ $IPAM_RC -ne 0 ]; then
            echo "$IPAM_RESULT"
            exit $IPAM_RC
        fi
        # Return the IPAM result as our result (IPs allocated, no interfaces).
        echo "$IPAM_RESULT"
        ;;
    DEL)
        # Release the IP via IPAM.
        echo "$CONFIG" | "$IPAM_BIN" 2>/dev/null
        echo '{}'
        ;;
    CHECK)
        echo '{}'
        ;;
    VERSION)
        echo '{"cniVersion":"1.0.0","supportedVersions":["0.3.0","0.3.1","0.4.0","1.0.0"]}'
        ;;
esac
NOOP_CNI
chmod +x /opt/cni/bin/noop

# Write the CNI config. The chain is:
#   1. noop — allocates an IP via host-local IPAM (no network devices)
#   2. loopback — sets up lo in each pod namespace
# host-local IPAM assigns IPs from 10.42.0.0/24.
mkdir -p /etc/cni/net.d
cat > /etc/cni/net.d/10-noop.conflist << 'CNI_CONFIG'
{
  "cniVersion": "1.0.0",
  "name": "noop",
  "plugins": [
    {
      "type": "noop",
      "ipam": {
        "type": "host-local",
        "ranges": [
          [{"subnet": "10.42.0.0/24"}]
        ]
      }
    },
    {
      "type": "loopback"
    }
  ]
}
CNI_CONFIG

# Copy bundled manifests if they exist (same as cluster-entrypoint.sh).
K3S_MANIFESTS="/run/k3s/server/manifests"
BUNDLED_MANIFESTS="/opt/navigator/manifests"
if [ -d "$BUNDLED_MANIFESTS" ]; then
    mkdir -p "$K3S_MANIFESTS"
    for manifest in "$BUNDLED_MANIFESTS"/*.yaml; do
        [ ! -f "$manifest" ] && continue
        cp "$manifest" "$K3S_MANIFESTS/"
    done
fi

echo "[vm-init] Starting k3s..."
exec /bin/k3s "$@"
