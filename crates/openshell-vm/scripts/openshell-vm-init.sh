#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Init script for the openshell-vm microVM. Runs as PID 1 inside the libkrun VM.
#
# Mounts essential virtual filesystems, configures networking, then execs
# k3s server. If the rootfs was pre-initialized by build-rootfs.sh (sentinel
# at /opt/openshell/.initialized), the full manifest setup is skipped and
# k3s resumes from its persisted state (~3-5s startup).

set -e

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
        udhcpc -i eth0 -f -q -n -T 1 -t 3 -A 1 -s "$UDHCPC_SCRIPT" 2>&1 || true
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
    NODE_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[^/]+' || echo "192.168.127.2")
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

# Clean stale runtime artifacts from previous boots (virtio-fs persists
# the rootfs between VM restarts).
rm -rf /var/lib/rancher/k3s/server/tls/temporary-certs 2>/dev/null || true
rm -f  /var/lib/rancher/k3s/server/kine.sock           2>/dev/null || true
# Clean stale node password so k3s doesn't fail validation on reboot.
# Each k3s start generates a new random node password; the old hash in
# the database will not match. Removing the local password file forces
# k3s to re-register with a fresh one.
rm -f /var/lib/rancher/k3s/server/cred/node-passwd      2>/dev/null || true
# Also clean any stale pid files and unix sockets
find /var/lib/rancher/k3s -name '*.sock' -delete 2>/dev/null || true
find /run -name '*.sock' -delete 2>/dev/null || true

# Clean stale containerd runtime state from previous boots.
#
# The rootfs persists across VM restarts via virtio-fs. The overlayfs
# snapshotter is backed by tmpfs (see below), so snapshot layer data is
# wiped on every boot. We must also delete meta.db because it contains
# snapshot metadata (parent chain references) that become invalid once
# the tmpfs is remounted. If meta.db survives but the snapshot dirs
# don't, containerd fails every pod with:
#   "missing parent <sha256:...> bucket: not found"
# because it tries to look up snapshot parents that no longer exist.
#
# Deleting meta.db is safe: containerd rebuilds it on startup by
# re-importing the pre-baked image tarballs from
# /var/lib/rancher/k3s/agent/images/ (adds ~3s to boot). The content
# store blobs on virtio-fs are preserved so no network pulls are needed.
#
# The kine (SQLite) DB cleanup in build-rootfs.sh already removes stale
# pod/sandbox records from k3s etcd, preventing kubelet from reconciling
# against stale sandboxes.
CONTAINERD_DIR="/var/lib/rancher/k3s/agent/containerd"
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
    # Delete meta.db — snapshot metadata references are invalidated by
    # the tmpfs remount below. containerd will rebuild it from the
    # pre-baked image tarballs on startup.
    rm -f "${CONTAINERD_DIR}/io.containerd.metadata.v1.bolt/meta.db" 2>/dev/null || true
    ts "cleaned containerd runtime state (reset meta.db + content store preserved)"
fi
rm -rf /run/k3s 2>/dev/null || true

# Mount tmpfs for the overlayfs snapshotter upper/work directories.
# The overlayfs snapshotter on virtio-fs fails with "network dropped
# connection on reset" when runc tries to create bind mount targets
# inside the overlay. This is because virtio-fs (FUSE) doesn't fully
# support the file operations overlayfs needs in the upper layer.
# Using tmpfs (backed by RAM) for the snapshotter directory avoids
# this issue entirely. With 8GB VM RAM, this leaves ~6GB for image
# layers which is sufficient for typical sandbox workloads.
OVERLAYFS_DIR="${CONTAINERD_DIR}/io.containerd.snapshotter.v1.overlayfs"
mkdir -p "$OVERLAYFS_DIR"
mount -t tmpfs -o size=4g tmpfs "$OVERLAYFS_DIR"
ts "mounted tmpfs for overlayfs snapshotter (4GB)"

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
for veth in $(ip -o link show type veth 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1); do
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
    for ns in $(ip netns list 2>/dev/null | awk '{print $1}'); do
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
    # Use pre-loaded images — don't pull from registry.
    sed -i 's|__IMAGE_PULL_POLICY__|IfNotPresent|g' "$HELMCHART"
    sed -i 's|__SANDBOX_IMAGE_PULL_POLICY__|IfNotPresent|g' "$HELMCHART"

    # Bridge CNI: pods use normal pod networking, not hostNetwork.
    # The pre-init in build-rootfs.sh replaces __HOST_NETWORK__ with "true"
    # for Docker container networking. At VM boot with bridge CNI we need
    # to override it back to "false" so pods use the CNI bridge network.
    sed -i 's|hostNetwork: true|hostNetwork: false|g' "$HELMCHART"
    sed -i 's|__HOST_NETWORK__|false|g' "$HELMCHART"
    sed -i 's|__AUTOMOUNT_SA_TOKEN__|true|g' "$HELMCHART"

    sed -i 's|__PERSISTENCE_ENABLED__|false|g' "$HELMCHART"
    sed -i 's|__DB_URL__|"sqlite:/tmp/openshell.db"|g' "$HELMCHART"
    # Clear SSH gateway placeholders (default 127.0.0.1 is correct for local VM).
    sed -i 's|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: ""|g' "$HELMCHART"
    sed -i 's|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g' "$HELMCHART"
    # Generate a random SSH handshake secret for this boot.
    SSH_SECRET=$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')
    sed -i "s|__SSH_HANDSHAKE_SECRET__|${SSH_SECRET}|g" "$HELMCHART"
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
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# Enable bridge netfilter call (required for CNI bridge masquerade to
# see bridged traffic).
if [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || true
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
        | grep -v '\-tmp/' | head -1
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

# ── PKI: generate once, write TLS secrets manifest every boot ──────────
# Certs are generated on first boot and stored at /opt/openshell/pki/.
# They survive --reset (which only wipes k3s server/agent state).
# The host-side bootstrap reads them from the rootfs via virtio-fs and
# copies the client certs to ~/.config/openshell/gateways/<name>/mtls/.

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
    # blocking image pulls and pod scheduling. Disable disk eviction
    # thresholds since the VM shares the host filesystem.
    "--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%"
    "--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%"
    --kubelet-arg=image-gc-high-threshold=99
    --kubelet-arg=image-gc-low-threshold=98
    # Increase CRI runtime timeout for large image operations. The native
    # snapshotter on virtio-fs is slow for large images (~1GB sandbox base);
    # the default 2m timeout causes CreateContainer failures.
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
    sqlite3 "$KINE_DB" "DELETE FROM kine WHERE name LIKE '/bootstrap/%';" 2>/dev/null || true
    sqlite3 "$KINE_DB" "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null || true
fi

exec /usr/local/bin/k3s server "${K3S_ARGS[@]}"
