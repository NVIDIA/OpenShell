#!/bin/sh

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Entrypoint script for OpenShell cluster image.
#
# This script configures DNS resolution for k3s when running in Docker.
#
# Problem: On Docker custom networks, /etc/resolv.conf contains 127.0.0.11
# (Docker's internal DNS). k3s detects this loopback address and automatically
# falls back to 8.8.8.8 - but on Docker Desktop (Mac/Windows), external UDP
# traffic to 8.8.8.8:53 doesn't work due to network limitations. The host
# gateway IP (host.docker.internal) is reachable but doesn't run a DNS server
# either.
#
# Solution: Use iptables to proxy DNS from the container's eth0 IP to Docker's
# embedded DNS resolver at 127.0.0.11. Docker's DNS listens on random high
# ports (visible in the DOCKER_OUTPUT iptables chain), so we parse those ports
# and set up DNAT rules to forward DNS traffic from k3s pods. We then point
# k3s's --resolv-conf at the container's routable eth0 IP.
#
# Per k3s docs: "Manually specified resolver configuration files are not
# subject to viability checks."

set -e

RESOLV_CONF="/etc/rancher/k3s/resolv.conf"

has_default_route() {
    ip -4 route show default 2>/dev/null | grep -q '^default ' \
        || ip -6 route show default 2>/dev/null | grep -q '^default '
}

wait_for_default_route() {
    attempts=${1:-30}
    delay_s=${2:-1}
    i=1

    while [ "$i" -le "$attempts" ]; do
        if has_default_route; then
            return 0
        fi
        sleep "$delay_s"
        i=$((i + 1))
    done

    echo "Error: no default route present before starting k3s"
    echo "IPv4 routes:"
    ip -4 route show 2>/dev/null || true
    echo "IPv6 routes:"
    ip -6 route show 2>/dev/null || true
    echo "/proc/net/route:"
    cat /proc/net/route 2>/dev/null || true
    echo "/proc/net/ipv6_route:"
    cat /proc/net/ipv6_route 2>/dev/null || true
    return 1
}

# ---------------------------------------------------------------------------
# Configure DNS proxy via iptables
# ---------------------------------------------------------------------------
# Docker's embedded DNS (127.0.0.11) is only reachable from the container's
# own network namespace via iptables OUTPUT rules. k3s pods run in separate
# network namespaces and route through PREROUTING, so they can't reach it
# directly. We solve this by:
#   1. Discovering the real DNS listener ports from Docker's iptables rules
#   2. Picking the container's eth0 IP as a routable DNS address
#   3. Adding DNAT rules so traffic to <eth0_ip>:53 reaches Docker's DNS
#   4. Writing that IP into the k3s resolv.conf

setup_dns_proxy() {
    # Extract Docker's actual DNS listener ports from the DOCKER_OUTPUT chain.
    # Docker sets up rules like:
    #   -A DOCKER_OUTPUT -d 127.0.0.11/32 -p udp --dport 53 -j DNAT --to-destination 127.0.0.11:<port>
    #   -A DOCKER_OUTPUT -d 127.0.0.11/32 -p tcp --dport 53 -j DNAT --to-destination 127.0.0.11:<port>
    UDP_PORT=$(iptables -t nat -S DOCKER_OUTPUT 2>/dev/null \
        | grep -- '-p udp.*--dport 53' \
        | sed -n 's/.*--to-destination 127.0.0.11:\([0-9]*\).*/\1/p' \
        | head -1)
    TCP_PORT=$(iptables -t nat -S DOCKER_OUTPUT 2>/dev/null \
        | grep -- '-p tcp.*--dport 53' \
        | sed -n 's/.*--to-destination 127.0.0.11:\([0-9]*\).*/\1/p' \
        | head -1)

    if [ -z "$UDP_PORT" ] || [ -z "$TCP_PORT" ]; then
        echo "Warning: Could not discover Docker DNS ports from iptables"
        echo "  UDP_PORT=${UDP_PORT:-<not found>}  TCP_PORT=${TCP_PORT:-<not found>}"
        return 1
    fi

    # Get the container's routable (non-loopback) IP
    CONTAINER_IP=$(ip -4 addr show eth0 2>/dev/null \
        | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)

    if [ -z "$CONTAINER_IP" ]; then
        echo "Warning: Could not determine container IP from eth0"
        return 1
    fi

    echo "Setting up DNS proxy: ${CONTAINER_IP}:53 -> 127.0.0.11 (udp:${UDP_PORT}, tcp:${TCP_PORT})"

    # Forward DNS from pods (PREROUTING) and local processes (OUTPUT) to Docker's DNS
    iptables -t nat -I PREROUTING -p udp --dport 53 -d "$CONTAINER_IP" -j DNAT \
        --to-destination "127.0.0.11:${UDP_PORT}"
    iptables -t nat -I PREROUTING -p tcp --dport 53 -d "$CONTAINER_IP" -j DNAT \
        --to-destination "127.0.0.11:${TCP_PORT}"

    echo "nameserver $CONTAINER_IP" > "$RESOLV_CONF"
    echo "Configured k3s DNS to use ${CONTAINER_IP} (proxied to Docker DNS)"
}

if ! setup_dns_proxy; then
    echo "DNS proxy setup failed, falling back to public DNS servers"
    echo "Note: this may not work on Docker Desktop (Mac/Windows)"
    cat > "$RESOLV_CONF" <<EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF
fi

# ---------------------------------------------------------------------------
# Verify DNS is functional after proxy setup.
# If resolution fails, the cluster will be unable to pull images and will
# spin for minutes with opaque "Try again" errors. Log a clear marker so
# the CLI polling loop can detect this early and fail fast.
# ---------------------------------------------------------------------------

# Check whether a string looks like an IP address (v4 or v6) with an
# optional port suffix.  When the registry host is an IP literal, DNS
# resolution is not required and we should skip the nslookup probe.
is_ip_literal() {
    # Strip an optional :port suffix
    local host="${1%:*}"
    # IPv4: digits and dots only
    echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && return 0
    # IPv6 (bare or bracketed)
    echo "$host" | grep -qE '^\[?[0-9a-fA-F:]+\]?$' && return 0
    return 1
}

verify_dns() {
    local dns_target="${REGISTRY_HOST:-ghcr.io}"

    # IP-literal registry hosts (e.g. 127.0.0.1:5000) don't need DNS.
    if is_ip_literal "$dns_target"; then
        echo "Registry host is an IP literal ($dns_target), skipping DNS probe"
        return 0
    fi

    # Strip port suffix — nslookup doesn't understand host:port.
    local lookup_host="${dns_target%%:*}"

    local attempts=5
    local i=1
    while [ "$i" -le "$attempts" ]; do
        if nslookup "$lookup_host" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

if ! verify_dns; then
    echo "DNS_PROBE_FAILED: cannot resolve ${REGISTRY_HOST:-ghcr.io} after DNS proxy setup"
    echo "  resolv.conf: $(cat "$RESOLV_CONF")"
    echo "  This usually means Docker DNS forwarding is broken."
    echo "  Try restarting Docker or pruning networks: docker network prune -f"
    # Don't exit — let k3s start so the Rust-side polling loop can detect the
    # failure via the log marker and present a user-friendly diagnosis.
fi

# ---------------------------------------------------------------------------
# Generate k3s private registry configuration
# ---------------------------------------------------------------------------
# Write registries.yaml so k3s/containerd can authenticate when pulling
# component and community sandbox images from the registry at runtime.
# Credentials are passed as environment variables by the bootstrap code.
REGISTRIES_YAML="/etc/rancher/k3s/registries.yaml"
if [ -n "${REGISTRY_HOST:-}" ]; then
    REGISTRY_SCHEME="https"
    REGISTRY_ENDPOINT="${REGISTRY_ENDPOINT:-${REGISTRY_HOST}}"
    insecure_value=$(printf '%s' "${REGISTRY_INSECURE:-false}" | tr '[:upper:]' '[:lower:]')
    if [ "$insecure_value" = "true" ] || [ "$insecure_value" = "1" ] || [ "$insecure_value" = "yes" ] || [ "$insecure_value" = "on" ]; then
        REGISTRY_SCHEME="http"
    fi

    echo "Configuring registry mirror for ${REGISTRY_HOST} via ${REGISTRY_ENDPOINT} (${REGISTRY_SCHEME})"
    cat > "$REGISTRIES_YAML" <<REGEOF
mirrors:
  "${REGISTRY_HOST}":
    endpoint:
      - "${REGISTRY_SCHEME}://${REGISTRY_ENDPOINT}"

REGEOF

    # If the community registry is a separate host (e.g. we're using a
    # local registry for component images), add it as an additional mirror
    # so community sandbox images can be pulled at runtime.
    if [ -n "${COMMUNITY_REGISTRY_HOST:-}" ] && [ "${COMMUNITY_REGISTRY_HOST}" != "${REGISTRY_HOST}" ]; then
        echo "Adding community registry mirror for ${COMMUNITY_REGISTRY_HOST}"
        cat >> "$REGISTRIES_YAML" <<REGEOF
  "${COMMUNITY_REGISTRY_HOST}":
    endpoint:
      - "https://${COMMUNITY_REGISTRY_HOST}"
REGEOF
    fi

    if [ -n "${REGISTRY_USERNAME:-}" ] && [ -n "${REGISTRY_PASSWORD:-}" ]; then
        cat >> "$REGISTRIES_YAML" <<REGEOF

configs:
  "${REGISTRY_HOST}":
    auth:
      username: ${REGISTRY_USERNAME}
      password: ${REGISTRY_PASSWORD}
REGEOF
    fi

    # Add auth for the community registry when it differs from the
    # primary registry (community sandbox images live there).
    if [ -n "${COMMUNITY_REGISTRY_HOST:-}" ] && [ "${COMMUNITY_REGISTRY_HOST}" != "${REGISTRY_HOST}" ] \
       && [ -n "${COMMUNITY_REGISTRY_USERNAME:-}" ] && [ -n "${COMMUNITY_REGISTRY_PASSWORD:-}" ]; then
        # Append to existing configs block or start a new one.
        if [ -n "${REGISTRY_USERNAME:-}" ] && [ -n "${REGISTRY_PASSWORD:-}" ]; then
            # configs: block already started above — just append the entry.
            cat >> "$REGISTRIES_YAML" <<REGEOF
  "${COMMUNITY_REGISTRY_HOST}":
    auth:
      username: ${COMMUNITY_REGISTRY_USERNAME}
      password: ${COMMUNITY_REGISTRY_PASSWORD}
REGEOF
        else
            cat >> "$REGISTRIES_YAML" <<REGEOF

configs:
  "${COMMUNITY_REGISTRY_HOST}":
    auth:
      username: ${COMMUNITY_REGISTRY_USERNAME}
      password: ${COMMUNITY_REGISTRY_PASSWORD}
REGEOF
        fi
    fi
else
    echo "Warning: REGISTRY_HOST not set; skipping registry config"
fi

# Copy bundled Helm chart tarballs to the k3s static charts directory.
# These are stored in /opt/openshell/charts/ because the volume mount
# on /var/lib/rancher/k3s overwrites any files baked into that path.
# Without this, a persistent volume from a previous deploy would keep
# serving stale chart tarballs.
K3S_CHARTS="/var/lib/rancher/k3s/server/static/charts"
BUNDLED_CHARTS="/opt/openshell/charts"
CHART_CHECKSUM=""

if [ -d "$BUNDLED_CHARTS" ]; then
    echo "Copying bundled charts to k3s..."
    for chart in "$BUNDLED_CHARTS"/*.tgz; do
        [ ! -f "$chart" ] && continue
        cp "$chart" "$K3S_CHARTS/"
    done
    # Compute a checksum of the openshell chart so we can inject it into the
    # HelmChart manifest below. When the chart content changes between image
    # versions the checksum changes, which modifies the HelmChart CR spec and
    # forces the k3s Helm controller to re-install.
    OPENSHELL_CHART="$BUNDLED_CHARTS/openshell-0.1.0.tgz"
    if [ -f "$OPENSHELL_CHART" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            CHART_CHECKSUM=$(sha256sum "$OPENSHELL_CHART" | cut -d ' ' -f 1)
        elif command -v shasum >/dev/null 2>&1; then
            CHART_CHECKSUM=$(shasum -a 256 "$OPENSHELL_CHART" | cut -d ' ' -f 1)
        fi
    fi
fi

# Copy bundled manifests to k3s manifests directory.
# These are stored in /opt/openshell/manifests/ because the volume mount
# on /var/lib/rancher/k3s overwrites any files baked into that path.
#
# When reusing a persistent volume from a previous deploy, stale manifests
# (e.g. envoy-gateway-helmchart.yaml from an older image) may linger.
# We remove any openshell-managed manifests that no longer exist in the
# bundled set so k3s does not keep installing removed components.
K3S_MANIFESTS="/var/lib/rancher/k3s/server/manifests"
BUNDLED_MANIFESTS="/opt/openshell/manifests"

if [ -d "$BUNDLED_MANIFESTS" ]; then
    echo "Copying bundled manifests to k3s..."
    for manifest in "$BUNDLED_MANIFESTS"/*.yaml; do
        [ ! -f "$manifest" ] && continue
        cp "$manifest" "$K3S_MANIFESTS/"
    done

    # Remove openshell-managed manifests that are no longer bundled.
    # Only clean up files that look like openshell manifests (openshell-* or
    # envoy-gateway-* or agent-*) to avoid removing built-in k3s manifests.
    for existing in "$K3S_MANIFESTS"/openshell-*.yaml \
                    "$K3S_MANIFESTS"/navigator-*.yaml \
                    "$K3S_MANIFESTS"/envoy-gateway-*.yaml \
                    "$K3S_MANIFESTS"/agent-*.yaml; do
        [ ! -f "$existing" ] && continue
        basename=$(basename "$existing")
        if [ ! -f "$BUNDLED_MANIFESTS/$basename" ]; then
            echo "Removing stale manifest: $basename"
            rm -f "$existing"
        fi
    done
fi

# ---------------------------------------------------------------------------
# GPU support: deploy NVIDIA device plugin when GPU_ENABLED=true
# ---------------------------------------------------------------------------
# When the cluster is started with --gpu, the bootstrap code sets
# GPU_ENABLED=true. This copies the NVIDIA device plugin HelmChart CR into
# the k3s manifests directory so the Helm controller installs it automatically.
# The nvidia-container-runtime binary is already on PATH (baked into the image)
# so k3s registers the "nvidia" RuntimeClass at startup.
if [ "${GPU_ENABLED:-}" = "true" ]; then
    echo "GPU support enabled — deploying NVIDIA device plugin"

    GPU_MANIFESTS="/opt/openshell/gpu-manifests"
    if [ -d "$GPU_MANIFESTS" ]; then
        for manifest in "$GPU_MANIFESTS"/*.yaml; do
            [ ! -f "$manifest" ] && continue
            cp "$manifest" "$K3S_MANIFESTS/"
        done
    fi
fi

# ---------------------------------------------------------------------------
# Override image tag and pull policy for local development
# ---------------------------------------------------------------------------
# When IMAGE_TAG is set, replace the default ":latest" tag on all component
# images in the HelmChart manifest so k3s deploys the locally-pushed versions.
# When IMAGE_PULL_POLICY is set, override the default "Always" so k3s uses
# images already present in containerd instead of pulling from the registry.
HELMCHART="/var/lib/rancher/k3s/server/manifests/openshell-helmchart.yaml"

if [ -n "${IMAGE_REPO_BASE:-}" ] && [ -f "$HELMCHART" ]; then
    echo "Setting image repository base: ${IMAGE_REPO_BASE}"
    sed -i -E "s|repository:[[:space:]]*[^[:space:]]+|repository: ${IMAGE_REPO_BASE}/gateway|" "$HELMCHART"
    # Sandbox images come from the community registry — do not override
fi

# In push mode, use the exact image references that were imported into cluster
# containerd so the Helm release cannot drift back to remote ":latest" tags.
# Only the gateway image is pushed; sandbox images are pulled from the
# community registry at runtime.
if [ -n "${PUSH_IMAGE_REFS:-}" ] && [ -f "$HELMCHART" ]; then
    server_image=""
    old_ifs="$IFS"
    IFS=','
    for ref in $PUSH_IMAGE_REFS; do
        case "$ref" in
            */gateway:*) server_image="$ref" ;;
        esac
    done
    IFS="$old_ifs"

    if [ -n "$server_image" ]; then
        server_repo="${server_image%:*}"
        server_tag="${server_image##*:}"
        echo "Setting server image repository: ${server_repo}"
        echo "Setting server image tag: ${server_tag}"
        sed -i -E "s|repository:[[:space:]]*[^[:space:]]+|repository: ${server_repo}|" "$HELMCHART"
        sed -i -E "s|tag:[[:space:]]*\"?[^\"[:space:]]+\"?|tag: \"${server_tag}\"|" "$HELMCHART"
    fi
fi

if [ -n "${IMAGE_TAG:-}" ] && [ -f "$HELMCHART" ]; then
    echo "Overriding gateway image tag to: ${IMAGE_TAG}"
    # server image tag (standalone value field)
    # Handle both quoted and unquoted defaults: tag: "latest" / tag: latest
    sed -i -E "s|tag:[[:space:]]*\"?latest\"?|tag: \"${IMAGE_TAG}\"|" "$HELMCHART"
fi

if [ -n "${IMAGE_PULL_POLICY:-}" ] && [ -f "$HELMCHART" ]; then
    echo "Overriding image pull policy to: ${IMAGE_PULL_POLICY}"
    sed -i "s|pullPolicy: Always|pullPolicy: ${IMAGE_PULL_POLICY}|" "$HELMCHART"
fi

# Generate a random SSH handshake secret for the NSSH1 HMAC handshake between
# the gateway and sandbox SSH servers. This is required — the server will refuse
# to start without it.
SSH_HANDSHAKE_SECRET="${SSH_HANDSHAKE_SECRET:-$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')}"

# Inject SSH gateway host/port into the HelmChart manifest so the navigator
# server returns the correct address to CLI clients for SSH proxy CONNECT.
if [ -f "$HELMCHART" ]; then
    if [ -n "$SSH_GATEWAY_HOST" ]; then
        echo "Setting SSH gateway host: $SSH_GATEWAY_HOST"
        sed -i "s|__SSH_GATEWAY_HOST__|${SSH_GATEWAY_HOST}|g" "$HELMCHART"
    else
        # Clear the placeholder so the default (127.0.0.1) is used
        sed -i "s|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: \"\"|g" "$HELMCHART"
    fi
    if [ -n "$SSH_GATEWAY_PORT" ]; then
        echo "Setting SSH gateway port: $SSH_GATEWAY_PORT"
        sed -i "s|__SSH_GATEWAY_PORT__|${SSH_GATEWAY_PORT}|g" "$HELMCHART"
    else
        # Clear the placeholder so the default (8080) is used
        sed -i "s|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g" "$HELMCHART"
    fi
    echo "Setting SSH handshake secret"
    sed -i "s|__SSH_HANDSHAKE_SECRET__|${SSH_HANDSHAKE_SECRET}|g" "$HELMCHART"

    # Disable gateway auth: when set, the server accepts connections without
    # client certificates (for reverse-proxy / Cloudflare Tunnel deployments).
    if [ "${DISABLE_GATEWAY_AUTH:-}" = "true" ]; then
        echo "Disabling gateway auth (mTLS client cert not required)"
        sed -i "s|__DISABLE_GATEWAY_AUTH__|true|g" "$HELMCHART"
    else
        sed -i "s|__DISABLE_GATEWAY_AUTH__|false|g" "$HELMCHART"
    fi

    # Disable TLS entirely: the server listens on plaintext HTTP.
    # Used when a reverse proxy / tunnel terminates TLS at the edge.
    if [ "${DISABLE_TLS:-}" = "true" ]; then
        echo "Disabling TLS (plaintext HTTP)"
        sed -i "s|__DISABLE_TLS__|true|g" "$HELMCHART"
        # The Helm template automatically rewrites https:// to http:// in
        # OPENSHELL_GRPC_ENDPOINT when disableTls is true, so no sed needed here.
    else
        sed -i "s|__DISABLE_TLS__|false|g" "$HELMCHART"
    fi
fi

# Inject chart checksum into the HelmChart manifest so that a changed chart
# tarball causes the HelmChart CR spec to differ, forcing the k3s Helm
# controller to upgrade the release.
if [ -n "$CHART_CHECKSUM" ] && [ -f "$HELMCHART" ]; then
    echo "Injecting chart checksum: ${CHART_CHECKSUM}"
    sed -i "s|__CHART_CHECKSUM__|${CHART_CHECKSUM}|g" "$HELMCHART"
else
    # Remove the placeholder line entirely so invalid YAML isn't left behind
    sed -i '/__CHART_CHECKSUM__/d' "$HELMCHART"
fi

# ---------------------------------------------------------------------------
# Ensure flannel CNI directories exist
# ---------------------------------------------------------------------------
# k3s uses flannel as its default CNI. Flannel writes subnet configuration to
# /run/flannel/subnet.env during startup. When running inside a Docker
# container, /run/flannel/ may not exist, causing a race where kubelet tries
# to create pod sandboxes before flannel can write the file. Without it, every
# pod (including CoreDNS) fails with:
#   plugin type="flannel" failed (add): failed to load flannel 'subnet.env'
# Pre-creating the directory eliminates this failure mode.
mkdir -p /run/flannel

# Docker Desktop can briefly start the container before its bridge default route
# is fully installed. k3s exits immediately in that state, so wait briefly for
# routing to settle first.
wait_for_default_route

# Execute k3s with explicit resolv-conf.
exec /bin/k3s "$@" --resolv-conf="$RESOLV_CONF"
