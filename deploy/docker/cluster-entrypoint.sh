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
# k3s's resolv-conf kubelet arg at the container's routable eth0 IP.
#
# Per k3s docs: "Manually specified resolver configuration files are not
# subject to viability checks."

set -e

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# Escape a value for safe embedding as a YAML single-quoted scalar.
# Single quotes are the only character that needs escaping ('  ->  '').
yaml_quote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

# ---------------------------------------------------------------------------
# Select iptables backend
# ---------------------------------------------------------------------------
# Some kernels (e.g. Jetson Linux 5.15-tegra) have the nf_tables subsystem
# but lack the nft_compat bridge that allows flannel and kube-proxy to use
# xt extension modules (xt_comment, xt_conntrack). Detect this by probing
# whether xt_comment is usable via the current iptables backend. If the
# probe fails, switch to iptables-legacy. Set USE_IPTABLES_LEGACY=1
# externally to skip the probe and force the legacy backend.
# ---------------------------------------------------------------------------
# Check br_netfilter kernel module
# ---------------------------------------------------------------------------
# br_netfilter makes the kernel pass bridge (pod-to-pod) traffic through
# iptables. Without it, kube-proxy's DNAT rules for ClusterIP services are
# never applied to pod traffic, so pods cannot reach services such as
# kube-dns (10.43.0.10), breaking all in-cluster DNS resolution.
#
# The module must be loaded on the HOST before the container starts —
# containers cannot load kernel modules themselves. If it is missing, log a
# warning rather than failing hard: some kernels have bridge netfilter support
# built-in or expose it differently, and will work correctly without the module
# being explicitly loaded as a separate .ko.
if [ ! -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    echo "Warning: br_netfilter does not appear to be loaded on the host." >&2
    echo "         Pod-to-service networking (including kube-dns) may not work without it." >&2
    echo "         If the cluster fails to start or DNS is broken, try loading it on the host:" >&2
    echo "           sudo modprobe br_netfilter" >&2
    echo "         To persist across reboots:" >&2
    echo "           echo br_netfilter | sudo tee /etc/modules-load.d/br_netfilter.conf" >&2
fi

if [ -z "${USE_IPTABLES_LEGACY:-}" ]; then
    if iptables -t filter -N _xt_probe 2>/dev/null; then
        _probe_rc=0
        iptables -t filter -A _xt_probe -m comment --comment "probe" -j ACCEPT \
            2>/dev/null || _probe_rc=$?
        iptables -t filter -D _xt_probe -m comment --comment "probe" -j ACCEPT \
            2>/dev/null || true
        iptables -t filter -X _xt_probe 2>/dev/null || true
        [ "$_probe_rc" -ne 0 ] && USE_IPTABLES_LEGACY=1
    fi
fi

if [ "${USE_IPTABLES_LEGACY:-0}" = "1" ]; then
    echo "iptables nf_tables xt extension bridge unavailable — switching to iptables-legacy"
    if update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null && \
       update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null; then
        echo "Now using iptables-legacy mode"
    else
        echo "Warning: could not switch to iptables-legacy — cluster networking may fail"
    fi
fi

IPTABLES=$([ "${USE_IPTABLES_LEGACY:-0}" = "1" ] && echo iptables-legacy || echo iptables)

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
    UDP_PORT=$($IPTABLES -t nat -S DOCKER_OUTPUT 2>/dev/null \
        | grep -- '-p udp.*--dport 53' \
        | sed -n 's/.*--to-destination 127.0.0.11:\([0-9]*\).*/\1/p' \
        | head -1)
    TCP_PORT=$($IPTABLES -t nat -S DOCKER_OUTPUT 2>/dev/null \
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
    $IPTABLES -t nat -I PREROUTING -p udp --dport 53 -d "$CONTAINER_IP" -j DNAT \
        --to-destination "127.0.0.11:${UDP_PORT}"
    $IPTABLES -t nat -I PREROUTING -p tcp --dport 53 -d "$CONTAINER_IP" -j DNAT \
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
      username: $(yaml_quote "${REGISTRY_USERNAME}")
      password: $(yaml_quote "${REGISTRY_PASSWORD}")
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
      username: $(yaml_quote "${COMMUNITY_REGISTRY_USERNAME}")
      password: $(yaml_quote "${COMMUNITY_REGISTRY_PASSWORD}")
REGEOF
        else
            cat >> "$REGISTRIES_YAML" <<REGEOF

configs:
  "${COMMUNITY_REGISTRY_HOST}":
    auth:
      username: $(yaml_quote "${COMMUNITY_REGISTRY_USERNAME}")
      password: $(yaml_quote "${COMMUNITY_REGISTRY_PASSWORD}")
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
# Detect host gateway IP for sandbox pod hostAliases
# ---------------------------------------------------------------------------
# Sandbox pods need to reach services running on the Docker host (e.g.
# provider endpoints during local development). On Docker Desktop,
# host.docker.internal resolves to a special host-reachable IP that is NOT the
# bridge default gateway, so prefer Docker's own resolution when available.
# Fall back to the container default gateway on Linux engines where
# host.docker.internal commonly maps to the bridge gateway anyway.
HOST_GATEWAY_IP=$(getent ahostsv4 host.docker.internal 2>/dev/null | awk 'NR == 1 { print $1; exit }')
if [ -n "$HOST_GATEWAY_IP" ]; then
    echo "Detected host gateway IP from host.docker.internal: $HOST_GATEWAY_IP"
else
    HOST_GATEWAY_IP=$(ip -4 route | awk '/default/ { print $3; exit }')
    if [ -n "$HOST_GATEWAY_IP" ]; then
        echo "Detected host gateway IP from default route: $HOST_GATEWAY_IP"
    else
        echo "Warning: Could not detect host gateway IP from host.docker.internal or default route"
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
# Gateway and supervisor images may be pushed; sandbox base images are pulled
# from the community registry at runtime.
if [ -n "${PUSH_IMAGE_REFS:-}" ] && [ -f "$HELMCHART" ]; then
    server_image=""
    supervisor_image=""
    old_ifs="$IFS"
    IFS=','
    for ref in $PUSH_IMAGE_REFS; do
        case "$ref" in
            */gateway:*) server_image="$ref" ;;
            */supervisor:*) supervisor_image="$ref" ;;
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

    if [ -n "$supervisor_image" ]; then
        echo "Setting supervisor image: ${supervisor_image}"
        sed -i -E "s|supervisorImage:[[:space:]]*\"?[^\"]+\"?|supervisorImage: ${supervisor_image}|" "$HELMCHART"
    fi
fi

if [ -n "${IMAGE_TAG:-}" ] && [ -f "$HELMCHART" ]; then
    echo "Overriding gateway and supervisor image tags to: ${IMAGE_TAG}"
    # server image tag (standalone value field)
    # Handle both quoted and unquoted defaults: tag: "latest" / tag: latest
    sed -i -E "s|tag:[[:space:]]*\"?latest\"?|tag: \"${IMAGE_TAG}\"|" "$HELMCHART"
    # supervisor image is a full image ref under server.supervisorImage
    sed -i -E "s|(supervisorImage:[[:space:]]*\"?[^\"]*:)[^\"[:space:]]+(\"?)|\\1${IMAGE_TAG}\\2|" "$HELMCHART"
fi

if [ -f "$HELMCHART" ]; then
    IMAGE_PULL_POLICY_VALUE="${IMAGE_PULL_POLICY:-Always}"
    if [ -n "${IMAGE_PULL_POLICY:-}" ]; then
        echo "Overriding image pull policy to: ${IMAGE_PULL_POLICY}"
    fi
    sed -i "s|__IMAGE_PULL_POLICY__|${IMAGE_PULL_POLICY_VALUE}|g" "$HELMCHART"

    SANDBOX_IMAGE_PULL_POLICY_VALUE="${SANDBOX_IMAGE_PULL_POLICY:-\"\"}"
    sed -i "s|__SANDBOX_IMAGE_PULL_POLICY__|${SANDBOX_IMAGE_PULL_POLICY_VALUE}|g" "$HELMCHART"

    DB_URL_VALUE="${DB_URL:-\"sqlite:/var/openshell/openshell.db\"}"
    sed -i "s|__DB_URL__|${DB_URL_VALUE}|g" "$HELMCHART"
fi

# SSH handshake secret: previously generated here and injected via sed into the
# HelmChart CR. Now persisted as a Kubernetes Secret (openshell-ssh-handshake)
# created by the bootstrap process after k3s starts. This ensures the secret
# survives container restarts without regeneration.

# Inject SSH gateway host/port into the HelmChart manifest so the openshell
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
    # Disable gateway auth: when set, the server accepts connections without
    # client certificates (for reverse-proxy / Cloudflare Tunnel deployments).
    if [ "${DISABLE_GATEWAY_AUTH:-}" = "true" ]; then
        echo "Disabling gateway auth (mTLS client cert not required)"
        sed -i "s|__DISABLE_GATEWAY_AUTH__|true|g" "$HELMCHART"
    else
        sed -i "s|__DISABLE_GATEWAY_AUTH__|false|g" "$HELMCHART"
    fi

    # OIDC JWT authentication: when OIDC_ISSUER is set, the server validates
    # Bearer tokens on gRPC requests against the issuer's JWKS endpoint.
    if [ -n "${OIDC_ISSUER:-}" ]; then
        echo "Enabling OIDC authentication (issuer: ${OIDC_ISSUER})"
        sed -i "s|__OIDC_ISSUER__|${OIDC_ISSUER}|g" "$HELMCHART"
        sed -i "s|__OIDC_AUDIENCE__|${OIDC_AUDIENCE:-openshell-cli}|g" "$HELMCHART"
        sed -i "s|__OIDC_ROLES_CLAIM__|${OIDC_ROLES_CLAIM:-realm_access.roles}|g" "$HELMCHART"
        sed -i "s|__OIDC_ADMIN_ROLE__|${OIDC_ADMIN_ROLE:-openshell-admin}|g" "$HELMCHART"
        sed -i "s|__OIDC_USER_ROLE__|${OIDC_USER_ROLE:-openshell-user}|g" "$HELMCHART"
        sed -i "s|__OIDC_SCOPES_CLAIM__|${OIDC_SCOPES_CLAIM:-}|g" "$HELMCHART"
    else
        sed -i "s|__OIDC_ISSUER__||g" "$HELMCHART"
        sed -i "s|__OIDC_AUDIENCE__|openshell-cli|g" "$HELMCHART"
        sed -i "s|__OIDC_ROLES_CLAIM__||g" "$HELMCHART"
        sed -i "s|__OIDC_ADMIN_ROLE__||g" "$HELMCHART"
        sed -i "s|__OIDC_USER_ROLE__||g" "$HELMCHART"
        sed -i "s|__OIDC_SCOPES_CLAIM__||g" "$HELMCHART"
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

# Inject host gateway IP into the HelmChart manifest so sandbox pods can
# reach services on the Docker host via host.docker.internal / host.openshell.internal.
if [ -n "$HOST_GATEWAY_IP" ] && [ -f "$HELMCHART" ]; then
    echo "Setting host gateway IP: $HOST_GATEWAY_IP"
    sed -i "s|__HOST_GATEWAY_IP__|${HOST_GATEWAY_IP}|g" "$HELMCHART"
else
    # Clear the placeholder so the server gets an empty string (feature disabled)
    sed -i "s|hostGatewayIP: __HOST_GATEWAY_IP__|hostGatewayIP: \"\"|g" "$HELMCHART"
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

# ---------------------------------------------------------------------------
# Detect cgroup version and set kubelet compatibility flags
# ---------------------------------------------------------------------------
# Kubernetes 1.35+ (k3s v1.35.x) rejects cgroup v1 by default. Hosts running
# older distros (e.g. Rocky Linux 8, CentOS 7/8, Ubuntu 18.04) still use
# cgroup v1. When we detect cgroup v1, pass --kubelet-arg=fail-cgroupv1=false
# so kubelet warns instead of refusing to start. This flag can be removed once
# cgroup v1 support is no longer needed.
EXTRA_KUBELET_ARGS=""
if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo "Detected cgroup v1 — adding kubelet compatibility flag (fail-cgroupv1=false)"
    EXTRA_KUBELET_ARGS="--kubelet-arg=fail-cgroupv1=false"
fi

# On kernels where xt_comment is unavailable, kube-router's network policy
# controller panics at startup. Disable it when the iptables-legacy probe
# triggered; sandbox isolation is enforced by the NSSH1 HMAC handshake instead.
if [ "${USE_IPTABLES_LEGACY:-0}" = "1" ]; then
    EXTRA_KUBELET_ARGS="$EXTRA_KUBELET_ARGS --disable-network-policy"
fi

# Docker Desktop can briefly start the container before its bridge default route
# is fully installed. k3s exits immediately in that state, so wait briefly for
# routing to settle first.
wait_for_default_route

# ---------------------------------------------------------------------------
# Deterministic k3s node name
# ---------------------------------------------------------------------------
# By default k3s uses the container hostname (= Docker container ID) as the
# node name.  When the container is recreated (e.g. after an image upgrade),
# the container ID changes, registering a new k3s node.  The bootstrap code
# then deletes PVCs whose backing PVs have node affinity for the old node —
# wiping the server database and any sandbox persistent volumes.
#
# OPENSHELL_NODE_NAME is set by the bootstrap code to a deterministic value
# derived from the gateway name, so the node identity survives container
# recreation and PVCs are never orphaned.
NODE_NAME_ARG=""
if [ -n "${OPENSHELL_NODE_NAME:-}" ]; then
    NODE_NAME_ARG="--node-name=${OPENSHELL_NODE_NAME}"
    echo "Using deterministic k3s node name: ${OPENSHELL_NODE_NAME}"
fi

# Execute k3s with explicit resolv-conf passed as a kubelet arg.
# k3s v1.35.2+ no longer accepts --resolv-conf as a top-level server flag;
# it must be passed via --kubelet-arg instead.
# shellcheck disable=SC2086
exec /bin/k3s "$@" $NODE_NAME_ARG --kubelet-arg=resolv-conf="$RESOLV_CONF" $EXTRA_KUBELET_ARGS
