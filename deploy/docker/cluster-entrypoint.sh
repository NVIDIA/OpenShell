#!/bin/sh
# Entrypoint script for navigator-cluster image.
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
# Generate k3s private registry configuration
# ---------------------------------------------------------------------------
# Write registries.yaml so k3s/containerd can authenticate when pulling
# component images from the distribution registry at runtime.
# Credentials are passed as environment variables by the bootstrap code.
REGISTRIES_YAML="/etc/rancher/k3s/registries.yaml"
if [ -n "$REGISTRY_HOST" ] && [ -n "$REGISTRY_USERNAME" ] && [ -n "$REGISTRY_PASSWORD" ]; then
    echo "Configuring registry credentials for distribution registry"
    cat > "$REGISTRIES_YAML" <<REGEOF
mirrors:
  "${REGISTRY_HOST}":
    endpoint:
      - "https://${REGISTRY_HOST}"

configs:
  "${REGISTRY_HOST}":
    auth:
      username: ${REGISTRY_USERNAME}
      password: ${REGISTRY_PASSWORD}
REGEOF
else
    echo "Warning: REGISTRY_HOST, REGISTRY_USERNAME, or REGISTRY_PASSWORD not set; skipping registry config"
fi

# Copy bundled manifests to k3s manifests directory.
# These are stored in /opt/navigator/manifests/ because the volume mount
# on /var/lib/rancher/k3s overwrites any files baked into that path.
if [ -d "/opt/navigator/manifests" ]; then
    echo "Copying bundled manifests to k3s..."
    cp /opt/navigator/manifests/*.yaml /var/lib/rancher/k3s/server/manifests/ 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Override image tag and pull policy for local development
# ---------------------------------------------------------------------------
# When IMAGE_TAG is set, replace the default ":latest" tag on all component
# images in the HelmChart manifest so k3s deploys the locally-pushed versions.
# When IMAGE_PULL_POLICY is set, override the default "Always" so k3s uses
# images already present in containerd instead of pulling from the registry.
HELMCHART="/var/lib/rancher/k3s/server/manifests/navigator-helmchart.yaml"

# In push mode, use the exact image references that were imported into cluster
# containerd so the Helm release cannot drift back to remote ":latest" tags.
if [ -n "${PUSH_IMAGE_REFS:-}" ] && [ -f "$HELMCHART" ]; then
    server_image=""
    sandbox_image=""
    pki_job_image=""
    old_ifs="$IFS"
    IFS=','
    for ref in $PUSH_IMAGE_REFS; do
        case "$ref" in
            */server:*) server_image="$ref" ;;
            */sandbox:*) sandbox_image="$ref" ;;
            */pki-job:*) pki_job_image="$ref" ;;
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

    if [ -n "$sandbox_image" ]; then
        echo "Setting sandbox image: ${sandbox_image}"
        sed -i -E "s|sandboxImage:[[:space:]]*[^[:space:]]+|sandboxImage: ${sandbox_image}|" "$HELMCHART"
    fi

    if [ -n "$pki_job_image" ]; then
        echo "Setting pki job image: ${pki_job_image}"
        sed -i -E "s|jobImage:[[:space:]]*[^[:space:]]+|jobImage: ${pki_job_image}|" "$HELMCHART"
    fi
fi

if [ -n "${IMAGE_TAG:-}" ] && [ -f "$HELMCHART" ]; then
    echo "Overriding component image tag to: ${IMAGE_TAG}"
    # server image tag (standalone value field)
    # Handle both quoted and unquoted defaults: tag: "latest" / tag: latest
    sed -i -E "s|tag:[[:space:]]*\"?latest\"?|tag: \"${IMAGE_TAG}\"|" "$HELMCHART"
    # sandbox image (inline tag in image reference)
    sed -i "s|sandbox:latest|sandbox:${IMAGE_TAG}|" "$HELMCHART"
    # pki-job image (inline tag in image reference)
    sed -i "s|pki-job:latest|pki-job:${IMAGE_TAG}|" "$HELMCHART"
fi

if [ -n "${IMAGE_PULL_POLICY:-}" ] && [ -f "$HELMCHART" ]; then
    echo "Overriding image pull policy to: ${IMAGE_PULL_POLICY}"
    sed -i "s|pullPolicy: Always|pullPolicy: ${IMAGE_PULL_POLICY}|" "$HELMCHART"
fi

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
fi

# If EXTRA_SANS is set (comma-separated list), inject them into the HelmChart
# manifest so the gateway PKI job includes them in the TLS certificate.
if [ -n "$EXTRA_SANS" ]; then
    HELMCHART="/var/lib/rancher/k3s/server/manifests/navigator-helmchart.yaml"
    if [ -f "$HELMCHART" ]; then
        echo "Injecting extra TLS SANs: $EXTRA_SANS"
        # Build a YAML list from the comma-separated string.
        # e.g. "160.211.47.2,my.host.com" -> "['160.211.47.2','my.host.com']"  (flow style)
        # We use sed-friendly single-quoted flow style to keep it on one line.
        yaml_list="["
        first=1
        IFS=','
        for san in $EXTRA_SANS; do
            san=$(echo "$san" | xargs)
            [ -z "$san" ] && continue
            if [ "$first" = "1" ]; then
                yaml_list="${yaml_list}'${san}'"
                first=0
            else
                yaml_list="${yaml_list},'${san}'"
            fi
        done
        unset IFS
        yaml_list="${yaml_list}]"
        sed -i "s|extraSANs: \[\]|extraSANs: ${yaml_list}|g" "$HELMCHART"
    fi
fi

# Execute k3s with explicit resolv-conf.
exec /bin/k3s "$@" --resolv-conf="$RESOLV_CONF"
