#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build an aarch64 Ubuntu rootfs for the gateway microVM.
#
# Produces a rootfs with k3s pre-installed, the OpenShell helm chart and
# manifests baked in, container images pre-loaded, AND a fully initialized
# k3s cluster state (database, TLS, images imported, all services deployed).
#
# On first VM boot, k3s resumes from this pre-baked state instead of
# cold-starting, achieving ~3-5s startup times.
#
# Usage:
#   ./crates/openshell-vm/scripts/build-rootfs.sh [output_dir]
#
# Requires: Docker (or compatible container runtime), curl, helm, zstd

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOTFS="${XDG_DATA_HOME:-${HOME}/.local/share}/openshell/gateway/rootfs"
ROOTFS_DIR="${1:-${DEFAULT_ROOTFS}}"
CONTAINER_NAME="krun-rootfs-builder"
INIT_CONTAINER_NAME="krun-k3s-init"
BASE_IMAGE_TAG="krun-rootfs:gateway"
# K3S_VERSION uses the semver "+" form for GitHub releases.
# The mise env may provide the Docker-tag form with "-" instead of "+";
# normalise to "+" so the GitHub download URL works.
K3S_VERSION="${K3S_VERSION:-v1.35.2+k3s1}"
K3S_VERSION="${K3S_VERSION//-k3s/+k3s}"

# Project root (two levels up from crates/openshell-vm/scripts/)
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Container images to pre-load into k3s (arm64).
IMAGE_REPO_BASE="${IMAGE_REPO_BASE:-navigator}"
IMAGE_TAG="${IMAGE_TAG:-dev}"
SERVER_IMAGE="${IMAGE_REPO_BASE}/server:${IMAGE_TAG}"
SANDBOX_IMAGE="${IMAGE_REPO_BASE}/sandbox:${IMAGE_TAG}"
AGENT_SANDBOX_IMAGE="registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.1.0"

echo "==> Building gateway rootfs"
echo "    k3s version: ${K3S_VERSION}"
echo "    Images:      ${SERVER_IMAGE}, ${SANDBOX_IMAGE}"
echo "    Output:      ${ROOTFS_DIR}"

# ── Download k3s binary (outside Docker — much faster) ─────────────────

K3S_BIN="/tmp/k3s-arm64-${K3S_VERSION}"
if [ -f "${K3S_BIN}" ]; then
    echo "==> Using cached k3s binary: ${K3S_BIN}"
else
    echo "==> Downloading k3s ${K3S_VERSION} for arm64..."
    curl -fSL "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s-arm64" \
        -o "${K3S_BIN}"
    chmod +x "${K3S_BIN}"
fi

# ── Build base image with dependencies ─────────────────────────────────

# Clean up any previous run
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
docker rm -f "${INIT_CONTAINER_NAME}" 2>/dev/null || true

echo "==> Building base image..."
docker build --platform linux/arm64 -t "${BASE_IMAGE_TAG}" -f - . <<'DOCKERFILE'
FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iptables \
        iproute2 \
        python3 \
        busybox-static \
        zstd \
    && rm -rf /var/lib/apt/lists/*
# busybox-static provides udhcpc for DHCP inside the VM.
RUN mkdir -p /usr/share/udhcpc && \
    ln -sf /bin/busybox /sbin/udhcpc
RUN mkdir -p /var/lib/rancher/k3s /etc/rancher/k3s
DOCKERFILE

# Create a container and export the filesystem
echo "==> Creating container..."
docker create --platform linux/arm64 --name "${CONTAINER_NAME}" "${BASE_IMAGE_TAG}" /bin/true

echo "==> Exporting filesystem..."
# Previous builds may leave overlayfs work/ dirs with permissions that
# prevent rm on macOS. Force-fix permissions before removing.
if [ -d "${ROOTFS_DIR}" ]; then
    chmod -R u+rwx "${ROOTFS_DIR}" 2>/dev/null || true
    rm -rf "${ROOTFS_DIR}"
fi
mkdir -p "${ROOTFS_DIR}"
docker export "${CONTAINER_NAME}" | tar -C "${ROOTFS_DIR}" -xf -

docker rm "${CONTAINER_NAME}"

# ── Inject k3s binary ────────────────────────────────────────────────

echo "==> Injecting k3s binary..."
cp "${K3S_BIN}" "${ROOTFS_DIR}/usr/local/bin/k3s"
chmod +x "${ROOTFS_DIR}/usr/local/bin/k3s"
ln -sf /usr/local/bin/k3s "${ROOTFS_DIR}/usr/local/bin/kubectl"

# ── Inject scripts ────────────────────────────────────────────────────

echo "==> Injecting gateway-init.sh..."
mkdir -p "${ROOTFS_DIR}/srv"
cp "${SCRIPT_DIR}/gateway-init.sh" "${ROOTFS_DIR}/srv/gateway-init.sh"
chmod +x "${ROOTFS_DIR}/srv/gateway-init.sh"

# Keep the hello server around for debugging
cp "${SCRIPT_DIR}/hello-server.py" "${ROOTFS_DIR}/srv/hello-server.py"
chmod +x "${ROOTFS_DIR}/srv/hello-server.py"

# ── Package and inject helm chart ────────────────────────────────────

HELM_CHART_DIR="${PROJECT_ROOT}/deploy/helm/openshell"
CHART_DEST="${ROOTFS_DIR}/var/lib/rancher/k3s/server/static/charts"

if [ -d "${HELM_CHART_DIR}" ]; then
    echo "==> Packaging helm chart..."
    mkdir -p "${CHART_DEST}"
    helm package "${HELM_CHART_DIR}" -d "${CHART_DEST}"
    echo "    $(ls "${CHART_DEST}"/*.tgz 2>/dev/null | xargs -I{} basename {})"
else
    echo "WARNING: Helm chart not found at ${HELM_CHART_DIR}, skipping"
fi

# ── Inject Kubernetes manifests ──────────────────────────────────────
# These are copied to /opt/navigator/manifests/ (staging). gateway-init.sh
# moves them to /var/lib/rancher/k3s/server/manifests/ at boot so the
# k3s Helm Controller auto-deploys them.

MANIFEST_SRC="${PROJECT_ROOT}/deploy/kube/manifests"
MANIFEST_DEST="${ROOTFS_DIR}/opt/navigator/manifests"

echo "==> Injecting Kubernetes manifests..."
mkdir -p "${MANIFEST_DEST}"

for manifest in openshell-helmchart.yaml agent-sandbox.yaml; do
    if [ -f "${MANIFEST_SRC}/${manifest}" ]; then
        cp "${MANIFEST_SRC}/${manifest}" "${MANIFEST_DEST}/"
        echo "    ${manifest}"
    else
        echo "WARNING: ${manifest} not found in ${MANIFEST_SRC}"
    fi
done

# ── Pre-load container images ────────────────────────────────────────
# Pull arm64 images and save as tarballs in the k3s airgap images
# directory. k3s auto-imports from /var/lib/rancher/k3s/agent/images/
# on startup, so no internet access is needed at boot time.
#
# Tarballs are cached in a persistent directory outside the rootfs so
# they survive rebuilds. This avoids re-pulling and re-saving ~1 GiB
# of images each time.

IMAGES_DIR="${ROOTFS_DIR}/var/lib/rancher/k3s/agent/images"
IMAGE_CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/nemoclaw/gateway/images"
mkdir -p "${IMAGES_DIR}" "${IMAGE_CACHE_DIR}"

echo "==> Pre-loading container images (arm64)..."

pull_and_save() {
    local image="$1"
    local output="$2"
    local cache="${IMAGE_CACHE_DIR}/$(basename "${output}")"

    # Use cached tarball if available.
    if [ -f "${cache}" ]; then
        echo "    cached: $(basename "${output}")"
        cp "${cache}" "${output}"
        return 0
    fi

    # Try to pull; if the registry is unavailable, fall back to the
    # local Docker image cache (image may exist from a previous pull).
    echo "    pulling: ${image}..."
    if ! docker pull --platform linux/arm64 "${image}" --quiet 2>/dev/null; then
        echo "    pull failed, checking local Docker cache..."
        if ! docker image inspect "${image}" >/dev/null 2>&1; then
            echo "ERROR: image ${image} not available locally or from registry"
            exit 1
        fi
        echo "    using locally cached image"
    fi

    echo "    saving:  $(basename "${output}")..."
    # Pipe through zstd for faster decompression and smaller tarballs.
    # k3s auto-imports .tar.zst files from the airgap images directory.
    # -T0 uses all CPU cores; -3 is a good speed/ratio tradeoff.
    docker save "${image}" | zstd -T0 -3 -o "${output}"
    # Cache for next rebuild.
    cp "${output}" "${cache}"
}

pull_and_save "${SERVER_IMAGE}" "${IMAGES_DIR}/openshell-server.tar.zst"
pull_and_save "${SANDBOX_IMAGE}" "${IMAGES_DIR}/openshell-sandbox.tar.zst"
pull_and_save "${AGENT_SANDBOX_IMAGE}" "${IMAGES_DIR}/agent-sandbox-controller.tar.zst"

# ── Pre-initialize k3s cluster state ─────────────────────────────────
# Boot k3s inside a Docker container using the rootfs we just built.
# Wait for it to fully initialize (import images, deploy manifests,
# create database), then capture the state back into the rootfs.
#
# This eliminates cold-start latency: on VM boot, k3s finds existing
# state and resumes in ~3-5 seconds instead of 30-60s.

echo ""
echo "==> Pre-initializing k3s cluster state..."
echo "    This boots k3s in a container, waits for full readiness,"
echo "    then captures the initialized state into the rootfs."

# Patch the HelmChart manifest for the init container (same patches
# gateway-init.sh applies at runtime).
INIT_MANIFESTS="${ROOTFS_DIR}/var/lib/rancher/k3s/server/manifests"
mkdir -p "${INIT_MANIFESTS}"

# Copy manifests from staging to the k3s manifest directory.
for manifest in "${MANIFEST_DEST}"/*.yaml; do
    [ -f "$manifest" ] || continue
    cp "$manifest" "${INIT_MANIFESTS}/"
done

# Patch HelmChart for local images and VM settings.
HELMCHART="${INIT_MANIFESTS}/openshell-helmchart.yaml"
if [ -f "$HELMCHART" ]; then
    # Use local images — explicitly imported into containerd.
    sed -i '' 's|pullPolicy: Always|pullPolicy: IfNotPresent|' "$HELMCHART" 2>/dev/null \
        || sed -i 's|pullPolicy: Always|pullPolicy: IfNotPresent|' "$HELMCHART"
    # Use the locally imported image references.
    sed -i '' -E "s|repository:[[:space:]]*[^[:space:]]+|repository: ${SERVER_IMAGE%:*}|" "$HELMCHART" 2>/dev/null \
        || sed -i -E "s|repository:[[:space:]]*[^[:space:]]+|repository: ${SERVER_IMAGE%:*}|" "$HELMCHART"
    sed -i '' -E "s|tag:[[:space:]]*\"?[^\"[:space:]]+\"?|tag: \"${IMAGE_TAG}\"|" "$HELMCHART" 2>/dev/null \
        || sed -i -E "s|tag:[[:space:]]*\"?[^\"[:space:]]+\"?|tag: \"${IMAGE_TAG}\"|" "$HELMCHART"
    sed -i '' "s|server:[[:space:]]*sandboxImage: ghcr.io/nvidia/openshell-community/sandboxes/base:latest|server:\n      sandboxImage: ${SANDBOX_IMAGE}|g" "$HELMCHART" 2>/dev/null || true
    sed -i '' "s|sandboxImage: ghcr.io/nvidia/openshell-community/sandboxes/base:latest|sandboxImage: ${SANDBOX_IMAGE}|g" "$HELMCHART" 2>/dev/null \
        || sed -i "s|sandboxImage: ghcr.io/nvidia/openshell-community/sandboxes/base:latest|sandboxImage: ${SANDBOX_IMAGE}|g" "$HELMCHART"
    # Enable hostNetwork for VM (no kube-proxy / iptables).
    sed -i '' 's|__HOST_NETWORK__|true|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__HOST_NETWORK__|true|g' "$HELMCHART"
    # Disable SA token automount. The projected volume at
    # /var/run/secrets/kubernetes.io/serviceaccount fails on sandbox
    # re-creation because /var/run is a symlink to /run in the container
    # image and the native snapshotter + virtiofs combination can't
    # resolve it correctly on the second mount.
    sed -i '' 's|__AUTOMOUNT_SA_TOKEN__|false|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__AUTOMOUNT_SA_TOKEN__|false|g' "$HELMCHART"
    # Mount the k3s kubeconfig into the pod since SA token isn't mounted.
    sed -i '' 's|__KUBECONFIG_HOST_PATH__|"/etc/rancher/k3s"|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__KUBECONFIG_HOST_PATH__|"/etc/rancher/k3s"|g' "$HELMCHART"
    # Disable persistence — use /tmp for the SQLite database. PVC mounts
    # are unreliable on virtiofs.
    sed -i '' 's|__PERSISTENCE_ENABLED__|false|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__PERSISTENCE_ENABLED__|false|g' "$HELMCHART"
    sed -i '' 's|__DB_URL__|"sqlite:/tmp/openshell.db"|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__DB_URL__|"sqlite:/tmp/openshell.db"|g' "$HELMCHART"
    # Clear SSH gateway placeholders.
    sed -i '' 's|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: ""|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: ""|g' "$HELMCHART"
    sed -i '' 's|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g' "$HELMCHART"
    SSH_HANDSHAKE_SECRET="$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')"
    sed -i '' "s|__SSH_HANDSHAKE_SECRET__|${SSH_HANDSHAKE_SECRET}|g" "$HELMCHART" 2>/dev/null \
        || sed -i "s|__SSH_HANDSHAKE_SECRET__|${SSH_HANDSHAKE_SECRET}|g" "$HELMCHART"
    sed -i '' 's|__DISABLE_GATEWAY_AUTH__|false|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__DISABLE_GATEWAY_AUTH__|false|g' "$HELMCHART"
    sed -i '' 's|__DISABLE_TLS__|false|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__DISABLE_TLS__|false|g' "$HELMCHART"
    sed -i '' 's|hostGatewayIP: __HOST_GATEWAY_IP__|hostGatewayIP: ""|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|hostGatewayIP: __HOST_GATEWAY_IP__|hostGatewayIP: ""|g' "$HELMCHART"
    sed -i '' '/__CHART_CHECKSUM__/d' "$HELMCHART" 2>/dev/null \
        || sed -i '/__CHART_CHECKSUM__/d' "$HELMCHART"
fi

# Boot k3s in a privileged container. We use a Docker volume for the
# k3s data directory because kine (SQLite) creates Unix sockets that
# don't work over bind mounts from macOS. After k3s is ready, we
# copy the state back into the rootfs.
docker rm -f "${INIT_CONTAINER_NAME}" 2>/dev/null || true
docker volume rm krun-k3s-init-data 2>/dev/null || true
docker volume create krun-k3s-init-data >/dev/null

# Seed the volume with the airgap images and manifests from the rootfs.
echo "    Seeding Docker volume with airgap images and manifests..."
docker run --rm \
    --platform linux/arm64 \
    -v krun-k3s-init-data:/var/lib/rancher/k3s \
    -v "${ROOTFS_DIR}/var/lib/rancher/k3s/agent/images:/src/images:ro" \
    -v "${ROOTFS_DIR}/var/lib/rancher/k3s/server/static/charts:/src/charts:ro" \
    -v "${ROOTFS_DIR}/var/lib/rancher/k3s/server/manifests:/src/manifests:ro" \
    "${BASE_IMAGE_TAG}" \
    sh -c '
        mkdir -p /var/lib/rancher/k3s/agent/images \
               /var/lib/rancher/k3s/server/static/charts \
               /var/lib/rancher/k3s/server/manifests &&
        cp /src/images/* /var/lib/rancher/k3s/agent/images/ 2>/dev/null || true &&
        cp /src/charts/* /var/lib/rancher/k3s/server/static/charts/ 2>/dev/null || true &&
        cp /src/manifests/* /var/lib/rancher/k3s/server/manifests/ 2>/dev/null || true
    '

echo "    Starting k3s in container..."
# Use --hostname=gateway so the k3s node name matches the VM's hostname.
# This ensures the pre-baked pod schedule (node affinity) is valid when
# the VM boots — avoiding a stale Docker-hostname node in the cluster.
docker run -d \
    --name "${INIT_CONTAINER_NAME}" \
    --hostname gateway \
    --platform linux/arm64 \
    --privileged \
    --tmpfs /run \
    --tmpfs /tmp \
    -v "${K3S_BIN}:/usr/local/bin/k3s:ro" \
    -v krun-k3s-init-data:/var/lib/rancher/k3s \
    "${BASE_IMAGE_TAG}" \
    /usr/local/bin/k3s server \
        --disable=traefik,servicelb,metrics-server,coredns,local-path-provisioner \
        --disable-network-policy \
        --write-kubeconfig-mode=644 \
        --flannel-backend=host-gw \
        --snapshotter=native

# Wait for kubeconfig to appear. k3s writes it to
# /etc/rancher/k3s/k3s.yaml inside the container.
echo "    Waiting for kubeconfig..."
for i in $(seq 1 90); do
    if docker exec "${INIT_CONTAINER_NAME}" test -s /etc/rancher/k3s/k3s.yaml 2>/dev/null; then
        echo "    Kubeconfig ready (${i}s)"
        break
    fi
    if [ "$i" -eq 90 ]; then
        echo "ERROR: kubeconfig did not appear in 90s"
        docker logs "${INIT_CONTAINER_NAME}" --tail 50
        docker rm -f "${INIT_CONTAINER_NAME}" 2>/dev/null || true
        docker volume rm krun-k3s-init-data 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# Wait for containerd to be fully ready before importing images.
# The kubeconfig may appear before containerd's gRPC socket is
# accepting requests. `k3s ctr version` exercises the full path.
echo "    Waiting for containerd..."
for i in $(seq 1 60); do
    if docker exec "${INIT_CONTAINER_NAME}" /usr/local/bin/k3s ctr version >/dev/null 2>&1; then
        echo "    Containerd ready (${i}s)"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: containerd did not become ready in 60s"
        docker logs "${INIT_CONTAINER_NAME}" --tail 30
        docker rm -f "${INIT_CONTAINER_NAME}" 2>/dev/null || true
        docker volume rm krun-k3s-init-data 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# Explicitly import images into containerd's k8s.io namespace, then
# tag them with the docker.io/ prefix that kubelet expects.
#
# When Docker saves "navigator/server:dev", the tarball stores the
# reference as "navigator/server:dev". But kubelet normalises all
# short names to "docker.io/navigator/server:dev". Without the
# re-tag, kubelet can't find the image and falls back to pulling.
echo "    Importing images into containerd..."
docker exec "${INIT_CONTAINER_NAME}" sh -c '
    # Prefer system zstd (installed in base image), fall back to k3s bundled.
    if command -v zstd >/dev/null 2>&1; then
        ZSTD=zstd
    else
        ZSTD=$(find /var/lib/rancher/k3s/data -name zstd -type f 2>/dev/null | head -1)
    fi

    for f in /var/lib/rancher/k3s/agent/images/*.tar.zst; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        echo "      importing ${base}..."
        if [ -n "$ZSTD" ]; then
            "$ZSTD" -d -c "$f" | /usr/local/bin/k3s ctr images import -
            rc=$?
        else
            echo "      ERROR: no zstd available, cannot decompress ${base}"
            rc=1
        fi
        if [ $rc -ne 0 ]; then
            echo "      ERROR: import failed for ${base} (rc=$rc)"
        fi
    done

    echo ""
    echo "      Images after import:"
    /usr/local/bin/k3s ctr images list -q | grep -v "^sha256:" | sort

    # Re-tag short-name images with docker.io/ prefix so kubelet can
    # find them. kubelet normalises "navigator/server:dev" to
    # "docker.io/navigator/server:dev". Only re-tag images that look
    # like short Docker Hub names (contain "/" but no "." before the
    # first "/", i.e. not registry.k8s.io/... or ghcr.io/...).
    echo ""
    echo "      Re-tagging short names with docker.io/ prefix..."
    for ref in $(/usr/local/bin/k3s ctr images list -q | grep -v "^sha256:"); do
        # Skip already-qualified names (contain a dot before the first slash).
        case "$ref" in
            *.*/*) continue ;;
        esac
        fqdn="docker.io/${ref}"
        echo "        ${ref} -> ${fqdn}"
        /usr/local/bin/k3s ctr images tag "${ref}" "${fqdn}" 2>/dev/null || true
    done

    echo ""
    echo "      Final image list:"
    /usr/local/bin/k3s ctr images list -q | grep -v "^sha256:" | sort
' 2>&1 | sed 's/^/    /'

# Wait for the openshell namespace (Helm controller creates it).
echo "    Waiting for openshell namespace..."
for i in $(seq 1 120); do
    if docker exec "${INIT_CONTAINER_NAME}" \
        /usr/local/bin/k3s kubectl get namespace openshell -o name 2>/dev/null | grep -q openshell; then
        echo "    Namespace ready (${i}s)"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "ERROR: openshell namespace did not appear in 120s"
        docker logs "${INIT_CONTAINER_NAME}" --tail 50
        docker rm -f "${INIT_CONTAINER_NAME}" 2>/dev/null || true
        docker volume rm krun-k3s-init-data 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# Generate PKI and create TLS secrets inside the cluster.
echo "    Generating TLS certificates and creating secrets..."

# We generate certs outside the container, then apply them via kubectl.
# Use openssl for cert generation at build time (simpler than pulling in
# the Rust PKI library). The bootstrap Rust code will detect
# these pre-baked secrets at runtime and skip its own generation.

PKI_DIR=$(mktemp -d)
trap 'rm -rf "${PKI_DIR}"' EXIT

# Generate CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${PKI_DIR}/ca.key" -out "${PKI_DIR}/ca.crt" \
    -days 3650 -nodes -subj "/O=openshell/CN=openshell-ca" 2>/dev/null

# Generate server cert with SANs
cat > "${PKI_DIR}/server.cnf" <<EOF
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
EOF

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${PKI_DIR}/server.key" -out "${PKI_DIR}/server.csr" \
    -nodes -config "${PKI_DIR}/server.cnf" 2>/dev/null
openssl x509 -req -in "${PKI_DIR}/server.csr" \
    -CA "${PKI_DIR}/ca.crt" -CAkey "${PKI_DIR}/ca.key" -CAcreateserial \
    -out "${PKI_DIR}/server.crt" -days 3650 \
    -extensions v3_req -extfile "${PKI_DIR}/server.cnf" 2>/dev/null

# Generate client cert
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${PKI_DIR}/client.key" -out "${PKI_DIR}/client.csr" \
    -nodes -subj "/CN=openshell-client" 2>/dev/null
openssl x509 -req -in "${PKI_DIR}/client.csr" \
    -CA "${PKI_DIR}/ca.crt" -CAkey "${PKI_DIR}/ca.key" -CAcreateserial \
    -out "${PKI_DIR}/client.crt" -days 3650 2>/dev/null

# Apply TLS secrets to the cluster via kubectl inside the container.
# We create JSON manifests and pipe them in.
apply_secret() {
    local name="$1"
    local json="$2"
    echo "$json" | docker exec -i "${INIT_CONTAINER_NAME}" \
        /usr/local/bin/k3s kubectl apply -f - 2>&1 | sed 's/^/    /'
}

# Base64 encode the cert files
CA_CRT_B64=$(base64 < "${PKI_DIR}/ca.crt" | tr -d '\n')
SERVER_CRT_B64=$(base64 < "${PKI_DIR}/server.crt" | tr -d '\n')
SERVER_KEY_B64=$(base64 < "${PKI_DIR}/server.key" | tr -d '\n')
CLIENT_CRT_B64=$(base64 < "${PKI_DIR}/client.crt" | tr -d '\n')
CLIENT_KEY_B64=$(base64 < "${PKI_DIR}/client.key" | tr -d '\n')

apply_secret "openshell-server-tls" "$(cat <<EOSECRET
{"apiVersion":"v1","kind":"Secret","metadata":{"name":"openshell-server-tls","namespace":"openshell"},"type":"kubernetes.io/tls","data":{"tls.crt":"${SERVER_CRT_B64}","tls.key":"${SERVER_KEY_B64}"}}
EOSECRET
)"

apply_secret "openshell-server-client-ca" "$(cat <<EOSECRET
{"apiVersion":"v1","kind":"Secret","metadata":{"name":"openshell-server-client-ca","namespace":"openshell"},"type":"Opaque","data":{"ca.crt":"${CA_CRT_B64}"}}
EOSECRET
)"

apply_secret "openshell-client-tls" "$(cat <<EOSECRET
{"apiVersion":"v1","kind":"Secret","metadata":{"name":"openshell-client-tls","namespace":"openshell"},"type":"Opaque","data":{"tls.crt":"${CLIENT_CRT_B64}","tls.key":"${CLIENT_KEY_B64}","ca.crt":"${CA_CRT_B64}"}}
EOSECRET
)"

# Wait for the openshell StatefulSet to have a ready replica.
echo "    Waiting for openshell pod to be ready..."
for i in $(seq 1 120); do
    ready=$(docker exec "${INIT_CONTAINER_NAME}" \
        /usr/local/bin/k3s kubectl -n openshell get statefulset openshell \
        -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    if [ "$ready" = "1" ]; then
        echo "    OpenShell pod ready (${i}s)"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "WARNING: openshell pod not ready after 120s, continuing anyway"
        docker exec "${INIT_CONTAINER_NAME}" \
            /usr/local/bin/k3s kubectl -n openshell get pods 2>/dev/null | sed 's/^/    /' || true
        break
    fi
    sleep 1
done

# Bake PKI materials into the rootfs so the host-side bootstrap can
# find them without waiting for the cluster. This is the key to
# skipping the namespace wait + kubectl apply on every boot.
echo "    Baking PKI into rootfs..."
PKI_DEST="${ROOTFS_DIR}/opt/navigator/pki"
mkdir -p "${PKI_DEST}"
cp "${PKI_DIR}/ca.crt" "${PKI_DEST}/ca.crt"
cp "${PKI_DIR}/ca.key" "${PKI_DEST}/ca.key"
cp "${PKI_DIR}/server.crt" "${PKI_DEST}/server.crt"
cp "${PKI_DIR}/server.key" "${PKI_DEST}/server.key"
cp "${PKI_DIR}/client.crt" "${PKI_DEST}/client.crt"
cp "${PKI_DIR}/client.key" "${PKI_DEST}/client.key"

# Stop k3s gracefully so the kine SQLite DB is flushed.
echo "    Stopping k3s..."
docker stop "${INIT_CONTAINER_NAME}" --timeout 10

# Surgically clean the kine SQLite DB. While k3s was running,
# controllers maintained pods, events, leases, and endpoints. These
# runtime objects would cause the VM's kubelet to reconcile against an
# empty containerd (SandboxChanged) on boot. With k3s stopped, we can
# safely strip them directly from the DB — no race condition, no auth.
echo "    Cleaning runtime objects from kine DB..."
CLEANUP_SQL=$(mktemp)
cat > "$CLEANUP_SQL" << 'EOSQL'
DELETE FROM kine WHERE name LIKE '/registry/pods/%';
DELETE FROM kine WHERE name LIKE '/registry/events/%';
DELETE FROM kine WHERE name LIKE '/registry/leases/%';
DELETE FROM kine WHERE name LIKE '/registry/endpointslices/%';
DELETE FROM kine WHERE name LIKE '/registry/masterleases/%';
PRAGMA wal_checkpoint(TRUNCATE);
VACUUM;
EOSQL
docker run --rm \
    -v krun-k3s-init-data:/data \
    -v "${CLEANUP_SQL}:/tmp/clean.sql:ro" \
    alpine:latest \
    sh -c '
        apk add --no-cache sqlite >/dev/null 2>&1
        DB=/data/server/db/state.db
        if [ ! -f "$DB" ]; then echo "ERROR: state.db not found"; exit 1; fi
        echo "  Before: $(sqlite3 "$DB" "SELECT COUNT(*) FROM kine;") kine records"
        sqlite3 "$DB" < /tmp/clean.sql
        echo "  After:  $(sqlite3 "$DB" "SELECT COUNT(*) FROM kine;") kine records"
    ' 2>&1 | sed 's/^/    /'
rm -f "$CLEANUP_SQL"

# Copy the initialized k3s state from the Docker volume back into the
# rootfs. We use a helper container to access the volume.
echo "    Extracting k3s state from Docker volume..."
if [ -d "${ROOTFS_DIR}/var/lib/rancher/k3s" ]; then
    chmod -R u+rwx "${ROOTFS_DIR}/var/lib/rancher/k3s" 2>/dev/null || true
    rm -rf "${ROOTFS_DIR}/var/lib/rancher/k3s"
fi
mkdir -p "${ROOTFS_DIR}/var/lib/rancher/k3s"
# Use tar instead of cp to handle special files that can't be created
# on the macOS-backed bind mount. tar's --ignore-failed-read and
# warning suppression let us capture everything that matters (database,
# TLS, containerd image store in native snapshotter format) while
# skipping uncopiable metadata.
#
# Exclude the overlayfs snapshotter — Docker's init container uses it
# but we use the native snapshotter in the VM. The overlayfs snapshots
# contain full image layer trees that are massive and create files with
# Docker Desktop VirtioFS ownership xattrs that are undeletable on macOS.
# Also exclude runtime task state (stale shim PIDs, sockets) and the
# containerd bolt database (we'll wipe it in the surgical cleanup below).
# Use alpine (native platform) instead of the arm64 base image to avoid
# QEMU emulation overhead. tar doesn't need ARM — it's just copying files.
# Include the containerd native snapshotter, content store, and metadata
# database (meta.db) so the VM doesn't need to re-extract image layers
# at boot time. Exclude the overlayfs snapshotter (Docker's init uses
# overlayfs internally but the VM uses native), runtime task state (stale
# PIDs/sockets), and airgap tarballs (restored from cache below).
#
# The native snapshotter data is ~1-3 GB depending on images. Copying
# through Docker Desktop VirtioFS is slower than native but necessary
# for fast boot times — without it, each boot spends >2 min extracting
# layers on virtio-fs, causing kubelet CreateContainer timeouts.
docker run --rm \
    -v krun-k3s-init-data:/src:ro \
    -v "${ROOTFS_DIR}/var/lib/rancher/k3s:/dst" \
    alpine:latest \
    sh -c 'cd /src && tar cf - \
        --exclude="./agent/containerd/io.containerd.snapshotter.v1.overlayfs" \
        --exclude="./agent/containerd/io.containerd.runtime.v2.task" \
        --exclude="./agent/containerd/io.containerd.sandbox.controller.v1.shim" \
        --exclude="./agent/containerd/tmpmounts" \
        --exclude="./agent/containerd/containerd.log" \
        --exclude="./agent/images" \
        . 2>/dev/null | (cd /dst && tar xf - 2>/dev/null); true'

# Clean up runtime artifacts that shouldn't persist (same cleanup
# gateway-init.sh does on warm boot).
echo "    Cleaning runtime artifacts..."
rm -rf "${ROOTFS_DIR}/var/lib/rancher/k3s/server/tls/temporary-certs" 2>/dev/null || true
rm -f  "${ROOTFS_DIR}/var/lib/rancher/k3s/server/kine.sock" 2>/dev/null || true
find "${ROOTFS_DIR}/var/lib/rancher/k3s" -name '*.sock' -delete 2>/dev/null || true
find "${ROOTFS_DIR}/run" -name '*.sock' -delete 2>/dev/null || true

# Restore airgap image tarballs. The extraction above excluded
# ./agent/images (to avoid pulling them from the Docker volume) and the
# rm -rf earlier wiped the pre-loaded copies. Copy them back from the
# persistent cache so k3s can import them on first VM boot.
echo "    Restoring airgap image tarballs..."
mkdir -p "${IMAGES_DIR}"
for f in "${IMAGE_CACHE_DIR}"/*.tar.zst; do
    [ -f "$f" ] || continue
    cp "$f" "${IMAGES_DIR}/"
done
echo "    Images: $(ls "${IMAGES_DIR}"/*.tar.zst 2>/dev/null | wc -l | tr -d ' ') tarballs ($(du -sh "${IMAGES_DIR}" 2>/dev/null | cut -f1))"

# Write sentinel file so gateway-init.sh and the host-side bootstrap
# know this rootfs has pre-initialized state.
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${ROOTFS_DIR}/opt/navigator/.initialized"

docker rm "${INIT_CONTAINER_NAME}" 2>/dev/null || true
docker volume rm krun-k3s-init-data 2>/dev/null || true

echo "    Pre-initialization complete."

# ── Verify ────────────────────────────────────────────────────────────

if [ ! -f "${ROOTFS_DIR}/usr/local/bin/k3s" ]; then
    echo "ERROR: k3s binary not found in rootfs. Something went wrong."
    exit 1
fi

if [ ! -f "${ROOTFS_DIR}/opt/navigator/.initialized" ]; then
    echo "WARNING: Pre-initialization sentinel not found. Cold starts will be slow."
fi

echo ""
echo "==> Rootfs ready at: ${ROOTFS_DIR}"
echo "    Size: $(du -sh "${ROOTFS_DIR}" | cut -f1)"
echo "    Pre-initialized: $(cat "${ROOTFS_DIR}/opt/navigator/.initialized" 2>/dev/null || echo 'no')"

# Show k3s data size
K3S_DATA="${ROOTFS_DIR}/var/lib/rancher/k3s"
if [ -d "${K3S_DATA}" ]; then
    echo "    k3s state: $(du -sh "${K3S_DATA}" | cut -f1)"
fi

# Show PKI
if [ -d "${ROOTFS_DIR}/opt/navigator/pki" ]; then
    echo "    PKI: baked ($(ls "${ROOTFS_DIR}/opt/navigator/pki/" | wc -l | tr -d ' ') files)"
fi

echo ""
echo "Next steps:"
echo "  1. Run:  ncl gateway"
echo "  Expected startup time: ~3-5 seconds (pre-initialized)"
