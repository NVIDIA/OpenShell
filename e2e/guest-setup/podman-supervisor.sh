#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the supervisor image inside the disposable VM so the Podman driver uses
# the openshell-sandbox binary built from the checkout under test.

set -euo pipefail

supervisor_bin=/home/openshell/.cache/openshell-e2e/bin/openshell-sandbox
supervisor_image=localhost/openshell/supervisor:e2e-vm
build_context="$(mktemp -d)"

cleanup() {
	rm -rf "${build_context}"
}
trap cleanup EXIT

if [ ! -x "${supervisor_bin}" ]; then
	echo "ERROR: staged supervisor binary is missing: ${supervisor_bin}" >&2
	exit 1
fi
if ! command -v podman >/dev/null 2>&1; then
	echo "ERROR: Podman is required by the supervisor guest setup" >&2
	exit 1
fi
if [ -z "${XDG_RUNTIME_DIR:-}" ]; then
	echo "ERROR: XDG_RUNTIME_DIR is required to locate the rootless Podman socket" >&2
	exit 1
fi
if ! command -v socat >/dev/null 2>&1; then
	echo "ERROR: socat is required by the Podman guest configuration" >&2
	exit 1
fi

# Build through the user API service so the gateway driver sees the image in
# the same Podman store even though the E2E launcher overrides XDG_DATA_HOME.
podman_remote=(podman --url "unix://${XDG_RUNTIME_DIR}/podman/podman.sock")

# Rootless netavark isolates its bridge from the VM host network namespace.
# Relay the bridge gateway through a Unix socket so supervisors can call the
# host gateway while the host-side E2E process still reaches its forwarded port.
relay_socket=/home/openshell/.cache/openshell-e2e/podman-gateway.sock
rm -f "${relay_socket}"
socat "UNIX-LISTEN:${relay_socket},fork" TCP:127.0.0.1:8080 &
host_relay_pid=$!
for _ in $(seq 1 50); do
	[ -S "${relay_socket}" ] && break
	sleep 0.1
done
if [ ! -S "${relay_socket}" ] || ! kill -0 "${host_relay_pid}" 2>/dev/null; then
	echo "ERROR: failed to start the host-side Podman gateway relay" >&2
	exit 1
fi
env -u XDG_CONFIG_HOME -u XDG_DATA_HOME -u XDG_STATE_HOME \
	podman unshare --rootless-netns \
	socat TCP-LISTEN:8080,bind=0.0.0.0,reuseaddr,fork "UNIX-CONNECT:${relay_socket}" &
network_relay_pid=$!
sleep 1
if ! kill -0 "${network_relay_pid}" 2>/dev/null; then
	echo "ERROR: failed to start the rootless-network Podman gateway relay" >&2
	exit 1
fi

install -m 0555 "${supervisor_bin}" "${build_context}/openshell-sandbox"
cat >"${build_context}/Containerfile" <<'EOF'
FROM alpine:3.22
RUN apk add --no-cache nftables iptables iptables-legacy
COPY --chmod=0555 openshell-sandbox /openshell-sandbox
ENTRYPOINT ["/openshell-sandbox"]
EOF

echo "==> Building checkout supervisor image: ${supervisor_image}"
"${podman_remote[@]}" build \
	--pull=missing \
	--tag "${supervisor_image}" \
	--file "${build_context}/Containerfile" \
	"${build_context}"
"${podman_remote[@]}" image exists "${supervisor_image}"
