#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

# Require xtask to provide the artifact path that it copied into the VM.
if [ -z "${OPENSHELL_RELEASE_ARTIFACT:-}" ]; then
	echo "OPENSHELL_RELEASE_ARTIFACT must be set" >&2
	exit 1
fi
artifact_path=$OPENSHELL_RELEASE_ARTIFACT
sandbox_name=${OPENSHELL_RELEASE_SMOKE_SANDBOX:-release-smoke-curl}

# Confirm that this OS+driver script is running on the guest OS it supports.
if [ ! -r /etc/os-release ]; then
	echo "cannot detect guest OS: /etc/os-release is missing" >&2
	exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != "ubuntu" ]; then
	echo "ubuntu-podman-rootless release smoke test requires Ubuntu, got ${ID:-unknown}" >&2
	exit 1
fi

# On failure, collect enough state to diagnose gateway startup or sandbox launch.
# shellcheck disable=SC2154
trap '
status=$?
trap - EXIT
if [ "$status" -ne 0 ]; then
	echo "==> OpenShell release smoke test diagnostics" >&2
	openshell status >&2 || true
	systemctl --user status openshell-gateway --no-pager >&2 || true
	systemctl --user status podman.socket --no-pager >&2 || true
	journalctl --user -u openshell-gateway --no-pager -n 200 >&2 || true
	ss -ltnp >&2 || true
	if command -v podman >/dev/null 2>&1; then
		podman info >&2 || true
		podman ps -a >&2 || true
		while IFS= read -r container_id; do
			[ -n "$container_id" ] || continue
			echo "==> Podman logs: $container_id" >&2
			podman logs "$container_id" >&2 || true
		done < <(podman ps -aq)
	fi
fi
openshell sandbox delete "$sandbox_name" >/dev/null 2>&1 || true
exit "$status"
' EXIT

# Install the Ubuntu Debian release artifact under test.
echo "==> Installing Ubuntu release artifact $artifact_path"
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "$artifact_path"
openshell --version
openshell-gateway --version

# Verify that VM setup left the rootless Podman compute driver available.
echo "==> Verifying the rootless Podman compute driver"
systemctl --user is-active --quiet podman.socket
test "$(podman info --format '{{.Host.Security.Rootless}}')" = true

# Temporary release-test workaround: Debian packages do not yet seed the
# Podman-ready gateway configuration that RPM packages install. Remove this when
# Debian first-start configuration owns the equivalent behavior.
echo "==> Applying the temporary Debian Podman gateway workaround"
mkdir -p "$HOME/.config/openshell"
cat >"$HOME/.config/openshell/gateway.toml" <<'EOF'
[openshell]
version = 1

[openshell.gateway]
bind_address = "0.0.0.0:17670"
compute_drivers = ["podman"]
EOF

# Start the packaged gateway service and register it with the CLI.
echo "==> Starting the packaged OpenShell gateway"
systemctl --user enable --now openshell-gateway
systemctl --user is-active --quiet openshell-gateway

echo "==> Registering the packaged gateway"
openshell gateway add https://127.0.0.1:17670 --local --name openshell

# Wait until the CLI can reach the packaged gateway.
echo "==> Waiting for the packaged gateway"
status_output=""
for _ in $(seq 1 30); do
	if status_output="$(NO_COLOR=1 openshell status 2>&1)" && grep -q "Version:" <<<"$status_output"; then
		break
	fi
	sleep 1
done
if ! grep -q "Version:" <<<"$status_output"; then
	echo "openshell status did not report a connected gateway:" >&2
	echo "$status_output" >&2
	exit 1
fi

# Create a sandbox and verify that the default policy denies undeclared egress.
echo "==> Creating a sandbox and verifying default-deny networking"
timeout 600 openshell sandbox create \
	--name "$sandbox_name" \
	--no-tty \
	-- \
	sh -c '
    command -v curl >/dev/null
    if curl --fail --show-error --silent --max-time 20 https://example.com; then
      echo "curl unexpectedly succeeded without a network policy" >&2
      exit 1
    fi
    echo "curl was denied as expected"
  '

# Report the single result this smoke test is meant to prove.
echo "==> Ubuntu rootless Podman release smoke test passed: sandbox curl was denied as expected"
