#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

case "${OPENSHELL_EXPECTED_OS:-}" in
	ubuntu-24.04) expected_podman_major=4 ;;
	ubuntu-26.04) expected_podman_major=5 ;;
	*)
		echo "cannot determine the expected Podman version for ${OPENSHELL_EXPECTED_OS:-unknown OS}" >&2
		exit 1
		;;
esac

echo "=== host ==="
uname -a
echo "=== AppArmor ==="
cat /proc/self/attr/current
sudo aa-status || true
echo "=== Podman ==="
podman version
podman info --debug

podman_version="$(podman version --format '{{.Client.Version}}')"
case "${podman_version}" in
	"${expected_podman_major}".*) ;;
	*)
		echo "expected Podman ${expected_podman_major}.x, found ${podman_version}" >&2
		exit 1
		;;
esac

apparmor_restrict_userns="$(sudo sysctl -n kernel.apparmor_restrict_unprivileged_userns)"
if [ "${apparmor_restrict_userns}" != "1" ]; then
	echo "expected kernel.apparmor_restrict_unprivileged_userns=1, found ${apparmor_restrict_userns}" >&2
	exit 1
fi

echo "==> Probing the rootless capability bounding set"
capbset_probe="$(mktemp "${TMPDIR:-/tmp}/openshell-capbset-probe.XXXXXX")"
cleanup_capbset_probe() {
	rm -f "${capbset_probe}"
}
trap cleanup_capbset_probe EXIT
cc -static -O2 -Wall -Wextra -Werror \
	e2e/support/capbset-probe.c \
	-o "${capbset_probe}"
podman run --rm \
	--cap-add=SETPCAP \
	--volume "${capbset_probe}:/openshell-capbset-probe:ro" \
	docker.io/library/alpine:3.22 \
	/openshell-capbset-probe
cleanup_capbset_probe
trap - EXIT
