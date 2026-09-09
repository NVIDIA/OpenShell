#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Reproduce the Release Canary Snap lifecycle: install the OpenShell Snap,
# connect its interfaces after the daemon is started, then immediately use the
# local gateway. Run this as root inside an Ubuntu guest prepared with --with snapd.

set -uo pipefail

usage() {
	cat <<'EOF'
Usage: snap-gateway-repro.sh SNAP_FILE [ATTEMPTS] [READY_TIMEOUT_SECONDS]

Install SNAP_FILE repeatedly using the Release Canary interface ordering.
ATTEMPTS defaults to 1. READY_TIMEOUT_SECONDS defaults to 0, preserving the
canary's immediate readiness check. Set it to a positive value to wait for
automatic gateway recovery after the immediate check fails. Every failed
attempt prints service, connection, snap-change, journal, gateway-log, and
listener diagnostics.
EOF
}

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
	usage >&2
	exit 2
fi

snap_file=$1
attempts=${2:-1}
ready_timeout=${3:-0}
if [ ! -f "${snap_file}" ]; then
	echo "Snap file does not exist: ${snap_file}" >&2
	exit 2
fi
if [[ ! ${attempts} =~ ^[1-9][0-9]*$ ]]; then
	echo "ATTEMPTS must be a positive integer: ${attempts}" >&2
	exit 2
fi
if [[ ! ${ready_timeout} =~ ^[0-9]+$ ]]; then
	echo "READY_TIMEOUT_SECONDS must be a non-negative integer: ${ready_timeout}" >&2
	exit 2
fi

diagnostics() {
	local attempt=$1
	echo "========== Snap diagnostics (attempt ${attempt}) ==========" >&2
	snap services openshell >&2 || true
	snap connections openshell >&2 || true
	snap changes >&2 || true
	systemctl status snap.openshell.gateway.service --no-pager >&2 || true
	journalctl -b -u snap.openshell.gateway.service --no-pager -n 300 >&2 || true
	journalctl -b -u snapd.service --no-pager -n 300 >&2 || true
	snap logs openshell.gateway -n=300 >&2 || true
	ss -ltnp '( sport = :17670 )' >&2 || true
}

gateway_is_ready() {
	runuser -u openshell -- /snap/bin/openshell status >/dev/null 2>&1
}

wait_for_gateway() {
	local deadline=$((SECONDS + ready_timeout))
	while [ "${SECONDS}" -lt "${deadline}" ]; do
		if gateway_is_ready; then
			return 0
		fi
		sleep 1
	done
	gateway_is_ready
}

if ! snap list docker >/dev/null 2>&1; then
	echo "==> Installing Docker Snap"
	snap install docker
fi

failures=0
for attempt in $(seq 1 "${attempts}"); do
	echo "==> Snap gateway reproduction attempt ${attempt}/${attempts}"
	snap remove --purge openshell >/dev/null 2>&1 || true
	rm -rf /home/openshell/snap/openshell

	if ! snap install "${snap_file}" --dangerous ||
		! snap connect openshell:docker docker:docker-daemon ||
		! snap connect openshell:log-observe ||
		! snap connect openshell:system-observe; then
		echo "OpenShell installation or interface connection failed" >&2
		diagnostics "${attempt}"
		failures=$((failures + 1))
		continue
	fi

	# This deliberately does not wait for the listener. It mirrors the canary
	# and exposes a daemon that fails or races after late interface connections.
	if ! runuser -u openshell -- /snap/bin/openshell gateway add \
		http://127.0.0.1:17670 --local --name snap-docker ||
		! runuser -u openshell -- /snap/bin/openshell gateway select snap-docker ||
		! gateway_is_ready; then
		if [ "${ready_timeout}" -gt 0 ] && wait_for_gateway; then
			echo "Gateway recovered automatically within ${ready_timeout}s"
			continue
		fi
		echo "Gateway was not usable immediately after interface connection" >&2
		diagnostics "${attempt}"
		failures=$((failures + 1))
	fi
done

if [ "${failures}" -gt 0 ]; then
	echo "${failures}/${attempts} attempt(s) failed" >&2
	exit 1
fi

echo "All ${attempts} attempt(s) passed"
