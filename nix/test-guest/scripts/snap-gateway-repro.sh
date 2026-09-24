#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Reproduce the Release Canary Snap lifecycle with install.sh. Run this as the
# test user inside an Ubuntu guest prepared with --with snapd and, for the
# system-docker mode, --with docker.

set -uo pipefail

usage() {
	cat <<'EOF'
Usage: snap-gateway-repro.sh INSTALL_SCRIPT MODE [ATTEMPTS]

MODE is system-docker or provisions-docker. The system-docker mode requires an
existing Docker daemon and verifies that install.sh does not install the Docker
snap. The provisions-docker mode requires Docker to be absent and verifies that
install.sh provisions it. ATTEMPTS defaults to 1; repeated attempts exercise
idempotent OpenShell Snap refreshes. Every failed attempt prints service,
connection, snap-change, journal, gateway-log, and listener diagnostics.
EOF
}

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	usage >&2
	exit 2
fi

install_script=$1
mode=$2
attempts=${3:-1}
if [ ! -f "${install_script}" ]; then
	echo "Install script does not exist: ${install_script}" >&2
	exit 2
fi
if [[ ! ${attempts} =~ ^[1-9][0-9]*$ ]]; then
	echo "ATTEMPTS must be a positive integer: ${attempts}" >&2
	exit 2
fi
case "${mode}" in
system-docker)
	if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
		echo "system-docker mode requires a running preinstalled Docker daemon" >&2
		exit 2
	fi
	;;
provisions-docker)
	if command -v docker >/dev/null 2>&1; then
		echo "provisions-docker mode requires Docker to be absent" >&2
		exit 2
	fi
	;;
*)
	echo "MODE must be system-docker or provisions-docker: ${mode}" >&2
	exit 2
	;;
esac

docker_is_ready() {
	if [ "${mode}" = provisions-docker ]; then
		sudo docker info >/dev/null
	else
		docker info >/dev/null
	fi
}

diagnostics() {
	local attempt=$1
	echo "========== Snap diagnostics (attempt ${attempt}) ==========" >&2
	if sudo snap list docker >/dev/null 2>&1; then
		sudo snap services docker >&2 || true
		sudo systemctl status snap.docker.dockerd.service --no-pager >&2 || true
		sudo journalctl -b -u snap.docker.dockerd.service --no-pager -n 300 >&2 || true
	else
		sudo systemctl status docker.service --no-pager >&2 || true
		sudo journalctl -b -u docker.service --no-pager -n 300 >&2 || true
	fi
	sudo snap services openshell >&2 || true
	sudo snap connections openshell >&2 || true
	sudo snap changes >&2 || true
	sudo systemctl status snap.openshell.gateway.service --no-pager >&2 || true
	sudo journalctl -b -u snap.openshell.gateway.service --no-pager -n 300 >&2 || true
	sudo journalctl -b -u snapd.service --no-pager -n 300 >&2 || true
	sudo snap logs openshell.gateway -n=300 >&2 || true
	sudo ss -ltnp '( sport = :17670 )' >&2 || true
}

failures=0
for attempt in $(seq 1 "${attempts}"); do
	echo "==> install.sh Snap ${mode} reproduction attempt ${attempt}/${attempts}"
	sandbox="snap-${attempt}-$$"
	if ! OPENSHELL_VERSION=dev sh "${install_script}" ||
		! sudo snap list openshell >/dev/null ||
		! snap info openshell | grep -Eq '^tracking: +latest/edge$' ||
		! docker_is_ready ||
		! sudo snap connections openshell | grep -Eq '^docker +openshell:docker +:docker +' ||
		! /snap/bin/openshell status ||
		! /snap/bin/openshell sandbox create --name "${sandbox}" --detach ||
		! /snap/bin/openshell sandbox exec --name "${sandbox}" --no-tty -- true ||
		! /snap/bin/openshell sandbox delete "${sandbox}"; then
		echo "install.sh Snap reproduction failed" >&2
		diagnostics "${attempt}"
		failures=$((failures + 1))
		continue
	fi

	case "${mode}" in
	system-docker)
		if sudo snap list docker >/dev/null 2>&1; then
			echo "install.sh unexpectedly installed the Docker snap" >&2
			diagnostics "${attempt}"
			failures=$((failures + 1))
		fi
		;;
	provisions-docker)
		if ! sudo snap list docker >/dev/null 2>&1; then
			echo "install.sh did not install the Docker snap" >&2
			diagnostics "${attempt}"
			failures=$((failures + 1))
		fi
		;;
	esac
done

if [ "${failures}" -gt 0 ]; then
	echo "${failures}/${attempts} attempt(s) failed" >&2
	exit 1
fi

echo "All ${attempts} attempt(s) passed"
