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

MODE is system-docker, missing-docker, or docker-snap. The system-docker mode requires an
existing non-Snap Docker daemon, verifies that install.sh does not install the
Docker snap, and exercises a sandbox. The missing-docker mode requires Docker
to be absent and verifies that install.sh fails before installing either snap.
The docker-snap mode requires the Docker snap and verifies that install.sh
rejects it before installing OpenShell. ATTEMPTS defaults to 1; repeated
system-docker attempts exercise idempotent OpenShell Snap refreshes. Every
failed attempt prints service, connection, snap-change, journal, gateway-log,
and listener diagnostics.
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
	if sudo snap list docker >/dev/null 2>&1; then
		echo "system-docker mode does not support the Docker snap" >&2
		exit 2
	fi
	;;
missing-docker)
	if command -v docker >/dev/null 2>&1; then
		echo "missing-docker mode requires Docker to be absent" >&2
		exit 2
	fi
	;;
docker-snap)
	if ! sudo snap list docker >/dev/null 2>&1; then
		echo "docker-snap mode requires the Docker snap" >&2
		exit 2
	fi
	;;
*)
	echo "MODE must be system-docker, missing-docker, or docker-snap: ${mode}" >&2
	exit 2
	;;
esac

docker_is_ready() {
	docker info >/dev/null
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
	if [ "${mode}" != system-docker ]; then
		output=$(mktemp)
		if OPENSHELL_INSTALL_METHOD=snap OPENSHELL_VERSION=dev sh "${install_script}" >"${output}" 2>&1; then
			echo "install.sh unexpectedly succeeded in ${mode} mode" >&2
			cat "${output}" >&2
			rm -f "${output}"
			diagnostics "${attempt}"
			failures=$((failures + 1))
			continue
		fi
		case "${mode}" in
		missing-docker) expected="Docker is required before installing the OpenShell snap" ;;
		docker-snap) expected="the Docker snap is not currently compatible with OpenShell" ;;
		esac
		if ! grep -Fq "${expected}" "${output}" ||
			sudo snap list openshell >/dev/null 2>&1 ||
			{ [ "${mode}" = missing-docker ] && sudo snap list docker >/dev/null 2>&1; }; then
			echo "install.sh did not fail safely in ${mode} mode" >&2
			cat "${output}" >&2
			rm -f "${output}"
			diagnostics "${attempt}"
			failures=$((failures + 1))
			continue
		fi
		cat "${output}"
		rm -f "${output}"
		continue
	fi

	sandbox="snap-${attempt}-$$"
	if ! OPENSHELL_INSTALL_METHOD=snap OPENSHELL_VERSION=dev sh "${install_script}" ||
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

	if sudo snap list docker >/dev/null 2>&1; then
		echo "install.sh unexpectedly installed the Docker snap" >&2
		diagnostics "${attempt}"
		failures=$((failures + 1))
	fi
done

if [ "${failures}" -gt 0 ]; then
	echo "${failures}/${attempts} attempt(s) failed" >&2
	exit 1
fi

echo "All ${attempts} attempt(s) passed"
