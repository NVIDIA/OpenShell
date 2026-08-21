#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Exercise the rootless Podman -> pasta SIGTERM path and assert either the
# packaged-profile control or the upstream-profile fix.

set -Eeuo pipefail

usage() {
	echo "Usage: pasta-signal-probe.sh --expect-denial|--expect-clean|--report" >&2
}

if [ "$#" -ne 1 ]; then
	usage
	exit 2
fi

case "$1" in
--expect-denial) expected_denial=1 ;;
--expect-clean) expected_denial=0 ;;
--report) expected_denial="" ;;
*)
	usage
	exit 2
	;;
esac

if [ "$(podman info --format '{{.Host.Security.Rootless}}:{{.Host.RootlessNetworkCmd}}')" != "true:pasta" ]; then
	echo "expected rootless Podman with pasta" >&2
	exit 1
fi

container_name="openshell-pasta-signal-probe-$$"
work_dir="$(mktemp -d)"
podman_socket="${work_dir}/podman/podman.sock"
podman_config="${work_dir}/containers.conf"
podman_service_log="${work_dir}/podman-service.log"
podman_service_pid=""

printf '%s\n' \
	'[engine]' \
	'conmon_path = ["/usr/bin/conmon"]' \
	> "${podman_config}"
export CONTAINERS_CONF_OVERRIDE="${podman_config}"

cleanup_service() {
	if [ -n "${podman_service_pid}" ] && kill -0 "${podman_service_pid}" 2>/dev/null; then
		kill "${podman_service_pid}" 2>/dev/null || true
		wait "${podman_service_pid}" 2>/dev/null || true
	fi
}
cleanup() {
	if [ -S "${podman_socket}" ]; then
		podman --url "unix://${podman_socket}" rm --force "${container_name}" >/dev/null 2>&1 || true
	fi
	cleanup_service
}
trap cleanup EXIT

mkdir -p "$(dirname "${podman_socket}")"
podman system service --time=0 "unix://${podman_socket}" >"${podman_service_log}" 2>&1 &
podman_service_pid=$!

for _ in $(seq 1 30); do
	if [ -S "${podman_socket}" ] && podman --url "unix://${podman_socket}" info >/dev/null 2>&1; then
		break
	fi
	if ! kill -0 "${podman_service_pid}" 2>/dev/null; then
		cat "${podman_service_log}" >&2 || true
		echo "rootless Podman API service exited before becoming reachable" >&2
		exit 1
	fi
	sleep 1
done

if ! podman --url "unix://${podman_socket}" info >/dev/null 2>&1; then
	cat "${podman_service_log}" >&2 || true
	echo "rootless Podman API service did not become reachable within 30 seconds" >&2
	exit 1
fi

log_process_state() {
	echo '=== runner-match process state ==='
	printf 'podman package: '
	dpkg-query -W -f='${Version}\n' podman
	printf 'conmon package: '
	dpkg-query -W -f='${Version}\n' conmon
	printf 'passt package: '
	dpkg-query -W -f='${Version}\n' passt
	printf 'Podman service PID: %s\n' "${podman_service_pid}"
	ps -eo pid,ppid,user,comm,args | grep -E '[p]odman|[p]asta' || true
	for pid in "${podman_service_pid}" $(pgrep -x pasta || true) $(pgrep -x podman || true); do
		[ -r "/proc/${pid}/attr/current" ] || continue
		echo "=== pid=${pid} ==="
		cat "/proc/${pid}/attr/current" || true
		readlink "/proc/${pid}/ns/user" || true
		readlink "/proc/${pid}/ns/net" || true
	done
}

# The guest is disposable. Clearing the kernel ring buffer makes the assertion
# independent of unrelated AppArmor events emitted during cloud-init or package
# configuration.
sudo dmesg --clear
podman --url "unix://${podman_socket}" run --detach --name "${container_name}" docker.io/library/alpine:3.22 sleep infinity >/dev/null
log_process_state
started_at="$(date +%s)"
podman --url "unix://${podman_socket}" stop --time 15 "${container_name}" >/dev/null
elapsed_seconds="$(( $(date +%s) - started_at ))"

new_dmesg="$(sudo dmesg)"
denials="$(printf '%s\n' "${new_dmesg}" | grep 'profile="pasta".*requested_mask="receive".*signal=term.*peer="podman"' || true)"

if [ -z "${expected_denial}" ]; then
	if [ -n "${denials}" ]; then
		echo "observed pasta AppArmor denial after ${elapsed_seconds}s"
	else
		echo "no pasta AppArmor denial observed; stop completed in ${elapsed_seconds}s"
	fi
	exit 0
fi

if [ "${expected_denial}" -eq 1 ]; then
	if [ -z "${denials}" ]; then
		echo "expected a pasta SIGTERM receive denial, but none was emitted" >&2
		exit 1
	fi
	if [ "${elapsed_seconds}" -lt 15 ]; then
		echo "expected the SIGKILL fallback delay, but stop completed in ${elapsed_seconds}s" >&2
		exit 1
	fi
	echo "observed expected pasta AppArmor denial after ${elapsed_seconds}s"
	exit 0
fi

if [ -n "${denials}" ]; then
	echo "pasta AppArmor still denied Podman's SIGTERM:" >&2
	printf '%s\n' "${denials}" >&2
	exit 1
fi
if [ "${elapsed_seconds}" -ge 15 ]; then
	echo "podman stop still reached the SIGKILL fallback delay (${elapsed_seconds}s)" >&2
	exit 1
fi
echo "pasta accepted Podman's SIGTERM; stop completed in ${elapsed_seconds}s"
