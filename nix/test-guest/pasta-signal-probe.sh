#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Exercise the rootless Podman -> pasta SIGTERM path and assert either the
# packaged-profile control or the upstream-profile fix.

set -Eeuo pipefail

usage() {
	echo "Usage: pasta-signal-probe.sh --expect-denial|--expect-clean" >&2
}

if [ "$#" -ne 1 ]; then
	usage
	exit 2
fi

case "$1" in
--expect-denial) expected_denial=1 ;;
--expect-clean) expected_denial=0 ;;
*)
	usage
	exit 2
	;;
esac

runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
podman_socket="${runtime_dir}/podman/podman.sock"
if [ ! -S "${podman_socket}" ]; then
	echo "rootless Podman API socket is unavailable: ${podman_socket}" >&2
	exit 1
fi
export CONTAINER_HOST="unix://${podman_socket}"

if [ "$(podman info --format '{{.Host.Security.Rootless}}:{{.Host.RootlessNetworkCmd}}')" != "true:pasta" ]; then
	echo "expected rootless Podman with pasta" >&2
	exit 1
fi

container_name="openshell-pasta-signal-probe-$$"
cleanup() {
	podman rm --force "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The guest is disposable. Clearing the kernel ring buffer makes the assertion
# independent of unrelated AppArmor events emitted during cloud-init or package
# configuration.
sudo dmesg --clear
podman run --detach --name "${container_name}" docker.io/library/alpine:3.22 sleep infinity >/dev/null
started_at="$(date +%s)"
podman stop --time 15 "${container_name}" >/dev/null
elapsed_seconds="$(( $(date +%s) - started_at ))"

new_dmesg="$(sudo dmesg)"
denials="$(printf '%s\n' "${new_dmesg}" | grep 'profile="pasta".*requested_mask="receive".*signal=term.*peer="podman"' || true)"

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
