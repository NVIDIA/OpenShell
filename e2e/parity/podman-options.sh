#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Shared candidate-owned oracle for both schema variants. It intentionally
# asserts only stable externally observable Podman semantics.

CLI="${OPENSHELL_BIN:?OPENSHELL_BIN is required}"
RESULT="${OPENSHELL_PARITY_ORACLE_RESULT:?OPENSHELL_PARITY_ORACLE_RESULT is required}"
VARIANT="${OPENSHELL_PARITY_VARIANT:?OPENSHELL_PARITY_VARIANT is required}"
IMAGE="${OPENSHELL_E2E_PODMAN_SANDBOX_IMAGE:-${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}}"
GATEWAY_LOG="${OPENSHELL_E2E_GATEWAY_LOG:?OPENSHELL_E2E_GATEWAY_LOG is required}"
NAME="po-${VARIANT:0:1}-${RANDOM}"
WORKDIR="${TMPDIR:-/tmp}/openshell-parity-options-${NAME}"
mkdir -p "${WORKDIR}"
CREATED=0
case "${VARIANT}" in
  baseline) EXPECTED_PIDS_LIMIT=2048 ;;
  candidate) EXPECTED_PIDS_LIMIT=31 ;;
  *) echo "ERROR: podman-options oracle: unknown parity variant ${VARIANT}" >&2; exit 2 ;;
esac

fail() { echo "ERROR: podman-options oracle: $*" >&2; exit 1; }
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
podman_cmd() {
  if [ "${OPENSHELL_E2E_CONTAINER_ENGINE_UNSET_XDG_CONFIG_HOME:-0}" = 1 ]; then
    env -u XDG_CONFIG_HOME podman --url "unix://${OPENSHELL_PODMAN_SOCKET}" "$@"
  elif [ -n "${OPENSHELL_E2E_CONTAINER_ENGINE_XDG_CONFIG_HOME:-}" ]; then
    XDG_CONFIG_HOME="${OPENSHELL_E2E_CONTAINER_ENGINE_XDG_CONFIG_HOME}" podman --url "unix://${OPENSHELL_PODMAN_SOCKET}" "$@"
  else
    podman --url "unix://${OPENSHELL_PODMAN_SOCKET}" "$@"
  fi
}
cleanup() {
  status=$?
  if [ "${CREATED}" = 1 ]; then "${CLI}" sandbox delete "${NAME}" >/dev/null 2>&1 || true; fi
  rm -rf "${WORKDIR}"
  exit "${status}"
}
trap cleanup EXIT

mkdir -p "${WORKDIR}/bind-source"
printf '%s\n' parity-bind-mount >"${WORKDIR}/bind-source/probe"
bind_source="$(json_escape "${WORKDIR}/bind-source")"
DRIVER_CONFIG="{\"podman\":{\"mounts\":[{\"type\":\"bind\",\"source\":\"${bind_source}\",\"target\":\"/tmp/parity-bind\",\"read_only\":true,\"selinux_label\":\"private\"},{\"type\":\"tmpfs\",\"target\":\"/tmp/parity-cache\",\"options\":[\"nosuid\",\"nodev\"],\"size_bytes\":1048576,\"mode\":448}]}}"
"${CLI}" sandbox create --name "${NAME}" --cpu 750m --memory 384Mi \
  --driver-config-json "${DRIVER_CONFIG}" --detach
CREATED=1
podman_cmd ps -aq --filter label=openshell.managed=true --filter "label=openshell.ai/sandbox-name=${NAME}" > "${WORKDIR}/ids"
env wc -l "${WORKDIR}/ids" | env grep -E "^[[:space:]]*1[[:space:]]" >/dev/null || fail "expected exactly one managed container"

# Image IDs, names, and inspect attributes are checked but never emitted.
while IFS= read -r id; do
  podman_cmd image inspect --format "{{.Id}}" "${IMAGE}" | env sed "s/^sha256://" > "${WORKDIR}/expected-image"
  podman_cmd inspect --format "{{.Image}}" "${id}" | env sed "s/^sha256://" > "${WORKDIR}/actual-image"
  env cmp -s "${WORKDIR}/expected-image" "${WORKDIR}/actual-image" || fail "selected sandbox image ID differs"
  podman_cmd inspect --format "{{index .Config.Labels \"openshell.managed\"}}" "${id}" | env grep -Fx true >/dev/null || fail "managed label missing"
  podman_cmd inspect --format "{{index .Config.Labels \"openshell.ai/sandbox-name\"}}" "${id}" | env grep -Fx "${NAME}" >/dev/null || fail "sandbox name label missing"
  for label in openshell.ai/sandbox-id openshell.ai/sandbox-workspace; do
    podman_cmd inspect --format "{{index .Config.Labels \"${label}\"}}" "${id}" | env grep -Ev "^(|<no value>)$" >/dev/null || fail "${label} missing"
  done
  actual_pids_limit="$(podman_cmd inspect --format "{{.HostConfig.PidsLimit}}" "${id}")"
  [ "${actual_pids_limit}" = "${EXPECTED_PIDS_LIMIT}" ] || fail "pids limit is ${actual_pids_limit}, expected ${EXPECTED_PIDS_LIMIT}"
  podman_cmd inspect --format "{{.HostConfig.CpuQuota}}" "${id}" | env grep -Fx 75000 >/dev/null || fail "CPU quota is not 750m"
  podman_cmd inspect --format "{{.HostConfig.CpuPeriod}}" "${id}" | env grep -Fx 100000 >/dev/null || fail "CPU period is not 100000"
  podman_cmd inspect --format "{{.HostConfig.Memory}}" "${id}" | env grep -Fx 402653184 >/dev/null || fail "memory limit is not 384Mi"
  podman_cmd inspect --format '{{range .Mounts}}{{if eq .Destination "/tmp/parity-bind"}}{{.RW}}{{end}}{{end}}' "${id}" \
    | env grep -Fx false >/dev/null || fail "bind mount is not read-only"
  podman_cmd inspect --format "{{.Config.Entrypoint}}" "${id}" | env grep -F /opt/openshell/bin/openshell-sandbox >/dev/null || fail "supervisor entrypoint missing"
  podman_cmd inspect --format "{{index .Config.Cmd 0}} {{index .Config.Cmd 1}}" "${id}" | env grep -Fx -- "--workdir /sandbox" >/dev/null || fail "supervisor workdir differs"
  podman_cmd inspect --format "{{range .Config.Env}}{{println .}}{{end}}" "${id}" | env grep -Fx OPENSHELL_SSH_SOCKET_PATH=/run/openshell/parity-ssh.sock >/dev/null || fail "SSH environment differs"
  podman_cmd inspect --format "{{range .Config.Env}}{{println .}}{{end}}" "${id}" | env grep -E "^OPENSHELL_ENDPOINT=https://host\.containers\.internal:" >/dev/null || fail "callback endpoint differs"
done < "${WORKDIR}/ids"
# Both schema spellings must map to Podman's pull-if-missing request. Inspect
# the driver emission so regressions to always or never do not pass merely
# because the wrapper preloaded the image.
sed $'s/\033\[[0-9;]*m//g' "${GATEWAY_LOG}" \
  | env grep -F 'Ensuring sandbox image' \
  | env grep -F 'policy=missing' >/dev/null \
  || fail "image pull policy did not map to Podman missing"

# Podman 5.8 reports Healthcheck.Interval in nanoseconds; wait for the
# eventual state instead of accepting a merely running container.
healthy=0
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90; do
  while IFS= read -r id; do
    podman_cmd inspect --format "{{.Config.Healthcheck.Interval}}" "${id}" | env grep -E "^(7000000000|7s)$" >/dev/null || fail "health interval is not 7 seconds"
    if podman_cmd inspect --format "{{.State.Health.Status}}" "${id}" | env grep -Fx healthy >/dev/null; then healthy=1; fi
  done < "${WORKDIR}/ids"
  [ "${healthy}" = 1 ] && break
  sleep 1
done
[ "${healthy}" = 1 ] || fail "container did not become healthy"
container_id="$(cat "${WORKDIR}/ids")"
podman_cmd exec "${container_id}" sh -c 'test "$(cat /tmp/parity-bind/probe)" = parity-bind-mount' \
  || fail "read-only bind mount is unavailable"
podman_cmd exec "${container_id}" test -d /tmp/parity-cache \
  || fail "tmpfs mount is unavailable"
podman_cmd exec "${container_id}" test -s /etc/openshell/auth/sandbox.jwt \
  || fail "sandbox token mount is unavailable"
for tls_file in ca.crt tls.crt tls.key; do
  podman_cmd exec "${container_id}" test -s "/etc/openshell/tls/client/${tls_file}" \
    || fail "guest TLS mount ${tls_file} is unavailable"
done
"${CLI}" sandbox exec --name "${NAME}" --no-tty --no-login-shell -- true

# This is the normalized result: no container IDs, timestamps, IPs, or ports.
escaped_image="$(json_escape "${IMAGE}")"
printf "%s\n" "{\"scenario\":\"podman-options\",\"sandbox_image\":\"${escaped_image}\",\"image_pull_policy\":\"if_not_present\",\"managed_labels\":true,\"supervisor_entrypoint\":\"/opt/openshell/bin/openshell-sandbox\",\"supervisor_workdir\":\"/sandbox\",\"callback_endpoint_scheme\":\"https\",\"callback_endpoint_host\":\"host.containers.internal\",\"ssh_socket_path\":\"/run/openshell/parity-ssh.sock\",\"cpu_millis\":750,\"memory_bytes\":402653184,\"pids_limit\":${actual_pids_limit},\"bind_mount\":\"read_only\",\"tmpfs_mount\":true,\"sandbox_token_mount\":true,\"guest_tls_mounts\":true,\"health_check_interval_secs\":7,\"health\":\"healthy\",\"callback_exec\":true}" > "${RESULT}"
