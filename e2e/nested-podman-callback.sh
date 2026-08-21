#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Exercise the Release Canary callback topology with artifacts from the current
# checkout: Docker -> Fedora systemd container -> rootful Podman sandbox.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CLI_BIN="${OPENSHELL_BIN:-}"
GATEWAY_BIN="${OPENSHELL_GATEWAY_BIN:-}"
SUPERVISOR_IMAGE="${OPENSHELL_SUPERVISOR_IMAGE:-}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
FEDORA_IMAGE="${OPENSHELL_E2E_NESTED_FEDORA_IMAGE:-fedora:latest}"
CONTAINER_NAME="${OPENSHELL_E2E_NESTED_CONTAINER_NAME:-openshell-e2e-nested-podman-$$}"
SANDBOX_NAME="${OPENSHELL_E2E_NESTED_SANDBOX_NAME:-nested-podman-cb}"
GATEWAY_SERVICE_FILE="${OPENSHELL_E2E_GATEWAY_SERVICE_FILE:-${ROOT}/deploy/deb/openshell-gateway.service}"
GATEWAY_DEFAULT_CONFIG="${OPENSHELL_E2E_GATEWAY_DEFAULT_CONFIG:-${ROOT}/deploy/rpm/gateway.toml.default}"

die() {
  echo "ERROR: $*" >&2
  exit 2
}

command -v docker >/dev/null 2>&1 || die "docker is required"
[ -x "${CLI_BIN}" ] || die "OPENSHELL_BIN must point to an executable Linux CLI artifact"
[ -x "${GATEWAY_BIN}" ] || die "OPENSHELL_GATEWAY_BIN must point to an executable Linux gateway artifact"
[ -n "${SUPERVISOR_IMAGE}" ] || die "OPENSHELL_SUPERVISOR_IMAGE is required"
[ -f "${GATEWAY_SERVICE_FILE}" ] || die "gateway service file not found: ${GATEWAY_SERVICE_FILE}"
[ -f "${GATEWAY_DEFAULT_CONFIG}" ] || die "gateway default config not found: ${GATEWAY_DEFAULT_CONFIG}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-e2e-nested-podman.XXXXXX")"
IMAGE_ARCHIVE="${WORKDIR}/images.tar"

root_exec() {
  docker exec --interactive "${CONTAINER_NAME}" env \
    HOME=/root \
    XDG_RUNTIME_DIR=/run/user/0 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus \
    "$@"
}

diagnostics() {
  if ! docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    return
  fi

  echo "=== nested Fedora container ===" >&2
  docker inspect --format '{{json .State}}' "${CONTAINER_NAME}" >&2 || true
  docker logs "${CONTAINER_NAME}" >&2 || true
  echo "=== nested gateway journal ===" >&2
  docker exec "${CONTAINER_NAME}" \
    journalctl --no-pager -n 200 _SYSTEMD_USER_UNIT=openshell-gateway.service >&2 || true
  echo "=== nested Podman state ===" >&2
  root_exec podman info >&2 || true
  root_exec podman network inspect openshell-e2e-nested >&2 || true
  root_exec podman ps --all >&2 || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [ "${status}" -ne 0 ]; then
    diagnostics
  fi
  docker rm --force "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  rm -rf -- "${WORKDIR}"
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "==> Pulling images used by nested Podman"
docker pull "${SUPERVISOR_IMAGE}"
docker pull "${SANDBOX_IMAGE}"
docker save --output "${IMAGE_ARCHIVE}" "${SUPERVISOR_IMAGE}" "${SANDBOX_IMAGE}"

echo "==> Starting Fedora systemd container"
docker run --detach \
  --name "${CONTAINER_NAME}" \
  --privileged \
  --cgroupns=host \
  --tmpfs /run \
  --tmpfs /tmp \
  --volume /sys/fs/cgroup:/sys/fs/cgroup:rw \
  "${FEDORA_IMAGE}" \
  bash -lc 'dnf install -y dbus-daemon iproute podman systemd && exec /usr/sbin/init' \
  >/dev/null

for _ in $(seq 1 120); do
  if docker exec "${CONTAINER_NAME}" systemctl list-units --no-pager >/dev/null 2>&1; then
    break
  fi
  if [ "$(docker inspect --format '{{.State.Running}}' "${CONTAINER_NAME}")" != true ]; then
    die "Fedora systemd container exited before systemd became reachable"
  fi
  sleep 1
done
docker exec "${CONTAINER_NAME}" systemctl list-units --no-pager >/dev/null 2>&1 \
  || die "Fedora systemd container did not become reachable within 120 seconds"

echo "==> Installing PR artifacts in nested Fedora"
docker exec "${CONTAINER_NAME}" install -d /usr/lib/systemd/user /usr/share/openshell
docker cp "${CLI_BIN}" "${CONTAINER_NAME}:/usr/bin/openshell"
docker cp "${GATEWAY_BIN}" "${CONTAINER_NAME}:/usr/bin/openshell-gateway"
docker cp "${GATEWAY_SERVICE_FILE}" \
  "${CONTAINER_NAME}:/usr/lib/systemd/user/openshell-gateway.service"
docker cp "${GATEWAY_DEFAULT_CONFIG}" \
  "${CONTAINER_NAME}:/usr/share/openshell/gateway.toml.default"
docker cp "${IMAGE_ARCHIVE}" "${CONTAINER_NAME}:/var/lib/openshell-e2e-images.tar"

root_exec bash -s -- "${SUPERVISOR_IMAGE}" "${SANDBOX_IMAGE}" "${SANDBOX_NAME}" <<'EOF'
set -euo pipefail

supervisor_image=$1
sandbox_image=$2
sandbox_name=$3

test -f /.dockerenv || {
  echo "ERROR: nested Podman E2E must run inside a Docker container" >&2
  exit 1
}

# The RPM service is a root systemd user unit. A container has no login
# session, so start root's user manager explicitly, just as Release Canary does.
mkdir -p "${XDG_RUNTIME_DIR}"
chmod 0700 "${XDG_RUNTIME_DIR}"
systemctl start user-runtime-dir@0.service || true
systemctl start user@0.service
for _ in $(seq 1 30); do
  if systemctl --user daemon-reload; then
    break
  fi
  sleep 1
done
systemctl --user daemon-reload
systemctl --user enable --now podman.socket

for _ in $(seq 1 30); do
  if podman info >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
podman info >/dev/null
test "$(podman info --format '{{.Host.Security.Rootless}}')" = false
podman load --input /var/lib/openshell-e2e-images.tar >/dev/null

install -d -m 0700 "${HOME}/.config/openshell"
install -m 0600 /usr/share/openshell/gateway.toml.default \
  "${HOME}/.config/openshell/gateway.toml"
cat >>"${HOME}/.config/openshell/gateway.toml" <<CONFIG

[openshell.drivers.podman]
socket_path = "${XDG_RUNTIME_DIR}/podman/podman.sock"
network_name = "openshell-e2e-nested"
gateway_port = 17670
default_image = "${sandbox_image}"
image_pull_policy = "missing"
supervisor_image = "${supervisor_image}"
guest_tls_ca = "${HOME}/.local/state/openshell/tls/ca.crt"
guest_tls_cert = "${HOME}/.local/state/openshell/tls/client/tls.crt"
guest_tls_key = "${HOME}/.local/state/openshell/tls/client/tls.key"
stop_timeout_secs = 15
CONFIG
printf 'OPENSHELL_TELEMETRY_ENABLED=false\n' >"${HOME}/.config/openshell/gateway.env"
install -d -m 0700 "${HOME}/.config/openshell/gateways/openshell"
cat >"${HOME}/.config/openshell/gateways/openshell/metadata.json" <<'METADATA'
{
  "name": "openshell",
  "gateway_endpoint": "https://127.0.0.1:17670",
  "is_remote": false,
  "gateway_port": 17670
}
METADATA
printf 'openshell' >"${HOME}/.config/openshell/active_gateway"

# Capture the startup ordering that caused the canary regression: Podman can
# report its future bridge gateway before that address exists in this namespace.
podman network create openshell-e2e-nested >/dev/null
gateway_ip="$(podman network inspect openshell-e2e-nested --format '{{(index .Subnets 0).Gateway}}')"
if ip -4 address show | grep -Fq "${gateway_ip}"; then
  echo "ERROR: Podman bridge gateway ${gateway_ip} unexpectedly exists before sandbox creation" >&2
  exit 1
fi
echo "==> Confirmed future Podman bridge gateway ${gateway_ip} is not assigned yet"

systemctl --user enable --now openshell-gateway.service
for _ in $(seq 1 90); do
  if openshell status 2>/dev/null | grep -q Connected; then
    break
  fi
  sleep 1
done
openshell status
journalctl --user -u openshell-gateway.service --no-pager \
  | grep -F 'listener_purpose="nested-podman-callback-fallback"'
ss -ltn | grep -F '0.0.0.0:17670'

echo "==> Creating sandbox through the nested rootful Podman driver"
openshell sandbox create \
  --name "${sandbox_name}" \
  --detach \
  --no-auto-providers \
  --from "${sandbox_image}"

callback_output="$(openshell sandbox exec -n "${sandbox_name}" -- printf nested-callback-ok)"
test "${callback_output}" = nested-callback-ok
ip -4 address show | grep -F "${gateway_ip}"
echo "==> Nested rootful Podman callback succeeded"
EOF
