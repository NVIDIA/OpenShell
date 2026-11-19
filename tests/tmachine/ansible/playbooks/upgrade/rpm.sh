#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Upgrades the installed RPM packages to the candidates in
# /var/lib/openshell-qualification/candidate, and runs the gateway on the
# candidate's runtime images. The rpm-upgrade-source installer stages this as
# /var/lib/openshell-qualification/disruptions/upgrade; the runner runs it as
# the login user, who runs the gateway's user service under rootless Podman.
#
# The gateway package restarts the user service after an upgrade
# (%systemd_user_postun_with_restart), so this selects the candidate's images
# before installing and restarts the service itself only if the package did
# not. A second restart right after the package's would interrupt the new
# gateway while it brings its sandboxes back.
set -euo pipefail

stage=/var/lib/openshell-qualification/candidate
unit=openshell-gateway.service
uid=$(id -u)
export XDG_RUNTIME_DIR="/run/user/${uid}"

# The epoch, version, release and architecture of each package, one per line.
versions_of() {
  rpm --query --queryformat '%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "$@"
}

diagnostics() {
  set +e
  echo "=== upgrade failed; diagnostics ===" >&2
  versions_of openshell openshell-gateway >&2
  openshell --version >&2
  systemctl --user status "${unit}" --no-pager >&2
  journalctl --user -u "${unit}" --no-pager -n 100 >&2
  podman images >&2
}
trap diagnostics EXIT

# The gateway has to be the login user's service: this upgrade loads images
# into that user's Podman storage.
if ! systemctl --user cat "${unit}" > /dev/null 2>&1; then
  echo "${unit} is not a user service of $(id -un): this upgrade supports rootless Podman only" >&2
  exit 1
fi

before=$(versions_of openshell openshell-gateway)
candidate=$(versions_of --package "${stage}/openshell.rpm" "${stage}/openshell-gateway.rpm")
if [ "${before}" = "${candidate}" ]; then
  echo "the candidates are the installed versions ($(tr '\n' ' ' <<< "${before}")); nothing to upgrade" >&2
  exit 1
fi

podman load --input "${stage}/sandbox.tar"
podman load --input "${stage}/supervisor.tar"

# Select the candidate's runtime images, which carry the tmachine tag, so the
# gateway the package restarts uses them.
mkdir -p "${HOME}/.config/openshell"
(
  umask 077
  cat > "${HOME}/.config/openshell/gateway.env" <<ENV
OPENSHELL_COMPUTE_DRIVER=podman
OPENSHELL_SANDBOX_RUNTIME_IMAGE=docker.io/openshell/sandbox:tmachine
OPENSHELL_SUPERVISOR_IMAGE=docker.io/openshell/supervisor:tmachine
ENV
)

invocation_of() {
  systemctl --user show --property=InvocationID --value "${unit}"
}
invocation=$(invocation_of)

sudo -n dnf --assumeyes install --allowerasing \
  "${stage}/openshell.rpm" "${stage}/openshell-gateway.rpm"

after=$(versions_of openshell openshell-gateway)
if [ "${after}" != "${candidate}" ]; then
  echo "installed $(tr '\n' ' ' <<< "${after}"), expected the candidates $(tr '\n' ' ' <<< "${candidate}")" >&2
  exit 1
fi

# Give the package's own restart a moment to show, then restart only if it
# didn't happen.
restarted=false
for _ in $(seq 1 20); do
  if [ "$(invocation_of)" != "${invocation}" ]; then
    restarted=true
    break
  fi
  sleep 0.5
done
if [ "${restarted}" = false ]; then
  systemctl --user daemon-reload
  systemctl --user restart "${unit}"
fi
echo "upgraded openshell $(tr '\n' ' ' <<< "${before}")-> $(tr '\n' ' ' <<< "${after}")(restarted by $([ "${restarted}" = true ] && echo the package || echo this step))"
trap - EXIT
