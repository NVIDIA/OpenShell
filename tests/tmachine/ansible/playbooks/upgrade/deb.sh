#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Upgrades the installed Debian package to the candidate in
# /var/lib/openshell-qualification/candidate, and restarts the gateway on the
# candidate's runtime images. The deb-upgrade-source installer stages this as
# /var/lib/openshell-qualification/disruptions/upgrade; the runner runs it as
# the login user, who runs the gateway's user service.
set -euo pipefail

stage=/var/lib/openshell-qualification/candidate
unit=openshell-gateway.service
uid=$(id -u)
export XDG_RUNTIME_DIR="/run/user/${uid}"

version_of() {
  dpkg-query --show --showformat='${Version}' openshell
}

diagnostics() {
  set +e
  echo "=== upgrade failed; diagnostics ===" >&2
  dpkg-query --show --showformat='${Package} ${Version}\n' openshell >&2
  openshell --version >&2
  systemctl --user status "${unit}" --no-pager >&2
  journalctl --user -u "${unit}" --no-pager -n 100 >&2
  sudo -n docker images >&2
}
trap diagnostics EXIT

before=$(version_of)
candidate=$(dpkg-deb --field "${stage}/openshell.deb" Version)
if [ "${before}" = "${candidate}" ]; then
  echo "the candidate is the installed version (${before}); nothing to upgrade" >&2
  exit 1
fi

sudo -n docker load --input "${stage}/sandbox.tar"
sudo -n docker load --input "${stage}/supervisor.tar"
sudo -n env DEBIAN_FRONTEND=noninteractive \
  apt-get install --yes --allow-downgrades "${stage}/openshell.deb"

after=$(version_of)
if [ "${after}" != "${candidate}" ]; then
  echo "installed ${after}, expected the candidate ${candidate}" >&2
  exit 1
fi

# Select the candidate's runtime images, which carry the tmachine tag.
mkdir -p "${HOME}/.config/openshell"
(
  umask 077
  cat > "${HOME}/.config/openshell/gateway.env" <<ENV
OPENSHELL_COMPUTE_DRIVER=docker
OPENSHELL_SANDBOX_RUNTIME_IMAGE=docker.io/openshell/sandbox:tmachine
OPENSHELL_SUPERVISOR_IMAGE=docker.io/openshell/supervisor:tmachine
ENV
)

systemctl --user daemon-reload
systemctl --user restart "${unit}"
echo "upgraded openshell ${before} -> ${after}"
trap - EXIT
