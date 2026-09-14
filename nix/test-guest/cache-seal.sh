#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sanitize a configured test guest before its disk is published as a cache base.

set -Eeuo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "cache sealing must run as root" >&2
	exit 1
fi

rm -f /home/openshell/.ssh/authorized_keys
rm -f /root/.ssh/authorized_keys
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub

if command -v cloud-init >/dev/null 2>&1; then
	cloud-init clean --logs --machine-id || true
fi
rm -rf /var/lib/cloud/instance /var/lib/cloud/instances /var/lib/cloud/seed
mkdir -p /var/lib/cloud/instances

: >/etc/machine-id
rm -f /var/lib/dbus/machine-id
rm -f /var/lib/systemd/random-seed
rm -f /var/lib/NetworkManager/*lease* /var/lib/dhcp/*lease* 2>/dev/null || true

rm -f /root/.bash_history /home/openshell/.bash_history
rm -f /root/.docker/config.json /home/openshell/.docker/config.json
rm -f /root/.config/containers/auth.json
rm -f /home/openshell/.config/containers/auth.json

if command -v apt-get >/dev/null 2>&1; then
	apt-get clean
fi
if command -v dnf >/dev/null 2>&1; then
	dnf clean all
fi

journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null || true
find /tmp /var/tmp -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true

rm -f -- "$0"
sync

# Deleted credentials can remain in allocated blocks. Fill free space with
# zeroes so qemu-img convert can safely omit those blocks from the cache disk.
zero_file=/var/tmp/openshell-cache-zero
dd if=/dev/zero of="${zero_file}" bs=64M status=none 2>/dev/null || true
rm -f "${zero_file}"
sync

# The authorized key is gone, so arrange shutdown before returning to the host.
nohup /bin/sh -c 'sleep 2; systemctl poweroff' </dev/null >/dev/null 2>&1 &
