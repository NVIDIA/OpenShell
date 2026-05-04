#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# postinst for openshell.
#
# The packaged systemd unit is user-scope (installed under
# /usr/lib/systemd/user/) so dpkg cannot enable or start it on the user's
# behalf. Each user opts in by running:
#   systemctl --user daemon-reload
#   systemctl --user enable --now openshell-gateway
#
# Tell any running per-user systemd manager to re-scan its unit search
# path so already-logged-in users see the new unit without restarting
# their session.
set -e

case "$1" in
configure | abort-upgrade | abort-deconfigure | abort-remove)
	if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload >/dev/null 2>&1 || true
		# --global only refreshes per-user managers' generators on next
		# session; existing managers pick up new unit files without it.
		systemctl --global daemon-reload >/dev/null 2>&1 || true
	fi
	;;

*)
	echo "postinst called with unknown argument \`$1'" >&2
	exit 1
	;;
esac

exit 0
