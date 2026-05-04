#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# prerm for openshell.
#
# Per-user systemd units cannot be stopped from a system-scope dpkg hook.
# Users who want to stop their gateway before removing the package should
# run `systemctl --user stop openshell-gateway` themselves.
set -e

case "$1" in
remove | upgrade | deconfigure | failed-upgrade) ;;

*)
	echo "prerm called with unknown argument \`$1'" >&2
	exit 1
	;;
esac

exit 0
