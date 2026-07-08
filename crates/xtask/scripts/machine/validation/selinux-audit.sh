#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

: "${OPENSHELL_SELINUX_AUDIT_START:?OPENSHELL_SELINUX_AUDIT_START must mark the e2e audit window}"

echo "==> Checking for SELinux AVC denials since ${OPENSHELL_SELINUX_AUDIT_START}"
audit_log="$(mktemp)"
trap 'rm -f "${audit_log}"' EXIT
# The temporary output file is owned by this user; only reading the audit log
# through ausearch requires elevated privileges.
# shellcheck disable=SC2024
sudo ausearch \
	-m avc,user_avc \
	-ts "${OPENSHELL_SELINUX_AUDIT_START}" \
	--raw >"${audit_log}" 2>/dev/null || true

if grep -q '^type=' "${audit_log}"; then
	echo "SELinux denied one or more operations during the e2e suite:" >&2
	cat "${audit_log}" >&2
	exit 1
fi

echo "==> No SELinux AVC denials recorded"
