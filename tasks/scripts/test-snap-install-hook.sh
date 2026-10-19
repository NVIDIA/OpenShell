#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

hook=${1:?Usage: test-snap-install-hook.sh <install-hook>}
work=$(mktemp -d "${TMPDIR:-/tmp}/openshell snap install hook.XXXXXX")
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/bin"
cat >"$work/bin/snapctl" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$work/snapctl.log"
EOF
chmod 755 "$work/bin/snapctl"

PATH="$work/bin:$PATH" SNAP_INSTANCE_NAME=openshell "$hook"
if [[ $(cat "$work/snapctl.log") != 'set gateway-mode=user' ]]; then
  echo "FAIL: install hook did not initialize user gateway mode" >&2
  cat "$work/snapctl.log" >&2
  exit 1
fi

echo "Snap install hook tests passed"
