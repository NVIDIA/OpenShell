#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

hook=${1:?Usage: test-snap-configure-hook.sh <configure-hook>}
work=$(mktemp -d "${TMPDIR:-/tmp}/openshell snap configure hook.XXXXXX")
trap 'rm -rf "$work"' EXIT

run_hook() {
  local mode=$1
  rm -f "$work/snapctl.log"
  mkdir -p "$work/bin"
  cat >"$work/bin/snapctl" <<EOF
#!/bin/sh
if [ "\${1:-}" = get ]; then
  printf '%s\n' '$mode'
  exit 0
fi
printf '%s\n' "\$*" >>'$work/snapctl.log'
EOF
  chmod 755 "$work/bin/snapctl"
  PATH="$work/bin:$PATH" SNAP_INSTANCE_NAME=openshell "$hook"
}

run_hook user
expected=$'stop --disable openshell.system-gateway\nstart --enable openshell.user-gateway'
[[ $(cat "$work/snapctl.log") == "$expected" ]]

run_hook system
expected=$'stop --disable openshell.user-gateway\nstart --enable openshell.system-gateway'
[[ $(cat "$work/snapctl.log") == "$expected" ]]

for mode in '' invalid; do
  if run_hook "$mode" >"$work/out" 2>"$work/err"; then
    echo "FAIL: configure hook accepted gateway mode '${mode}'" >&2
    exit 1
  fi
  [[ ! -e "$work/snapctl.log" ]]
done
grep -Fq 'unsupported gateway-mode: invalid' "$work/err"

mkdir -p "$work/failure-bin"
cat >"$work/failure-bin/snapctl" <<EOF
#!/bin/sh
if [ "\${1:-}" = get ]; then printf '%s\n' user; exit 0; fi
printf '%s\n' "\$*" >>'$work/failure.log'
[ "\${1:-}" != stop ]
EOF
chmod 755 "$work/failure-bin/snapctl"
if PATH="$work/failure-bin:$PATH" SNAP_INSTANCE_NAME=openshell "$hook"; then
  echo "FAIL: configure hook ignored inactive-service stop failure" >&2
  exit 1
fi
[[ $(cat "$work/failure.log") == 'stop --disable openshell.system-gateway' ]]

cat >"$work/failure-bin/snapctl" <<EOF
#!/bin/sh
if [ "\${1:-}" = get ]; then printf '%s\n' user; exit 0; fi
printf '%s\n' "\$*" >>'$work/start-failure.log'
[ "\${1:-}" != start ]
EOF
chmod 755 "$work/failure-bin/snapctl"
if PATH="$work/failure-bin:$PATH" SNAP_INSTANCE_NAME=openshell "$hook"; then
  echo "FAIL: configure hook ignored selected-service start failure" >&2
  exit 1
fi
expected=$'stop --disable openshell.system-gateway\nstart --enable openshell.user-gateway'
[[ $(cat "$work/start-failure.log") == "$expected" ]]

echo "Snap configure hook tests passed"
