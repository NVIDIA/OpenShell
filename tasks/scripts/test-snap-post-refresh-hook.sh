#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

hook=${1:?Usage: test-snap-post-refresh-hook.sh <post-refresh-hook>}
work=$(mktemp -d "${TMPDIR:-/tmp}/openshell snap post-refresh hook.XXXXXX")
trap 'rm -rf "$work"' EXIT

run_hook() {
  local common=$1
  local mode=$2
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
  PATH="$work/bin:$PATH" SNAP_COMMON="$common" SNAP_INSTANCE_NAME=openshell "$hook"
}

for mode in user system; do
  common="$work/$mode"
  mkdir -p "$common"
  printf '%s\n' 'disable_tls = true' >"$common/gateway.toml"
  cp "$common/gateway.toml" "$work/$mode-before"
  run_hook "$common" "$mode"
  cmp -s "$work/$mode-before" "$common/gateway.toml"
  [[ ! -e "$work/snapctl.log" ]]
done

common="$work/missing"
mkdir -p "$common"
run_hook "$common" ""
expected='set gateway-mode=system'
[[ $(cat "$work/snapctl.log") == "$expected" ]]

common="$work/secure"
mkdir -p "$common"
cat >"$common/gateway.toml" <<'EOF'
[openshell]
version = 2
[openshell.gateway]
disable_tls = false
[openshell.gateway.auth]
allow_unauthenticated_users = false
EOF
cp "$common/gateway.toml" "$work/secure-before"
run_hook "$common" ""
cmp -s "$work/secure-before" "$common/gateway.toml"
[[ $(cat "$work/snapctl.log") == "$expected" ]]

for setting in 'allow_unauthenticated_users = true' 'disable_tls = true # legacy'; do
  common="$work/unsafe-${setting%% *}"
  mkdir -p "$common"
  printf '%s\n' "$setting" >"$common/gateway.toml"
  run_hook "$common" ""
  [[ ! -e "$common/gateway.toml" ]]
  expected='set gateway-mode=system'
  [[ $(cat "$work/snapctl.log") == "$expected" ]]
done

common="$work/symlink"
mkdir -p "$common"
printf '%s\n' 'disable_tls = true' >"$work/linked-config.toml"
ln -s "$work/linked-config.toml" "$common/gateway.toml"
run_hook "$common" ""
[[ ! -e "$common/gateway.toml" && ! -L "$common/gateway.toml" ]]
[[ -f "$work/linked-config.toml" ]]
expected='set gateway-mode=system'
[[ $(cat "$work/snapctl.log") == "$expected" ]]

common="$work/broken-symlink"
mkdir -p "$common"
ln -s "$work/missing-target" "$common/gateway.toml"
run_hook "$common" ""
[[ -L "$common/gateway.toml" ]]
[[ $(cat "$work/snapctl.log") == "$expected" ]]

common="$work/unknown"
mkdir -p "$common"
if run_hook "$common" invalid >"$work/out" 2>"$work/err"; then
  echo "FAIL: post-refresh hook accepted unknown service mode" >&2
  exit 1
fi
grep -Fq 'unsupported gateway-mode: invalid' "$work/err"
[[ ! -e "$work/snapctl.log" ]]

common="$work/get-failure"
mkdir -p "$common" "$work/get-failure-bin"
cat >"$work/get-failure-bin/snapctl" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod 755 "$work/get-failure-bin/snapctl"
if PATH="$work/get-failure-bin:$PATH" SNAP_COMMON="$common" \
  SNAP_INSTANCE_NAME=openshell "$hook"; then
  echo "FAIL: post-refresh hook treated snapctl get failure as a missing mode" >&2
  exit 1
fi

common="$work/remove-failure"
mkdir -p "$common" "$work/remove-failure-bin"
printf '%s\n' 'disable_tls = true' >"$common/gateway.toml"
cat >"$work/remove-failure-bin/snapctl" <<EOF
#!/bin/sh
  if [ "\${1:-}" = get ]; then exit 0; fi
printf '%s\n' "\$*" >>'$work/remove-failure.log'
EOF
cat >"$work/remove-failure-bin/rm" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod 755 "$work/remove-failure-bin/snapctl" "$work/remove-failure-bin/rm"
if PATH="$work/remove-failure-bin:$PATH" SNAP_COMMON="$common" \
  SNAP_INSTANCE_NAME=openshell "$hook"; then
  echo "FAIL: post-refresh hook ignored config removal failure" >&2
  exit 1
fi
[[ ! -e "$work/remove-failure.log" ]]

echo "Snap post-refresh hook tests passed"
