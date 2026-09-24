#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

hook_input=${1:?Usage: test-snap-install-hook.sh <install-hook>}
hook_dir=$(cd "$(dirname "$hook_input")" && pwd)
hook="${hook_dir}/$(basename "$hook_input")"
work=$(mktemp -d "${TMPDIR:-/tmp}/openshell snap install hook.XXXXXX")
trap 'rm -rf "$work"' EXIT

expected="${work}/expected.toml"
cat >"$expected" <<'EOF'
[openshell]
version = 2

[openshell.gateway]

[openshell.gateway.auth]
allow_unauthenticated_users = true
EOF

common="${work}/fresh"
SNAP_COMMON="$common" "$hook"
cmp -s "$expected" "$common/gateway.toml"
if [[ -z $(find "$common/gateway.toml" -perm 600) ]]; then
  echo "FAIL: install hook config must be mode 0600" >&2
  exit 1
fi

printf '\noperator setting = true\n' >>"$common/gateway.toml"
cp "$common/gateway.toml" "${work}/operator-before"
SNAP_COMMON="$common" "$hook"
cmp -s "${work}/operator-before" "$common/gateway.toml"

common="${work}/broken-link"
mkdir -p "$common"
ln -s "${work}/missing-target" "$common/gateway.toml"
SNAP_COMMON="$common" "$hook"
if [[ $(readlink "$common/gateway.toml") != "${work}/missing-target" ]]; then
  echo "FAIL: install hook replaced a broken operator symlink" >&2
  exit 1
fi

common="${work}/directory"
mkdir -p "$common/gateway.toml"
SNAP_COMMON="$common" "$hook"
if [[ ! -d "$common/gateway.toml" ]]; then
  echo "FAIL: install hook replaced an operator-owned directory" >&2
  exit 1
fi

echo "Snap install hook tests passed"
