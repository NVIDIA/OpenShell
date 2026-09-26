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
compute_driver = "docker"
EOF

legacy="${work}/legacy.toml"
cat >"$legacy" <<'EOF'
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

common="${work}/legacy"
mkdir -p "$common"
cp "$legacy" "$common/gateway.toml"
chmod 644 "$common/gateway.toml"
SNAP_COMMON="$common" "$hook"
if ! cmp -s "$expected" "$common/gateway.toml"; then
  echo "FAIL: install hook must migrate the legacy unauthenticated config" >&2
  exit 1
fi
if [[ -z $(find "$common/gateway.toml" -perm 600) ]]; then
  echo "FAIL: migrated config must be mode 0600" >&2
  exit 1
fi

common="${work}/legacy-edited"
mkdir -p "$common"
cp "$legacy" "$common/gateway.toml"
printf '\n# operator note\n' >>"$common/gateway.toml"
cp "$common/gateway.toml" "${work}/legacy-edited-before"
SNAP_COMMON="$common" "$hook"
cmp -s "$expected" "$common/gateway.toml"
cmp -s "${work}/legacy-edited-before" "$common/gateway.toml.pre-mtls"
if [[ -z $(find "$common/gateway.toml.pre-mtls" -perm 600) ]]; then
  echo "FAIL: migrated config backup must be mode 0600" >&2
  exit 1
fi
SNAP_COMMON="$common" "$hook"
cmp -s "${work}/legacy-edited-before" "$common/gateway.toml.pre-mtls"
cp "$legacy" "$common/gateway.toml"
SNAP_COMMON="$common" "$hook"
cmp -s "$expected" "$common/gateway.toml"
cmp -s "${work}/legacy-edited-before" "$common/gateway.toml.pre-mtls"
if [[ $(find "$common" -maxdepth 1 -name 'gateway.toml.pre-mtls.*' -type f | wc -l) -ne 1 ]]; then
  echo "FAIL: repeated migration must preserve the existing backup" >&2
  exit 1
fi

common="${work}/custom-insecure"
mkdir -p "$common"
cat >"$common/gateway.toml" <<'EOF'
[openshell]
version = 2

[openshell.gateway]
compute_driver = "docker"
disable_tls = true # old local override

[openshell.gateway.auth]
allow_unauthenticated_users = true # old local override
EOF
cp "$common/gateway.toml" "${work}/custom-insecure-before"
SNAP_COMMON="$common" "$hook"
cmp -s "$expected" "$common/gateway.toml"
cmp -s "${work}/custom-insecure-before" "$common/gateway.toml.pre-mtls"

common="${work}/custom-secure"
mkdir -p "$common"
cat >"$common/gateway.toml" <<'EOF'
[openshell]
version = 2

[openshell.gateway]
compute_driver = "docker"
# allow_unauthenticated_users = true
EOF
cp "$common/gateway.toml" "${work}/custom-secure-before"
SNAP_COMMON="$common" "$hook"
cmp -s "${work}/custom-secure-before" "$common/gateway.toml"
if [[ -e "$common/gateway.toml.pre-mtls" ]]; then
  echo "FAIL: secure operator config should not be backed up or replaced" >&2
  exit 1
fi

common="${work}/post-refresh"
mkdir -p "$common" "${work}/snap/meta/hooks"
cp "$hook" "${work}/snap/meta/hooks/install"
cp "${work}/legacy-edited-before" "$common/gateway.toml"
SNAP="${work}/snap" SNAP_COMMON="$common" "${hook_dir}/post-refresh"
if ! cmp -s "$expected" "$common/gateway.toml"; then
  echo "FAIL: post-refresh hook must migrate an edited insecure config" >&2
  exit 1
fi
cmp -s "${work}/legacy-edited-before" "$common/gateway.toml.pre-mtls"

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
