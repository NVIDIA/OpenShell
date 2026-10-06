#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

hook_input=${1:?Usage: test-snap-post-refresh-hook.sh <post-refresh-hook>}
hook_dir=$(cd "$(dirname "$hook_input")" && pwd)
hook="${hook_dir}/$(basename "$hook_input")"
work=$(mktemp -d "${TMPDIR:-/tmp}/ryno snap post-refresh hook.XXXXXX")
trap 'rm -rf "$work"' EXIT

mkdir -p "${work}/bin"
cat >"${work}/bin/snapctl" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >>"${work}/snapctl.log"
EOF
chmod 755 "${work}/bin/snapctl"

run_hook() {
  local common=$1

  PATH="${work}/bin:$PATH" SNAP_COMMON="$common" SNAP_INSTANCE_NAME=ryno "$hook"
}

assert_no_restart() {
  local name=$1
  local common=$2

  rm -f "${work}/snapctl.log"
  run_hook "$common"
  if [[ -e "${work}/snapctl.log" ]]; then
    echo "FAIL: post-refresh hook restarted the gateway for ${name}" >&2
    cat "${work}/snapctl.log" >&2
    exit 1
  fi
}

assert_removed_and_restarted() {
  local name=$1
  local common=$2

  rm -f "${work}/snapctl.log"
  run_hook "$common"
  if [[ -e "$common/gateway.toml" ]] || [[ -L "$common/gateway.toml" ]]; then
    echo "FAIL: post-refresh hook did not remove ${name}" >&2
    exit 1
  fi
  if [[ $(cat "${work}/snapctl.log") != "restart ryno.gateway" ]]; then
    echo "FAIL: post-refresh hook did not restart the gateway once for ${name}" >&2
    cat "${work}/snapctl.log" >&2
    exit 1
  fi
}

common="${work}/missing"
mkdir -p "$common"
assert_no_restart "a missing config" "$common"
if [[ -e "$common/gateway.toml" ]] || [[ -L "$common/gateway.toml" ]]; then
  echo "FAIL: post-refresh hook created a missing config" >&2
  exit 1
fi

common="${work}/secure"
mkdir -p "$common"
cat >"$common/gateway.toml" <<'EOF'
[ryno]
version = 2

[ryno.gateway]
compute_driver = "docker"
disable_tls = false

[ryno.gateway.auth]
allow_unauthenticated_users = false
# allow_unauthenticated_users = true
EOF
cp "$common/gateway.toml" "${work}/secure-before"
assert_no_restart "a secure config" "$common"
cmp -s "${work}/secure-before" "$common/gateway.toml"

common="${work}/unauthenticated"
mkdir -p "$common"
cat >"$common/gateway.toml" <<'EOF'
[ryno.gateway.auth]
allow_unauthenticated_users = true
EOF
assert_removed_and_restarted "an unauthenticated config" "$common"

common="${work}/tls-disabled"
mkdir -p "$common"
cat >"$common/gateway.toml" <<'EOF'
[ryno.gateway]
disable_tls = true # old local override

# operator note
EOF
assert_removed_and_restarted "an edited TLS-disabled config" "$common"

common="${work}/broken-link"
mkdir -p "$common"
ln -s "${work}/missing-target" "$common/gateway.toml"
assert_no_restart "a broken operator symlink" "$common"
if [[ $(readlink "$common/gateway.toml") != "${work}/missing-target" ]]; then
  echo "FAIL: post-refresh hook replaced a broken operator symlink" >&2
  exit 1
fi

common="${work}/existing-link"
mkdir -p "$common"
printf '%s\n' 'disable_tls = true' >"${work}/linked-config.toml"
ln -s "${work}/linked-config.toml" "$common/gateway.toml"
assert_no_restart "an existing operator symlink" "$common"
if [[ $(readlink "$common/gateway.toml") != "${work}/linked-config.toml" ]]; then
  echo "FAIL: post-refresh hook replaced an existing operator symlink" >&2
  exit 1
fi

common="${work}/directory"
mkdir -p "$common/gateway.toml"
assert_no_restart "an operator-owned directory" "$common"
if [[ ! -d "$common/gateway.toml" ]]; then
  echo "FAIL: post-refresh hook replaced an operator-owned directory" >&2
  exit 1
fi

common="${work}/remove-failure"
mkdir -p "$common" "${work}/failing-bin"
printf '%s\n' 'disable_tls = true' >"$common/gateway.toml"
cat >"${work}/failing-bin/rm" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod 755 "${work}/failing-bin/rm"
rm -f "${work}/snapctl.log"
if PATH="${work}/failing-bin:${work}/bin:$PATH" SNAP_COMMON="$common" \
  SNAP_INSTANCE_NAME=ryno "$hook"; then
  echo "FAIL: post-refresh hook succeeded when config removal failed" >&2
  exit 1
fi
if [[ -e "${work}/snapctl.log" ]]; then
  echo "FAIL: post-refresh hook restarted after config removal failed" >&2
  cat "${work}/snapctl.log" >&2
  exit 1
fi

echo "Snap post-refresh hook tests passed"
