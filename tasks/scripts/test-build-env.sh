#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=tasks/scripts/build-env.sh
source "${SCRIPT_DIR}/build-env.sh"

pass() { echo "PASS: $1"; }
fail() {
  echo "FAIL: $1" >&2
  exit 1
}

# The function must be defined by sourcing the helper.
if ! declare -F ensure_build_nofile_limit >/dev/null; then
  fail "ensure_build_nofile_limit not defined after sourcing build-env.sh"
fi
pass "ensure_build_nofile_limit is defined"

os="$(uname -s)"

if [ "${os}" != "Darwin" ]; then
  # On non-Darwin hosts the helper must be a no-op regardless of the current
  # limit — CI Linux runners and native Linux dev must be unaffected.
  (
    ulimit -Sn 256 2>/dev/null || true
    before="$(ulimit -n)"
    ensure_build_nofile_limit >/dev/null
    after="$(ulimit -n)"
    [ "${before}" = "${after}" ] || fail "limit changed on non-Darwin host (${before} -> ${after})"
  )
  pass "no-op on non-Darwin host (${os})"
  echo "All build-env tests passed."
  exit 0
fi

# Darwin below.
if ! command -v cargo-zigbuild >/dev/null 2>&1; then
  # Without cargo-zigbuild the helper must be a no-op even on macOS.
  (
    ulimit -Sn 256 2>/dev/null || true
    before="$(ulimit -n)"
    ensure_build_nofile_limit >/dev/null
    after="$(ulimit -n)"
    [ "${before}" = "${after}" ] || fail "limit changed on macOS without cargo-zigbuild (${before} -> ${after})"
  )
  pass "no-op on macOS without cargo-zigbuild"
  echo "All build-env tests passed."
  exit 0
fi

# Darwin + cargo-zigbuild: the helper should raise a low soft limit.
(
  if ! ulimit -Sn 256 2>/dev/null; then
    echo "SKIP: unable to lower soft limit to 256 for test"
    exit 0
  fi
  ensure_build_nofile_limit >/dev/null
  after="$(ulimit -n)"
  hard="$(ulimit -Hn 2>/dev/null || echo unlimited)"
  case "${hard}" in
    unlimited|infinity)
      [ "${after}" -ge 8192 ] || fail "expected soft limit >= 8192, got ${after}"
      ;;
    *[!0-9]*)
      [ "${after}" -gt 256 ] || fail "expected soft limit to rise above 256, got ${after}"
      ;;
    *)
      expected=8192
      [ "${hard}" -lt "${expected}" ] && expected="${hard}"
      [ "${after}" -ge "${expected}" ] || fail "expected soft limit >= ${expected}, got ${after}"
      ;;
  esac
)
pass "raises low soft limit on macOS with cargo-zigbuild"

# Idempotent: when the current limit already meets the desired value, the helper
# leaves it unchanged (drive this via the env override so it holds regardless of
# the host default).
(
  before="$(ulimit -n)"
  OPENSHELL_BUILD_NOFILE_LIMIT=1 ensure_build_nofile_limit >/dev/null
  after="$(ulimit -n)"
  [ "${before}" = "${after}" ] || fail "limit changed when already above desired (${before} -> ${after})"
)
pass "no-op when current limit already meets desired"

echo "All build-env tests passed."
