#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Shared test helpers for install.sh e2e tests.
# Sourced by each per-shell test file (except fish, which has its own helpers).
#
# Provides:
#   - pass / fail / print_summary
#   - assert_output_contains / assert_output_not_contains
#   - run_install          (runs the real install.sh to a temp dir, captures output)
#   - REPO_ROOT / INSTALL_SCRIPT paths
#   - INSTALL_DIR / INSTALL_OUTPUT (set after run_install)

HELPERS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HELPERS_DIR/../.." && pwd)"
INSTALL_SCRIPT="$REPO_ROOT/install.sh"

_PASS=0
_FAIL=0

# Set by run_install
INSTALL_DIR=""
INSTALL_OUTPUT=""

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

pass() {
  _PASS=$((_PASS + 1))
  printf '  PASS: %s\n' "$1"
}

fail() {
  _FAIL=$((_FAIL + 1))
  printf '  FAIL: %s\n' "$1" >&2
  if [ -n "${2:-}" ]; then
    printf '        %s\n' "$2" >&2
  fi
}

assert_output_contains() {
  _aoc_output="$1"
  _aoc_pattern="$2"
  _aoc_label="$3"

  if printf '%s' "$_aoc_output" | grep -qF "$_aoc_pattern"; then
    pass "$_aoc_label"
  else
    fail "$_aoc_label" "expected '$_aoc_pattern' in output"
  fi
}

assert_output_not_contains() {
  _aonc_output="$1"
  _aonc_pattern="$2"
  _aonc_label="$3"

  if printf '%s' "$_aonc_output" | grep -qF "$_aonc_pattern"; then
    fail "$_aonc_label" "unexpected '$_aonc_pattern' found in output"
  else
    pass "$_aonc_label"
  fi
}

# ---------------------------------------------------------------------------
# Install runner
# ---------------------------------------------------------------------------

# Run the real install.sh, installing to a temp directory with the install
# dir removed from PATH so we always get PATH guidance output.
#
# Sets INSTALL_DIR and INSTALL_OUTPUT for subsequent assertions.
# The SHELL variable is passed through so tests can control which shell
# guidance is shown.
#
# Usage:
#   SHELL="/bin/bash" run_install
run_install() {
  INSTALL_DIR="$(mktemp -d)/bin"

  # Remove the install dir from PATH (it won't be there, but be explicit).
  # Keep a minimal PATH so curl/tar/install are available.
  INSTALL_OUTPUT="$(OPENSHELL_INSTALL_DIR="$INSTALL_DIR" \
    PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    sh "$INSTALL_SCRIPT" 2>&1)" || {
    printf 'install.sh failed:\n%s\n' "$INSTALL_OUTPUT" >&2
    return 1
  }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
  printf '\n=== Results: %d passed, %d failed ===\n' "$_PASS" "$_FAIL"
  [ "$_FAIL" -eq 0 ]
}
