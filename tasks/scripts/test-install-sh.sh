#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
out="${tmpdir}/out"
err="${tmpdir}/err"

export OPENSHELL_INSTALL_SH_TEST=1
# shellcheck source=../../install.sh
. "${ROOT}/install.sh"

assert_glibc_preflight_passes() {
  local name=$1
  local ldd_output=$2

  if ! (export OPENSHELL_TEST_GETCONF_UNAVAILABLE=1 OPENSHELL_TEST_LDD_OUTPUT="$ldd_output"; require_linux_package_glibc) >"$out" 2>"$err"; then
    echo "FAIL: ${name}" >&2
    cat "$err" >&2 || true
    exit 1
  fi
}

assert_glibc_preflight_fails() {
  local name=$1
  local expected=$2
  local setup=$3

  if ("$setup"; require_linux_package_glibc) >"$out" 2>"$err"; then
    echo "FAIL: ${name}: expected failure" >&2
    exit 1
  fi

  if ! grep -Fq "$expected" "$err"; then
    echo "FAIL: ${name}: missing expected message" >&2
    echo "Expected: ${expected}" >&2
    echo "Actual:" >&2
    cat "$err" >&2 || true
    exit 1
  fi
}

setup_glibc_227() {
  export OPENSHELL_TEST_GETCONF_UNAVAILABLE=1
  export OPENSHELL_TEST_LDD_OUTPUT="ldd (GNU libc) 2.27"
}

setup_missing_glibc() {
  export OPENSHELL_TEST_GETCONF_UNAVAILABLE=1
  export OPENSHELL_TEST_LDD_UNAVAILABLE=1
}

setup_getconf_musl() {
  export OPENSHELL_TEST_LDD_UNAVAILABLE=1
  export OPENSHELL_TEST_GETCONF_OUTPUT="musl libc"
}

setup_ldd_musl() {
  export OPENSHELL_TEST_GETCONF_UNAVAILABLE=1
  export OPENSHELL_TEST_LDD_OUTPUT="musl libc (x86_64)"
}

assert_glibc_preflight_passes "glibc 2.28 passes" "glibc 2.28"
assert_glibc_preflight_passes "glibc 2.31 passes" "glibc 2.31"
assert_glibc_preflight_passes "glibc 2.35 passes" "ldd (GNU libc) 2.35"

if ! (export OPENSHELL_TEST_LDD_UNAVAILABLE=1 OPENSHELL_TEST_GETCONF_OUTPUT="glibc 2.35"; require_linux_package_glibc) >"$out" 2>"$err"; then
  echo "FAIL: getconf glibc fallback passes" >&2
  cat "$err" >&2 || true
  exit 1
fi

if ! (export OPENSHELL_TEST_LDD_OUTPUT="not ldd" OPENSHELL_TEST_GETCONF_OUTPUT="glibc 2.35"; require_linux_package_glibc) >"$out" 2>"$err"; then
  echo "FAIL: unparseable ldd output falls back to getconf" >&2
  cat "$err" >&2 || true
  exit 1
fi

assert_glibc_preflight_fails \
  "glibc 2.27 fails" \
  "OpenShell Linux packages require glibc >= 2.28; detected glibc 2.27." \
  setup_glibc_227

assert_glibc_preflight_fails \
  "missing glibc detection fails" \
  "OpenShell Linux packages require glibc >= 2.28; could not detect glibc." \
  setup_missing_glibc

assert_glibc_preflight_fails \
  "musl detection fails" \
  "OpenShell Linux packages require glibc >= 2.28; detected musl or unsupported libc." \
  setup_getconf_musl

assert_glibc_preflight_fails \
  "ldd musl fallback fails" \
  "OpenShell Linux packages require glibc >= 2.28; detected musl or unsupported libc." \
  setup_ldd_musl

assert_method_equals() {
  local name=$1
  local value=$2
  local expected=$3

  local result
  if ! result="$(OPENSHELL_INSTALL_METHOD="$value" linux_package_method)" 2>"$err"; then
    echo "FAIL: ${name}: expected '${expected}' but call failed" >&2
    cat "$err" >&2 || true
    exit 1
  fi

  if [ "$result" != "$expected" ]; then
    echo "FAIL: ${name}: expected '${expected}', got '${result}'" >&2
    exit 1
  fi
}

assert_method_fails() {
  local name=$1
  local value=$2
  local expected=$3

  if (OPENSHELL_INSTALL_METHOD="$value" linux_package_method) >"$out" 2>"$err"; then
    echo "FAIL: ${name}: expected failure for value '${value}'" >&2
    exit 1
  fi

  if ! grep -Fq "$expected" "$err"; then
    echo "FAIL: ${name}: missing expected message" >&2
    echo "Expected: ${expected}" >&2
    echo "Actual:" >&2
    cat "$err" >&2 || true
    exit 1
  fi
}

assert_method_equals "method deb passes through" "deb" "deb"
assert_method_equals "method rpm passes through" "rpm" "rpm"
assert_method_equals "method snap passes through" "snap" "snap"
assert_method_equals "method homebrew passes through" "homebrew" "homebrew"

assert_method_equals "alias apt maps to deb" "apt" "deb"
assert_method_equals "alias dnf maps to rpm" "dnf" "rpm"
assert_method_equals "alias yum maps to rpm" "yum" "rpm"
assert_method_equals "alias zypper maps to rpm" "zypper" "rpm"
assert_method_equals "alias brew maps to homebrew" "brew" "homebrew"

assert_method_fails \
  "unknown method fails" \
  "apk" \
  "is not supported; use one of: deb, rpm, snap, homebrew"

assert_method_fails \
  "classic method fails" \
  "classic" \
  "is not supported; use one of: deb, rpm, snap, homebrew"

# Unset OPENSHELL_INSTALL_METHOD falls through to host detection. Shim the
# has_* helpers so the auto-detect path is deterministic regardless of the
# host running the tests.
assert_method_unset_detects() {
  local name=$1
  local snapd=$2
  local native_docker=$3
  local dpkg=$4
  local rpm=$5
  local expected=$6

  local result
  if ! result="$(
    unset OPENSHELL_INSTALL_METHOD
    has_snapd() { [ "$snapd" = "1" ]; }
    has_native_docker() { [ "$native_docker" = "1" ]; }
    has_cmd() {
      case "$1" in
        dpkg) [ "$dpkg" = "1" ] ;;
        rpm) [ "$rpm" = "1" ] ;;
        *) return 1 ;;
      esac
    }
    linux_package_method
  )" 2>"$err"; then
    echo "FAIL: ${name}: call failed" >&2
    cat "$err" >&2 || true
    exit 1
  fi

  if [ "$result" != "$expected" ]; then
    echo "FAIL: ${name}: expected '${expected}', got '${result}'" >&2
    exit 1
  fi
}

assert_method_unset_detects \
  "unset prefers snap when snapd and no native docker" \
  1 0 1 1 "snap"

assert_method_unset_detects \
  "unset skips snap when native docker present" \
  1 1 1 0 "deb"

assert_method_unset_detects \
  "unset skips snap when snapd absent" \
  0 0 1 0 "deb"

assert_method_unset_detects \
  "unset falls back to rpm when no dpkg" \
  0 0 0 1 "rpm"

# Unset with no snapd, no dpkg, no rpm must error.
if (
  unset OPENSHELL_INSTALL_METHOD
  has_snapd() { return 1; }
  has_native_docker() { return 1; }
  has_cmd() { return 1; }
  linux_package_method
) >"$out" 2>"$err"; then
  echo "FAIL: unset with no package managers should error" >&2
  exit 1
fi

if ! grep -Fq "Linux installs require either dpkg or rpm" "$err"; then
  echo "FAIL: missing no-package-manager error" >&2
  cat "$err" >&2 || true
  exit 1
fi

echo "install.sh libc preflight tests passed"
