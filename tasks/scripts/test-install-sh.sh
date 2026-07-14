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

  if ! grep -Fq -- "$expected" "$err"; then
    echo "FAIL: ${name}: missing expected message" >&2
    echo "Expected: ${expected}" >&2
    echo "Actual:" >&2
    cat "$err" >&2 || true
    exit 1
  fi
}

assert_gateway_failure() {
  local name=$1
  local platform=$2
  local action=$3

  if (
    export PLATFORM="$platform"
    TARGET_USER="test-user"
    TARGET_HOME="${tmpdir}/home"

    as_target_user() {
      if [ "$*" = "$action" ]; then
        return 1
      fi
      return 0
    }
    dump_local_gateway_diagnostics() {
      echo "TEST gateway diagnostics" >&2
    }
    register_local_gateway() { return 0; }
    wait_for_local_gateway_listener() { return 0; }
    wait_for_local_gateway_status() { return 0; }

    case "$platform" in
      linux) start_user_gateway ;;
      darwin) restart_homebrew_gateway "${HOMEBREW_TAP}/${HOMEBREW_FORMULA_NAME}" ;;
    esac
  ) >"$out" 2>"$err"; then
    echo "FAIL: ${name}: expected failure" >&2
    exit 1
  fi

  for expected in \
    "TEST gateway diagnostics" \
    "OpenShell package installation succeeded" \
    "gateway service is not healthy" \
    "install and start Docker or Podman" \
    "supervised service will normally retry automatically"; do
    if ! grep -Fq -- "$expected" "$err"; then
      echo "FAIL: ${name}: missing expected message: ${expected}" >&2
      cat "$err" >&2 || true
      exit 1
    fi
  done
}

assert_gateway_healthy() {
  if ! (
    export PLATFORM="linux"
    TARGET_USER="test-user"
    TARGET_HOME="${tmpdir}/home"

    as_target_user() { return 0; }
    register_local_gateway() { return 0; }
    wait_for_local_gateway_listener() { return 0; }
    wait_for_local_gateway_status() { return 0; }

    start_user_gateway
  ) >"$out" 2>"$err"; then
    echo "FAIL: healthy gateway service should succeed" >&2
    cat "$err" >&2 || true
    exit 1
  fi

  if ! grep -Fq -- "gateway service is healthy" "$err"; then
    echo "FAIL: healthy gateway service should report its outcome" >&2
    cat "$err" >&2 || true
    exit 1
  fi
}

assert_detected_driver_guidance() {
  local name=$1
  local driver=$2
  local expected=$3

  if ! (
    OPENSHELL_GATEWAY_BIN="/test/bin/openshell-gateway"
    as_target_user() {
      if [ "$*" != "/test/bin/openshell-gateway config detect-driver" ]; then
        echo "unexpected detection command: $*" >&2
        return 1
      fi
      printf '%s\n' "$driver"
    }
    report_detected_compute_driver
  ) >"$out" 2>"$err"; then
    echo "FAIL: ${name}" >&2
    cat "$err" >&2 || true
    exit 1
  fi
  if [ -n "$expected" ] && ! grep -Fq -- "$expected" "$err"; then
    echo "FAIL: ${name}: missing expected message: ${expected}" >&2
    cat "$err" >&2 || true
    exit 1
  fi
  if [ -z "$expected" ] && [ -s "$err" ]; then
    echo "FAIL: ${name}: unexpected guidance" >&2
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

assert_detected_driver_guidance \
  "podman detection prints rootless bind guidance" \
  podman \
  "If you use rootless Podman, configure the gateway to listen on the host bridge"

if ! grep -Fq -- \
  "openshell-gateway config set openshell.gateway.bind_address=0.0.0.0:17670" \
  "$err"; then
  echo "FAIL: podman detection: missing configuration command" >&2
  cat "$err" >&2 || true
  exit 1
fi
if ! grep -Fq -- "Restart the gateway service for changes to take effect." "$err"; then
  echo "FAIL: podman detection: missing restart guidance" >&2
  cat "$err" >&2 || true
  exit 1
fi

assert_detected_driver_guidance \
  "docker detection does not print bind guidance" \
  docker \
  ""

assert_detected_driver_guidance \
  "no detected driver does not print bind guidance" \
  none \
  ""

assert_gateway_healthy

assert_gateway_failure \
  "systemd enable failure is actionable" \
  linux \
  "systemctl --user enable openshell-gateway"

assert_gateway_failure \
  "systemd restart failure is actionable" \
  linux \
  "systemctl --user restart openshell-gateway"

assert_gateway_failure \
  "inactive systemd service is actionable" \
  linux \
  "systemctl --user is-active --quiet openshell-gateway"

assert_gateway_failure \
  "Homebrew restart failure is actionable" \
  darwin \
  "brew services restart ${HOMEBREW_TAP}/${HOMEBREW_FORMULA_NAME}"

echo "install.sh tests passed"
