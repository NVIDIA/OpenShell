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

echo "install.sh libc preflight tests passed"

# Package format is detected based on the host environment. Shim the has_*
# helpers so the auto-detect path is deterministic regardless of the host
# running the tests.
assert_package_format_detection() {
  local name=$1
  local snapd=$2
  local docker=$3
  local dpkg=$4
  local rpm=$5
  local expected=$6

  local result
  if ! result="$(
    has_snapd() { [ "$snapd" = "1" ]; }
    has_cmd() {
      case "$1" in
        docker) [ "$docker" = "1" ] ;;
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

assert_package_format_detection \
  "prefers snap when snapd and docker are available" \
  1 1 1 1 "snap"

assert_package_format_detection \
  "uses rpm when snapd is available without docker" \
  1 0 1 1 "rpm"

assert_package_format_detection \
  "provisions docker through snap when rpm is unavailable" \
  1 0 1 0 "snap"

assert_package_format_detection \
  "provisions docker through snap without another package manager" \
  1 0 0 0 "snap"

assert_package_format_detection \
  "skips snap when snapd absent" \
  0 0 1 0 "deb"

assert_package_format_detection \
  "falls back to rpm when no dpkg" \
  0 0 0 1 "rpm"

# Host with no snapd, no dpkg, no rpm must error.
if (
  has_snapd() { return 1; }
  has_cmd() { return 1; }
  linux_package_method
) >"$out" 2>"$err"; then
  echo "FAIL: host with no package managers should error" >&2
  exit 1
fi

if ! grep -Fq "Linux installs require either snapd, dpkg, or rpm" "$err"; then
  echo "FAIL: missing no-package-manager error" >&2
  cat "$err" >&2 || true
  exit 1
fi

if [ "$(PLATFORM=darwin local_gateway_endpoint)" != "https://localhost:17670" ]; then
  echo "FAIL: macOS local gateway endpoint must use a TLS-compatible loopback hostname" >&2
  exit 1
fi

if [ "$(PLATFORM=linux local_gateway_endpoint)" != "https://127.0.0.1:17670" ]; then
  echo "FAIL: Linux local gateway endpoint must use IPv4 loopback" >&2
  exit 1
fi

cat >"${tmpdir}/checksums" <<'EOF'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  openshell-dev-x86_64.rpm
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  openshell-gateway-dev-x86_64.rpm
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  openshell-prover-dev-x86_64.rpm
EOF

if [ "$(find_rpm_asset "${tmpdir}/checksums" x86_64 openshell-prover)" != "openshell-prover-dev-x86_64.rpm" ]; then
  echo "FAIL: RPM prover package selection" >&2
  exit 1
fi

assert_snap_install_flow() {
  local name=$1
  local docker_present=$2
  local expected=$3
  local calls

  if ! calls="$(
    has_cmd() {
      case "$1" in
        snap) return 0 ;;
        docker) [ "$docker_present" = "1" ] ;;
        *) command -v "$1" >/dev/null 2>&1 ;;
      esac
    }
    as_root() { printf 'root:%s\n' "$*"; }
    set_linux_target_runtime_dir() { :; }
    wait_for_docker_daemon() { printf '%s\n' "wait:docker"; }
    register_local_gateway_snap() { printf '%s\n' "register:gateway"; }
    wait_for_local_gateway_listener_snap() { printf '%s\n' "wait:gateway-listener"; }
    wait_for_local_gateway_status() { printf '%s\n' "wait:gateway-status"; }
    info() { :; }
    export TARGET_USER=test-user
    install_linux_snap
  )"; then
    echo "FAIL: ${name}: call failed" >&2
    exit 1
  fi

  if [ "$calls" != "$expected" ]; then
    echo "FAIL: ${name}: unexpected command sequence" >&2
    echo "Expected:" >&2
    printf '%s\n' "$expected" >&2
    echo "Actual:" >&2
    printf '%s\n' "$calls" >&2
    exit 1
  fi
}

assert_snap_install_flow \
  "existing docker is reused" \
  1 \
  "wait:docker
root:snap install openshell
register:gateway
wait:gateway-listener
wait:gateway-status"

assert_snap_install_flow \
  "missing docker is installed before openshell" \
  0 \
  "root:snap install docker
wait:docker
root:snap install openshell
register:gateway
wait:gateway-listener
wait:gateway-status"

assert_docker_readiness() {
  local attempts_file="${tmpdir}/docker-attempts"
  printf '0\n' > "$attempts_file"

  docker() {
    local attempts
    attempts="$(<"$attempts_file")"
    attempts=$((attempts + 1))
    printf '%s\n' "$attempts" > "$attempts_file"
    [ "$attempts" -ge 3 ]
  }
  sleep() { :; }
  info() { :; }

  OPENSHELL_INSTALL_DOCKER_TIMEOUT=3 wait_for_docker_daemon
  local attempts
  attempts="$(<"$attempts_file")"
  [ "$attempts" -eq 3 ] || {
    echo "FAIL: Docker readiness expected 3 attempts, got ${attempts}" >&2
    exit 1
  }
}

assert_docker_readiness

if (
  docker() { return 1; }
  sleep() { :; }
  info() { :; }
  OPENSHELL_INSTALL_DOCKER_TIMEOUT=2 wait_for_docker_daemon
) >"$out" 2>"$err"; then
  echo "FAIL: Docker readiness timeout should fail" >&2
  exit 1
fi

if ! grep -Fq "Docker daemon did not become reachable within 2s" "$err"; then
  echo "FAIL: missing Docker readiness timeout error" >&2
  cat "$err" >&2 || true
  exit 1
fi

echo "install.sh focused tests passed"
