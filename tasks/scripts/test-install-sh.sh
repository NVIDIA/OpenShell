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

assert_linux_package_method() {
  local name=$1
  local snap_present=$2
  local dpkg_present=$3
  local rpm_present=$4
  local expected=$5
  local actual

  actual="$(
    has_cmd() {
      case "$1" in
        snap) [ "$snap_present" = "1" ] ;;
        dpkg) [ "$dpkg_present" = "1" ] ;;
        rpm) [ "$rpm_present" = "1" ] ;;
        *) return 1 ;;
      esac
    }
    linux_package_method
  )"
  if [ "$actual" != "$expected" ]; then
    echo "FAIL: ${name}: expected ${expected}, got ${actual}" >&2
    exit 1
  fi
}

assert_linux_package_method "snap takes precedence over deb and rpm" 1 1 1 snap
assert_linux_package_method "deb is selected without snap" 0 1 1 deb
assert_linux_package_method "rpm is selected without snap or deb" 0 0 1 rpm

if ! (
  find_existing_native_openshell_bin() { return 1; }
  guard_native_to_snap_transition
) >"$out" 2>"$err"; then
  echo "FAIL: Snap install without an existing native installation should continue" >&2
  cat "$err" >&2 || true
  exit 1
fi

assert_native_to_snap_blocked() {
  local name=$1
  local version=$2

  if (
    find_existing_native_openshell_bin() { printf '%s\n' /usr/bin/openshell; }
    existing_openshell_version() { printf '%s\n' "$version"; }
    UPGRADE_NOTICE_ACK=""
    guard_native_to_snap_transition
  ) >"$out" 2>"$err"; then
    echo "FAIL: ${name}: expected native-to-Snap transition to be blocked" >&2
    exit 1
  fi
  if ! grep -Fq "detected existing non-snap OpenShell ${version} at /usr/bin/openshell" "$err"; then
    echo "FAIL: ${name}: missing native installation warning" >&2
    cat "$err" >&2 || true
    exit 1
  fi
  if ! grep -Fq "does not import state from a non-snap installation" "$err"; then
    echo "FAIL: ${name}: missing isolated Snap state explanation" >&2
    cat "$err" >&2 || true
    exit 1
  fi
}

assert_native_to_snap_blocked "old native install" v0.0.36
assert_native_to_snap_blocked "current native install" v1.2.3

if ! (
  find_existing_native_openshell_bin() { printf '%s\n' /usr/local/bin/openshell; }
  existing_openshell_version() { printf '%s\n' v1.2.3; }
  UPGRADE_NOTICE_ACK=1
  guard_native_to_snap_transition
) >"$out" 2>"$err"; then
  echo "FAIL: acknowledged native-to-Snap transition should continue" >&2
  cat "$err" >&2 || true
  exit 1
fi
if ! grep -Fq "continuing because OPENSHELL_ACK_BREAKING_UPGRADE=1 is set" "$err"; then
  echo "FAIL: acknowledged native-to-Snap transition was not reported" >&2
  cat "$err" >&2 || true
  exit 1
fi

if (
  RELEASE_TAG=""
  target_uses_breaking_gateway_model
); then
  echo "FAIL: Snap targets must not use the version-boundary upgrade guard" >&2
  exit 1
fi

out="$(mktemp)"
err="$(mktemp)"

if ! OPENSHELL_VERSION=dev openshell_snap_channel >"$out" 2>"$err"; then
  echo "FAIL: dev must select the latest/edge Snap channel" >&2
  cat "$err" >&2 || true
  exit 1
fi
if [ "$(cat "$out")" != "latest/edge" ]; then
  echo "FAIL: dev must select the latest/edge Snap channel" >&2
  exit 1
fi
if [ -s "$err" ]; then
  echo "FAIL: dev must not warn about an ignored version" >&2
  cat "$err" >&2 || true
  exit 1
fi

if ! OPENSHELL_VERSION="" openshell_snap_channel >"$out" 2>"$err"; then
  echo "FAIL: unset OPENSHELL_VERSION must select the latest/stable Snap channel" >&2
  cat "$err" >&2 || true
  exit 1
fi
if [ "$(cat "$out")" != "latest/stable" ]; then
  echo "FAIL: unset OPENSHELL_VERSION must select the latest/stable Snap channel" >&2
  exit 1
fi
if [ -s "$err" ]; then
  echo "FAIL: unset OPENSHELL_VERSION must not warn about an ignored version" >&2
  cat "$err" >&2 || true
  exit 1
fi

for requested_version in pre v1.2.3; do
  if ! OPENSHELL_VERSION="$requested_version" openshell_snap_channel >"$out" 2>"$err"; then
    echo "FAIL: '${requested_version}' must select the latest/stable Snap channel" >&2
    cat "$err" >&2 || true
    exit 1
  fi
  if [ "$(cat "$out")" != "latest/stable" ]; then
    echo "FAIL: '${requested_version}' must select the latest/stable Snap channel" >&2
    exit 1
  fi
  if ! grep -Fq "OPENSHELL_VERSION=${requested_version} is ignored for Snap installs" "$err"; then
    echo "FAIL: '${requested_version}' must warn that the requested version is ignored" >&2
    cat "$err" >&2 || true
    exit 1
  fi
done
rm -f "$out" "$err"

assert_snap_install_flow() {
  local name=$1
  local docker_present=$2
  local openshell_present=$3
  local requested_version=$4
  local expected=$5
  local calls

  calls="$(
    has_cmd() {
      case "$1" in
        snap) return 0 ;;
        docker) [ "$docker_present" = "1" ] ;;
        *) command -v "$1" >/dev/null 2>&1 ;;
      esac
    }
    snap() {
      case "${1:-}:${2:-}" in
        list:docker) return 1 ;;
        list:openshell) [ "$openshell_present" = "1" ] ;;
        *) command snap "$@" ;;
      esac
    }
    as_root() { printf 'root:%s\n' "$*"; }
    set_linux_target_runtime_dir() { :; }
    wait_for_docker_daemon() { printf '%s\n' "wait:docker"; }
    ensure_snap_gateway_config() { printf '%s\n' "ensure:gateway-config"; }
    register_snap_gateway() { printf '%s\n' "register:gateway"; }
    wait_for_snap_gateway_listener() { printf '%s\n' "wait:gateway-listener"; }
    wait_for_local_gateway_status() { printf '%s\n' "wait:gateway-status"; }
    info() { :; }
    export TARGET_USER=test-user
    export OPENSHELL_VERSION="$requested_version"
    install_linux_snap
  )"
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
  "existing Docker is reused" \
  1 0 "" \
  "wait:docker
root:snap install openshell --channel=latest/stable
ensure:gateway-config
root:snap restart openshell.gateway
register:gateway
wait:gateway-listener
wait:gateway-status"

assert_snap_install_flow \
  "existing OpenShell snap is refreshed" \
  1 1 pre \
  "wait:docker
root:snap refresh openshell --channel=latest/stable
ensure:gateway-config
root:snap restart openshell.gateway
register:gateway
wait:gateway-listener
wait:gateway-status"

assert_snap_install_rejected() {
  local name=$1
  local docker_present=$2
  local docker_snap_present=$3
  local expected=$4

  if (
    has_cmd() {
      case "$1" in
        snap) return 0 ;;
        docker) [ "$docker_present" = "1" ] ;;
        *) command -v "$1" >/dev/null 2>&1 ;;
      esac
    }
    snap() {
      if [ "${1:-}:${2:-}" = list:docker ]; then
        [ "$docker_snap_present" = "1" ]
      else
        echo "FAIL: ${name}: unexpected snap command: $*" >&2
        return 99
      fi
    }
    as_root() {
      echo "FAIL: ${name}: installation reached root command: $*" >&2
      return 99
    }
    set_linux_target_runtime_dir() { :; }
    install_linux_snap
  ) >"$out" 2>"$err"; then
    echo "FAIL: ${name}: Snap installation should have been rejected" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" "$err"; then
    echo "FAIL: ${name}: missing rejection message" >&2
    cat "$err" >&2 || true
    exit 1
  fi
  if grep -Fq "installation reached root command" "$err"; then
    cat "$err" >&2 || true
    exit 1
  fi
}

assert_snap_install_rejected \
  "missing Docker" \
  0 0 \
  "Docker is required before installing the OpenShell snap"

assert_snap_install_rejected \
  "Docker snap" \
  1 1 \
  "the Docker snap is not currently compatible with OpenShell"

snap_config_dir="${tmpdir}/snap-config"
snap_config="${snap_config_dir}/gateway.toml"
if ! (as_root() { "$@"; }; ensure_snap_gateway_config "$snap_config"); then
  echo "FAIL: Snap gateway config bootstrap should create a missing config" >&2
  exit 1
fi
if ! grep -Fq 'allow_unauthenticated_users = true' "$snap_config"; then
  echo "FAIL: Snap gateway config must permit the plaintext local CLI" >&2
  exit 1
fi
if [[ $(stat -c '%a' "$snap_config") != 600 ]]; then
  echo "FAIL: Snap gateway config must be mode 0600" >&2
  exit 1
fi

printf '\noperator setting = true\n' >>"$snap_config"
cp "$snap_config" "${tmpdir}/snap-config-before"
(as_root() { "$@"; }; ensure_snap_gateway_config "$snap_config")
cmp -s "${tmpdir}/snap-config-before" "$snap_config"

broken_config="${tmpdir}/broken-gateway.toml"
ln -s "${tmpdir}/missing-gateway.toml" "$broken_config"
(as_root() { "$@"; }; ensure_snap_gateway_config "$broken_config")
if [[ $(readlink "$broken_config") != "${tmpdir}/missing-gateway.toml" ]]; then
  echo "FAIL: Snap gateway config bootstrap replaced a broken operator symlink" >&2
  exit 1
fi

attempts_file="${tmpdir}/docker-attempts"
root_probes_file="${tmpdir}/docker-root-probes"
printf '0\n' >"$attempts_file"
printf '0\n' >"$root_probes_file"
if ! (
  docker() {
    attempts="$(cat "$attempts_file")"
    attempts=$((attempts + 1))
    printf '%s\n' "$attempts" >"$attempts_file"
    [ "$attempts" -ge 3 ]
  }
  as_root() {
    root_probes="$(cat "$root_probes_file")"
    printf '%s\n' "$((root_probes + 1))" >"$root_probes_file"
    "$@"
  }
  sleep() { :; }
  info() { :; }
  OPENSHELL_INSTALL_DOCKER_TIMEOUT=3 wait_for_docker_daemon
) >"$out" 2>"$err"; then
  echo "FAIL: Docker readiness should succeed after retries" >&2
  cat "$err" >&2 || true
  exit 1
fi
if [ "$(cat "$attempts_file")" != "3" ]; then
  echo "FAIL: Docker readiness did not retry three times" >&2
  exit 1
fi
if [ "$(cat "$root_probes_file")" != "3" ]; then
  echo "FAIL: Docker readiness probes did not run through as_root" >&2
  exit 1
fi

if (
  docker() { return 1; }
  as_root() { "$@"; }
  snap() { return 1; }
  sleep() { :; }
  info() { :; }
  OPENSHELL_INSTALL_DOCKER_TIMEOUT=2 wait_for_docker_daemon
) >"$out" 2>"$err"; then
  echo "FAIL: Docker readiness timeout should fail" >&2
  exit 1
fi
if ! grep -Fq "Docker daemon did not become reachable within 2s" "$err"; then
  echo "FAIL: missing Docker readiness timeout message" >&2
  cat "$err" >&2 || true
  exit 1
fi

if ! grep -Fq '/snap/bin/openshell' "${ROOT}/install.sh"; then
  echo "FAIL: Snap installs must use the Snap CLI explicitly" >&2
  exit 1
fi

registration_calls_file="${tmpdir}/registration-calls"
: >"$registration_calls_file"
if ! (
  as_target_user() { printf 'target:%s\n' "$*" >>"$registration_calls_file"; }
  print_gateway_add_output() { :; }
  register_snap_gateway
) >"$out" 2>"$err"; then
  echo "FAIL: Snap gateway registration should succeed" >&2
  cat "$err" >&2 || true
  exit 1
fi
registration_calls="$(cat "$registration_calls_file")"
if [ "$registration_calls" != "target:/snap/bin/openshell gateway add http://127.0.0.1:17670 --local --name openshell" ]; then
  echo "FAIL: Snap gateway registration must use the Snap CLI as the target user" >&2
  printf '%s\n' "$registration_calls" >&2
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

mock_gh_log="${tmpdir}/gh.log"
PLATFORM=linux
linux_package_method() {
  printf 'deb\n'
}
uname() {
  case "${1:-}" in
    -m) printf 'x86_64\n' ;;
    *) command uname "$@" ;;
  esac
}
gh() {
  printf '%s\n' "$*" >>"$mock_gh_log"
  case "$1:$2" in
    auth:status)
      return 0
      ;;
    api:*)
      case "$*" in
        *"?name="*) printf '123456\n' ;;
        *"actions/workflows/release-tag.yml/runs?status=success"*)
          printf '%s\n' 100 101
          ;;
        *)
          if [ "${MOCK_NO_PRERELEASE:-0}" != "1" ]; then
            printf '%b\n' \
              '100\topenshell-v0.1.0-pre.9-linux-amd64-deb' \
              '101\topenshell-v1.0.0-pre.2-linux-amd64-deb' \
              '101\topenshell-v1.0.0-pre.1-macos-arm64' \
              '101\topenshell-v0.2.0-pre.10-linux-aarch64-rpm' \
              '999\topenshell-v2.0.0-pre.1-linux-amd64-deb'
          fi
          ;;
      esac
      ;;
    run:download)
      while [ "$#" -gt 0 ]; do
        if [ "$1" = "--dir" ]; then
          shift
          mkdir -p "$1"
          printf 'checksums\n' >"$1/$CHECKSUMS_NAME"
          return 0
        fi
        shift
      done
      return 1
      ;;
    *) return 1 ;;
  esac
}

resolved_prerelease="$(OPENSHELL_VERSION=pre resolve_release_tag)"
if [ "$resolved_prerelease" != "v1.0.0-pre.2" ]; then
  echo "FAIL: pre alias resolved to ${resolved_prerelease}, expected v1.0.0-pre.2" >&2
  exit 1
fi
if ! grep -Fq 'actions/workflows/release-tag.yml/runs?status=success' "$mock_gh_log"; then
  echo "FAIL: pre alias did not query successful Release Tag workflow runs" >&2
  cat "$mock_gh_log" >&2
  exit 1
fi
if ! grep -Fq 'select(.status == "completed" and .conclusion == "success")' "$mock_gh_log"; then
  echo "FAIL: pre alias did not require completed successful workflow runs" >&2
  cat "$mock_gh_log" >&2
  exit 1
fi

if (MOCK_NO_PRERELEASE=1 OPENSHELL_VERSION=pre resolve_release_tag) >"$out" 2>"$err"; then
  echo "FAIL: pre alias should fail when no unexpired prerelease artifacts exist" >&2
  exit 1
fi
if ! grep -Fq 'no unexpired prerelease artifacts found' "$err"; then
  echo "FAIL: missing prerelease resolution failure was not explained" >&2
  cat "$err" >&2
  exit 1
fi

RELEASE_TAG=v0.1.0-pre.9
prerelease_tmp="${tmpdir}/prerelease"
prepare_prerelease_assets "$prerelease_tmp"
if [ "$RELEASE_ASSET_DIR" != "${prerelease_tmp}/release" ]; then
  echo "FAIL: prerelease artifact directory was not recorded" >&2
  exit 1
fi
if ! grep -Fq 'select(.expired == false)' "$mock_gh_log"; then
  echo "FAIL: prerelease lookup did not filter expired artifacts" >&2
  cat "$mock_gh_log" >&2
  exit 1
fi
if ! grep -Fq 'actions/artifacts?name=openshell-v0.1.0-pre.9-linux-amd64-deb' "$mock_gh_log"; then
  echo "FAIL: prerelease lookup did not select the current platform artifact" >&2
  cat "$mock_gh_log" >&2
  exit 1
fi
if ! grep -Fq 'run download 123456 --repo NVIDIA/OpenShell --name openshell-v0.1.0-pre.9-linux-amd64-deb' "$mock_gh_log"; then
  echo "FAIL: prerelease download did not select the current platform artifact" >&2
  cat "$mock_gh_log" >&2
  exit 1
fi

downloaded_checksum="${tmpdir}/downloaded-checksums.txt"
download_release_asset "$RELEASE_TAG" "$CHECKSUMS_NAME" "$downloaded_checksum"
if [ "$(cat "$downloaded_checksum")" != "checksums" ]; then
  echo "FAIL: prerelease checksum was not copied from the platform artifact" >&2
  exit 1
fi

for asset in "$HOMEBREW_CLI_ASSET" "$HOMEBREW_GATEWAY_ASSET" "$HOMEBREW_DRIVER_VM_ASSET" "$HOMEBREW_PROVER_ASSET"; do
  : >"${RELEASE_ASSET_DIR}/${asset}"
done
prerelease_formula="${tmpdir}/openshell.rb"
printf '%s\n' \
  "  url \"${GITHUB_URL}/releases/download/${RELEASE_TAG}/${HOMEBREW_CLI_ASSET}\"" \
  "    url \"${GITHUB_URL}/releases/download/${RELEASE_TAG}/${HOMEBREW_GATEWAY_ASSET}\"" \
  "    url \"${GITHUB_URL}/releases/download/${RELEASE_TAG}/${HOMEBREW_DRIVER_VM_ASSET}\"" \
  "    url \"${GITHUB_URL}/releases/download/${RELEASE_TAG}/${HOMEBREW_PROVER_ASSET}\"" \
  >"$prerelease_formula"
patch_prerelease_homebrew_formula_urls "$prerelease_formula"
for asset in "$HOMEBREW_CLI_ASSET" "$HOMEBREW_GATEWAY_ASSET" "$HOMEBREW_DRIVER_VM_ASSET" "$HOMEBREW_PROVER_ASSET"; do
  if ! grep -Fq "file://${RELEASE_ASSET_DIR}/${asset}" "$prerelease_formula"; then
    echo "FAIL: prerelease formula did not use local asset ${asset}" >&2
    exit 1
  fi
done

unset -f gh uname linux_package_method

echo "install.sh focused tests passed"
