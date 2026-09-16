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
        *)
          if [ "${MOCK_NO_PRERELEASE:-0}" != "1" ]; then
            printf '%s\n' \
              openshell-v0.1.0-pre.9-linux-amd64-deb \
              openshell-v1.0.0-pre.2-linux-amd64-deb \
              openshell-v1.0.0-pre.1-macos-arm64 \
              openshell-v0.2.0-pre.10-linux-aarch64-rpm
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

if (MOCK_NO_PRERELEASE=1 OPENSHELL_VERSION=pre resolve_release_tag) >"$out" 2>"$err"; then
  echo "FAIL: pre alias should fail when no unexpired prerelease artifacts exist" >&2
  exit 1
fi
if ! grep -Fq 'no unexpired prerelease artifacts found' "$err"; then
  echo "FAIL: missing prerelease resolution failure was not explained" >&2
  cat "$err" >&2
  exit 1
fi

if [ "$(OPENSHELL_VERSION=pre-0.1.0 resolve_release_tag)" != "v0.1.0-pre.9" ]; then
  echo "FAIL: explicit prerelease train did not resolve its latest candidate" >&2
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

for asset in "$HOMEBREW_CLI_ASSET" "$HOMEBREW_GATEWAY_ASSET" "$HOMEBREW_DRIVER_VM_ASSET"; do
  : >"${RELEASE_ASSET_DIR}/${asset}"
done
prerelease_formula="${tmpdir}/openshell.rb"
printf '%s\n' \
  "  url \"${GITHUB_URL}/releases/download/${RELEASE_TAG}/${HOMEBREW_CLI_ASSET}\"" \
  "    url \"${GITHUB_URL}/releases/download/${RELEASE_TAG}/${HOMEBREW_GATEWAY_ASSET}\"" \
  "    url \"${GITHUB_URL}/releases/download/${RELEASE_TAG}/${HOMEBREW_DRIVER_VM_ASSET}\"" \
  >"$prerelease_formula"
patch_prerelease_homebrew_formula_urls "$prerelease_formula"
for asset in "$HOMEBREW_CLI_ASSET" "$HOMEBREW_GATEWAY_ASSET" "$HOMEBREW_DRIVER_VM_ASSET"; do
  if ! grep -Fq "file://${RELEASE_ASSET_DIR}/${asset}" "$prerelease_formula"; then
    echo "FAIL: prerelease formula did not use local asset ${asset}" >&2
    exit 1
  fi
done

unset -f gh uname linux_package_method

echo "install.sh focused tests passed"
