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
#   - run_install          (runs install.sh against fake release assets)
#   - run_install_with_checksum_state / _expect_failure
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
TEST_ROOT=""
TEST_RELEASE_VERSION="v0.0.10-test"
TEST_DEFAULT_RELEASE_REPO="abols/OpenShell"
TEST_CURL_LOG=""
TEST_NON_PRODUCTION_OVERRIDE_ENV="OPENSHELL_INSTALL_ALLOW_INSECURE_PROVENANCE"

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

assert_setup_selection() {
  _ass_kind="$1"
  _ass_value="$2"
  _ass_label="$3"

  assert_output_contains "$INSTALL_OUTPUT" "validated setup ${_ass_kind} selection: ${_ass_value}" "$_ass_label"
}

assert_setup_selection_notice() {
  assert_output_contains "$INSTALL_OUTPUT" "applies to later OpenShell setup" "mentions later setup flow"
  assert_output_contains "$INSTALL_OUTPUT" "installs the openshell CLI" "keeps CLI installer scope clear"
}

assert_release_root_uses_repo() {
  _arr_repo="$1"
  _arr_label="$2"
  _arr_root="https://github.com/${_arr_repo}/releases"

  assert_output_contains "$(read_curl_log)" "${_arr_root}/latest" "${_arr_label}: latest release uses ${_arr_repo}"
  assert_output_contains "$(read_curl_log)" "${_arr_root}/download/${TEST_RELEASE_VERSION}" "${_arr_label}: asset download uses ${_arr_repo}"
}

assert_release_repo_validation_error() {
  _arv_value="$1"

  assert_output_contains "$INSTALL_OUTPUT" "invalid OPENSHELL_RELEASE_REPO" "rejects malformed release repo"
  assert_output_contains "$INSTALL_OUTPUT" "${_arv_value}" "includes malformed release repo value"
}

# ---------------------------------------------------------------------------
# Fake release assets
# ---------------------------------------------------------------------------

test_target() {
  case "$(uname -m)" in
    x86_64|amd64) _tt_arch="x86_64" ;;
    aarch64|arm64) _tt_arch="aarch64" ;;
    *) _tt_arch="x86_64" ;;
  esac

  case "$(uname -s)" in
    Darwin) _tt_os="apple-darwin" ;;
    *) _tt_os="unknown-linux-musl" ;;
  esac

  printf '%s-%s\n' "$_tt_arch" "$_tt_os"
}

setup_fake_release_assets() {
  TEST_ROOT="$(mktemp -d)"
  _target="$(test_target)"
  _filename="openshell-${_target}.tar.gz"
  _checksums_filename="openshell-checksums-sha256.txt"
  _release_dir="${TEST_ROOT}/releases/download/${TEST_RELEASE_VERSION}"
  _fake_bin_dir="${TEST_ROOT}/fakebin"
  TEST_CURL_LOG="${TEST_ROOT}/curl.log"

  mkdir -p "$_release_dir" "$_fake_bin_dir"
  : >"$TEST_CURL_LOG"

  cat >"${TEST_ROOT}/openshell" <<EOF
#!/bin/sh
if [ "\${1:-}" = "--version" ]; then
  printf 'openshell %s\n' "${TEST_RELEASE_VERSION}"
else
  printf 'openshell test binary\n'
fi
EOF
  chmod 755 "${TEST_ROOT}/openshell"

  tar -czf "${_release_dir}/${_filename}" -C "${TEST_ROOT}" openshell

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${_release_dir}/${_filename}" | awk '{print $1 "  '"${_filename}"'"}' >"${_release_dir}/${_checksums_filename}"
  else
    sha256sum "${_release_dir}/${_filename}" | awk '{print $1 "  '"${_filename}"'"}' >"${_release_dir}/${_checksums_filename}"
  fi

  cat >"${_fake_bin_dir}/curl" <<'EOF'
#!/bin/sh
set -eu

_output=""
_format=""
_url=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      _output="$2"
      shift 2
      ;;
    -w)
      _format="$2"
      shift 2
      ;;
    --retry)
      shift 2
      ;;
    -f|-L|-s|-S)
      shift
      ;;
    *)
      _url="$1"
      shift
      ;;
  esac
done

printf '%s\n' "$_url" >>"${TEST_CURL_LOG}"

if [ -n "$_format" ]; then
  case "$_url" in
    */releases/latest)
      _release_root="${_url%/releases/latest}"
      printf '%s/releases/tag/%s' "${_release_root}" "${TEST_RELEASE_VERSION}"
      ;;
    *)
      printf '%s' "$_url"
      ;;
  esac
  exit 0
fi

_name="${_url##*/}"
[ -n "$_output" ] || exit 1
[ -f "${TEST_RELEASE_DIR}/${_name}" ] || exit 22
cp "${TEST_RELEASE_DIR}/${_name}" "$_output"
EOF
  chmod 755 "${_fake_bin_dir}/curl"
}

apply_checksum_state() {
  _checksum_state="${1:-manifest-present}"
  _release_dir="${TEST_ROOT}/releases/download/${TEST_RELEASE_VERSION}"
  _target="$(test_target)"
  _filename="openshell-${_target}.tar.gz"
  _checksums_filename="openshell-checksums-sha256.txt"

  case "$_checksum_state" in
    manifest-present)
      ;;
    manifest-missing)
      rm -f "${_release_dir}/${_checksums_filename}"
      ;;
    checksum-mismatch)
      printf 'tampered archive\n' >>"${_release_dir}/${_filename}"
      ;;
    *)
      printf 'unknown checksum state: %s\n' "$_checksum_state" >&2
      return 1
      ;;
  esac
}

run_with_test_env() {
  INSTALL_OUTPUT="$(env \
    OPENSHELL_INSTALL_DIR="$INSTALL_DIR" \
    PATH="${TEST_ROOT}/fakebin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    SHELL="${SHELL:-/bin/sh}" \
    TEST_RELEASE_DIR="${TEST_ROOT}/releases/download/${TEST_RELEASE_VERSION}" \
    TEST_RELEASE_VERSION="${TEST_RELEASE_VERSION}" \
    TEST_CURL_LOG="$TEST_CURL_LOG" \
    "$@" 2>&1)"
}

read_curl_log() {
  if [ -n "$TEST_CURL_LOG" ] && [ -f "$TEST_CURL_LOG" ]; then
    tr '\n' '\n' <"$TEST_CURL_LOG"
  fi
}

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
  setup_fake_release_assets

  run_with_test_env sh "$INSTALL_SCRIPT" || {
    printf 'install.sh failed:\n%s\n' "$INSTALL_OUTPUT" >&2
    return 1
  }
}

# Run install.sh with additional environment variables and expect success.
run_install_with_env() {
  INSTALL_DIR="$(mktemp -d)/bin"
  setup_fake_release_assets

  run_with_test_env env "$@" sh "$INSTALL_SCRIPT" || {
    printf 'install.sh failed:\n%s\n' "$INSTALL_OUTPUT" >&2
    return 1
  }
}

run_install_with_args() {
  INSTALL_DIR="$(mktemp -d)/bin"
  setup_fake_release_assets

  run_with_test_env sh "$INSTALL_SCRIPT" "$@" || {
    printf 'install.sh failed:\n%s\n' "$INSTALL_OUTPUT" >&2
    return 1
  }
}

run_install_with_checksum_state() {
  INSTALL_DIR="$(mktemp -d)/bin"
  setup_fake_release_assets
  apply_checksum_state "$1" || return 1

  run_with_test_env sh "$INSTALL_SCRIPT" || {
    printf 'install.sh failed:\n%s\n' "$INSTALL_OUTPUT" >&2
    return 1
  }
}

# Run install.sh with additional environment variables and expect failure.
run_install_expect_failure() {
  INSTALL_DIR="$(mktemp -d)/bin"
  setup_fake_release_assets

  if run_with_test_env env "$@" sh "$INSTALL_SCRIPT"
  then
    printf 'install.sh unexpectedly succeeded:\n%s\n' "$INSTALL_OUTPUT" >&2
    return 1
  fi
}

run_install_with_checksum_state_expect_failure() {
  INSTALL_DIR="$(mktemp -d)/bin"
  setup_fake_release_assets
  apply_checksum_state "$1" || return 1

  if run_with_test_env sh "$INSTALL_SCRIPT"
  then
    printf 'install.sh unexpectedly succeeded:\n%s\n' "$INSTALL_OUTPUT" >&2
    return 1
  fi
}

run_install_args_expect_failure() {
  INSTALL_DIR="$(mktemp -d)/bin"
  setup_fake_release_assets

  if run_with_test_env sh "$INSTALL_SCRIPT" "$@"
  then
    printf 'install.sh unexpectedly succeeded:\n%s\n' "$INSTALL_OUTPUT" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
  printf '\n=== Results: %d passed, %d failed ===\n' "$_PASS" "$_FAIL"
  [ "$_FAIL" -eq 0 ]
}
