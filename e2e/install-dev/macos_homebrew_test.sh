#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Fake-Homebrew regression test for install-dev.sh on macOS.

set -eu

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FAKE_BIN="${TEST_DIR}/bin"
BREW_TAP_DIR="${TEST_DIR}/homebrew/Library/Taps/nvidia/homebrew-openshell-dev"
BREW_PREFIX="${TEST_DIR}/prefix"
BREW_LOG="${TEST_DIR}/brew.log"
INSTALL_OUTPUT="${TEST_DIR}/install.out"

mkdir -p "$FAKE_BIN" "$BREW_PREFIX/bin" "${TEST_DIR}/home"
: >"$BREW_LOG"

cat >"${FAKE_BIN}/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s)
    echo Darwin
    ;;
  -m)
    echo arm64
    ;;
  *)
    /usr/bin/uname "$@"
    ;;
esac
EOF
chmod +x "${FAKE_BIN}/uname"

cat >"${FAKE_BIN}/curl" <<'EOF'
#!/bin/sh
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      shift
      output="$1"
      ;;
  esac
  shift
done

[ -n "$output" ] || exit 2
cat >"$output" <<'FORMULA'
class Openshell < Formula
end
FORMULA
EOF
chmod +x "${FAKE_BIN}/curl"

cat >"${FAKE_BIN}/brew" <<'EOF'
#!/bin/sh
printf 'brew %s\n' "$*" >>"$BREW_LOG"

case "$1" in
  --version)
    echo "Homebrew 5.1.9"
    ;;
  tap-info)
    exit 1
    ;;
  tap-new)
    mkdir -p "${BREW_TAP_DIR}/Formula"
    ;;
  --repository)
    echo "$BREW_TAP_DIR"
    ;;
  list)
    exit 1
    ;;
  install|reinstall)
    ;;
  services)
    ;;
  --prefix)
    echo "$BREW_PREFIX"
    ;;
  *)
    echo "unexpected brew command: $*" >&2
    exit 99
    ;;
esac
EOF
chmod +x "${FAKE_BIN}/brew"

cat >"${BREW_PREFIX}/bin/openshell" <<'EOF'
#!/bin/sh
printf 'openshell %s\n' "$*" >>"$BREW_LOG"
EOF
chmod +x "${BREW_PREFIX}/bin/openshell"

PATH="${FAKE_BIN}:/usr/bin:/bin:/usr/sbin:/sbin" \
  HOME="${TEST_DIR}/home" \
  BREW_LOG="$BREW_LOG" \
  BREW_TAP_DIR="$BREW_TAP_DIR" \
  BREW_PREFIX="$BREW_PREFIX" \
  sh "${REPO_ROOT}/install-dev.sh" >"$INSTALL_OUTPUT" 2>&1

assert_log_contains() {
  _needle="$1"
  if ! grep -qF "$_needle" "$BREW_LOG"; then
    echo "missing log entry: $_needle" >&2
    echo "--- brew log ---" >&2
    cat "$BREW_LOG" >&2
    echo "--- installer output ---" >&2
    cat "$INSTALL_OUTPUT" >&2
    exit 1
  fi
}

assert_log_contains "brew tap-new --no-git nvidia/openshell-dev"
assert_log_contains "brew install --formula nvidia/openshell-dev/openshell"
assert_log_contains "brew services restart openshell"
assert_log_contains "openshell gateway add http://127.0.0.1:17670 --local --name local"

if ! grep -qF "class Openshell < Formula" "${BREW_TAP_DIR}/Formula/openshell.rb"; then
  echo "formula was not staged into the local tap" >&2
  exit 1
fi

if grep -Eq 'brew (install|reinstall) --formula .*[.]rb' "$BREW_LOG"; then
  echo "installer still passed a formula file path to Homebrew" >&2
  cat "$BREW_LOG" >&2
  exit 1
fi

echo "install-dev macOS Homebrew test passed"
