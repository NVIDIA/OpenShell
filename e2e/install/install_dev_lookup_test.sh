#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# POSIX sh tests for install-dev.sh release asset lookup.
#
set -eu

. "$(dirname "$0")/helpers.sh"

INSTALL_DEV_SCRIPT="$REPO_ROOT/install-dev.sh"

_TMPDIR="$(mktemp -d)"
trap 'rm -rf "$_TMPDIR"' EXIT

_FUNCTIONS="${_TMPDIR}/install-dev-functions.sh"
awk '$0 == "main \"$@\"" { next } { print }' "$INSTALL_DEV_SCRIPT" > "$_FUNCTIONS"
. "$_FUNCTIONS"

write_checksums() {
  _path="$1"
  shift

  : > "$_path"
  for _line in "$@"; do
    printf '%s\n' "$_line" >> "$_path"
  done
}

assert_deb_asset() {
  _label="$1"
  _arch="$2"
  _expected="$3"
  shift 3

  _checksums="${_TMPDIR}/${_label}.checksums"
  write_checksums "$_checksums" "$@"

  _actual="$(find_deb_asset "$_checksums" "$_arch")"
  if [ "$_actual" = "$_expected" ]; then
    pass "$_label"
  else
    fail "$_label" "expected '${_expected}', got '${_actual}'"
  fi
}

assert_no_deb_asset() {
  _label="$1"
  _arch="$2"
  shift 2

  _checksums="${_TMPDIR}/${_label}.checksums"
  write_checksums "$_checksums" "$@"

  _actual="$(find_deb_asset "$_checksums" "$_arch")"
  if [ -z "$_actual" ]; then
    pass "$_label"
  else
    fail "$_label" "expected no match, got '${_actual}'"
  fi
}

printf '=== install-dev.sh asset lookup tests ===\n\n'

assert_deb_asset \
  "selects normalized amd64 dev asset" \
  "amd64" \
  "openshell-dev-amd64.deb" \
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  openshell-dev-amd64.deb" \
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  openshell-dev-arm64.deb"

assert_deb_asset \
  "selects normalized arm64 dev asset with binary marker" \
  "arm64" \
  "openshell-dev-arm64.deb" \
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa *openshell-dev-amd64.deb" \
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb *openshell-dev-arm64.deb"

assert_deb_asset \
  "keeps legacy Debian package fallback" \
  "amd64" \
  "openshell_0.1.0~dev_amd64.deb" \
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  openshell_0.1.0~dev_amd64.deb"

assert_deb_asset \
  "prefers normalized dev asset over legacy fallback" \
  "arm64" \
  "openshell-dev-arm64.deb" \
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  openshell_0.1.0~dev_arm64.deb" \
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  openshell-dev-arm64.deb"

assert_no_deb_asset \
  "ignores mismatched architecture" \
  "amd64" \
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  openshell-dev-arm64.deb"

print_summary
