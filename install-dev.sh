#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install the OpenShell development build from the rolling GitHub `dev` release.
#
# This script is intended as a convenient installer for development builds. It
# currently supports Debian packages on Linux amd64 and arm64 only.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-dev.sh -o install-dev.sh
#   sh install-dev.sh --dry-run
#   sh install-dev.sh
#
set -e

APP_NAME="openshell"
REPO="NVIDIA/OpenShell"
GITHUB_URL="https://github.com/${REPO}"
RELEASE_TAG="dev"
CHECKSUMS_NAME="openshell-checksums-sha256.txt"
DRY_RUN="${DRY_RUN:-}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

info() {
  printf '%s: %s\n' "$APP_NAME" "$*" >&2
}

error() {
  printf '%s: error: %s\n' "$APP_NAME" "$*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
  cat <<EOF
install-dev.sh - Install the OpenShell development Debian package

USAGE:
    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-dev.sh -o install-dev.sh
    sh install-dev.sh --dry-run
    sh install-dev.sh

    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-dev.sh | sh

OPTIONS:
    --dry-run    Print the install commands without installing the package
    --help       Print this help message

ENVIRONMENT VARIABLES:
    DRY_RUN=1    Same as --dry-run

NOTES:
    This installs the rolling development release from:
    ${GITHUB_URL}/releases/tag/${RELEASE_TAG}

    Only Linux amd64 and arm64 Debian packages are supported right now.
EOF
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

is_dry_run() {
  [ -n "$DRY_RUN" ]
}

require_cmd() {
  if ! has_cmd "$1"; then
    error "'$1' is required"
  fi
}

download() {
  _url="$1"
  _output="$2"
  curl -fLsS --retry 3 --max-redirs 5 -o "$_output" "$_url"
}

resolve_redirect() {
  _url="$1"
  curl -fLsS -I -o /dev/null -w '%{url_effective}' "$_url"
}

download_url_available() {
  _url="$1"
  _resolved="$(resolve_redirect "$_url" 2>/dev/null)" || return 1

  case "$_resolved" in
    https://github.com/${REPO}/*) return 0 ;;
    https://objects.githubusercontent.com/*) return 0 ;;
    https://release-assets.githubusercontent.com/*) return 0 ;;
    *)
      error "unexpected redirect target: ${_resolved}"
      ;;
  esac
}

resolve_release_asset_name() {
  _filename="$1"
  _url="${GITHUB_URL}/releases/download/${RELEASE_TAG}/${_filename}"

  if download_url_available "$_url"; then
    echo "$_filename"
    return 0
  fi

  # GitHub normalizes `~` to `.` in release asset names, while the checksum file
  # still records the Debian package filename with `~dev` for correct version
  # ordering. Download the normalized asset but verify it against the checksum
  # entry for the original package filename.
  _normalized="$(printf '%s' "$_filename" | tr '~' '.')"
  if [ "$_normalized" != "$_filename" ]; then
    _url="${GITHUB_URL}/releases/download/${RELEASE_TAG}/${_normalized}"
    if download_url_available "$_url"; then
      info "using GitHub-normalized asset name ${_normalized}"
      echo "$_normalized"
      return 0
    fi
  fi

  return 1
}

quote_arg() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

print_command() {
  printf '+' >&2
  for _arg in "$@"; do
    printf ' ' >&2
    quote_arg "$_arg" >&2
  done
  printf '\n' >&2
}

run_privileged() {
  if is_dry_run; then
    if [ "$(id -u)" -eq 0 ]; then
      print_command "$@"
    else
      print_command sudo "$@"
    fi
    return 0
  fi

  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif has_cmd sudo; then
    sudo "$@"
  else
    error "this installer needs root privileges; rerun as root or install sudo"
  fi
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

check_platform() {
  if [ "$(uname -s)" != "Linux" ]; then
    error "unsupported OS: $(uname -s); dev Debian packages require Linux"
  fi

  require_cmd dpkg
}

get_deb_arch() {
  _arch="$(dpkg --print-architecture)"

  case "$_arch" in
    amd64|arm64)
      echo "$_arch"
      ;;
    *)
      error "no dev Debian package is published for architecture: ${_arch}"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Checksum helpers
# ---------------------------------------------------------------------------

find_deb_asset() {
  _checksums="$1"
  _arch="$2"

  awk -v arch="$_arch" '
    $2 ~ "^\\*?openshell_.*_" arch "\\.deb$" {
      sub("^\\*", "", $2)
      print $2
      exit
    }
  ' "$_checksums"
}

verify_checksum() {
  _archive="$1"
  _checksums="$2"
  _filename="$3"

  if has_cmd sha256sum; then
    _expected="$(awk -v name="$_filename" '($2 == name || $2 == "*" name) { print $1; exit }' "$_checksums")"
    [ -n "$_expected" ] || error "no checksum entry found for ${_filename}"
    echo "$_expected  $_archive" | sha256sum -c --quiet
  elif has_cmd shasum; then
    _expected="$(awk -v name="$_filename" '($2 == name || $2 == "*" name) { print $1; exit }' "$_checksums")"
    [ -n "$_expected" ] || error "no checksum entry found for ${_filename}"
    echo "$_expected  $_archive" | shasum -a 256 -c --quiet
  else
    error "neither 'sha256sum' nor 'shasum' found; cannot verify download integrity"
  fi
}

# ---------------------------------------------------------------------------
# Package installation
# ---------------------------------------------------------------------------

install_deb_package() {
  _deb_path="$1"

  if has_cmd apt-get; then
    run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confnew \
      "$_deb_path"
  elif has_cmd apt; then
    run_privileged env DEBIAN_FRONTEND=noninteractive apt install -y \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confnew \
      "$_deb_path"
  else
    run_privileged dpkg --force-confdef --force-confnew -i "$_deb_path"
  fi
}

print_next_steps() {
  info "installed ${APP_NAME} development package"

  if has_cmd systemctl; then
    info "the openshell-gateway systemd unit is installed but not enabled"
    info "start it with: sudo systemctl enable --now openshell-gateway"
  fi

  info "the packaged gateway is registered as the system-wide default"
  info "check it with: openshell status"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        ;;
      --help)
        usage
        exit 0
        ;;
      *)
        error "unknown option: $1"
        ;;
    esac
    shift
  done

  require_cmd curl
  check_platform

  _arch="$(get_deb_arch)"
  _tmpdir="$(mktemp -d)"
  chmod 0755 "$_tmpdir"
  trap 'rm -rf "$_tmpdir"' EXIT

  _checksums_url="${GITHUB_URL}/releases/download/${RELEASE_TAG}/${CHECKSUMS_NAME}"
  info "downloading ${RELEASE_TAG} release checksums..."
  download "$_checksums_url" "${_tmpdir}/${CHECKSUMS_NAME}" || {
    error "failed to download ${_checksums_url}"
  }

  _deb_file="$(find_deb_asset "${_tmpdir}/${CHECKSUMS_NAME}" "$_arch")"
  if [ -z "$_deb_file" ]; then
    error "no dev Debian package found for architecture: ${_arch}"
  fi

  _deb_download_file="$(resolve_release_asset_name "$_deb_file")" || {
    error "failed to resolve download URL for ${_deb_file}"
  }
  _deb_url="${GITHUB_URL}/releases/download/${RELEASE_TAG}/${_deb_download_file}"
  _deb_path="${_tmpdir}/${_deb_file}"

  info "selected ${_deb_file}"

  if is_dry_run; then
    print_command curl -fLsS --retry 3 --max-redirs 5 -o "$_deb_path" "$_deb_url"
    info "would verify ${_deb_file} with ${CHECKSUMS_NAME}"
    install_deb_package "$_deb_path"
    exit 0
  fi

  info "downloading ${_deb_file}..."
  download "$_deb_url" "$_deb_path" || {
    error "failed to download ${_deb_url}"
  }
  chmod 0644 "$_deb_path"

  info "verifying checksum..."
  verify_checksum "$_deb_path" "${_tmpdir}/${CHECKSUMS_NAME}" "$_deb_file"

  info "installing ${_deb_file}..."
  install_deb_package "$_deb_path"
  print_next_steps
}

main "$@"
