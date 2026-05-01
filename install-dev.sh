#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install the OpenShell development build from the rolling GitHub `dev` release.
#
# This script is intended as a convenient installer for development builds. It
# currently supports Debian packages on Linux amd64 and arm64 only.
#
set -e

APP_NAME="openshell"
REPO="NVIDIA/OpenShell"
GITHUB_URL="https://github.com/${REPO}"
RELEASE_TAG="dev"
CHECKSUMS_NAME="openshell-checksums-sha256.txt"

info() {
  printf '%s: %s\n' "$APP_NAME" "$*" >&2
}

error() {
  printf '%s: error: %s\n' "$APP_NAME" "$*" >&2
  exit 1
}

usage() {
  cat <<EOF
install-dev.sh - Install the OpenShell development Debian package

USAGE:
    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-dev.sh -o install-dev.sh
    sh install-dev.sh

    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-dev.sh | sh

OPTIONS:
    --help       Print this help message

NOTES:
    This installs the rolling development release from:
    ${GITHUB_URL}/releases/tag/${RELEASE_TAG}

    Only Linux amd64 and arm64 Debian packages are supported right now.
EOF
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
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

download_release_asset() {
  _filename="$1"
  _output="$2"

  if curl -fLs --retry 3 --max-redirs 5 -o "$_output" \
    "${GITHUB_URL}/releases/download/${RELEASE_TAG}/${_filename}"; then
    return 0
  fi

  # GitHub normalizes `~` to `.` in release asset names, while the checksum file
  # still records the Debian package filename with `~dev` for correct version
  # ordering. Download the normalized asset but verify it against the checksum
  # entry for the original package filename.
  _normalized="$(printf '%s' "$_filename" | tr '~' '.')"
  if [ "$_normalized" != "$_filename" ]; then
    if download "${GITHUB_URL}/releases/download/${RELEASE_TAG}/${_normalized}" "$_output"; then
      info "using GitHub-normalized asset name ${_normalized}"
      return 0
    fi
  fi

  return 1
}

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif has_cmd sudo; then
    sudo "$@"
  else
    error "this installer needs root privileges; rerun as root or install sudo"
  fi
}

target_user() {
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    echo "$SUDO_USER"
  else
    id -un
  fi
}

user_home() {
  _user="$1"
  if has_cmd getent; then
    _home="$(getent passwd "$_user" | awk -F: '{ print $6 }')"
    if [ -n "$_home" ]; then
      echo "$_home"
      return 0
    fi
  fi

  if [ "$(id -un)" = "$_user" ]; then
    echo "${HOME:-}"
    return 0
  fi

  echo "/home/${_user}"
}

as_target_user() {
  _bus="unix:path=${TARGET_RUNTIME_DIR}/bus"
  if [ "$(id -u)" -eq "$TARGET_UID" ]; then
    env HOME="$TARGET_HOME" XDG_RUNTIME_DIR="$TARGET_RUNTIME_DIR" DBUS_SESSION_BUS_ADDRESS="$_bus" "$@"
  elif has_cmd sudo; then
    sudo -u "$TARGET_USER" env HOME="$TARGET_HOME" XDG_RUNTIME_DIR="$TARGET_RUNTIME_DIR" DBUS_SESSION_BUS_ADDRESS="$_bus" "$@"
  elif has_cmd runuser; then
    runuser -u "$TARGET_USER" -- env HOME="$TARGET_HOME" XDG_RUNTIME_DIR="$TARGET_RUNTIME_DIR" DBUS_SESSION_BUS_ADDRESS="$_bus" "$@"
  else
    error "cannot run user service commands as ${TARGET_USER}; install sudo or run as ${TARGET_USER}"
  fi
}

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

install_deb_package() {
  _deb_path="$1"

  if has_cmd apt-get; then
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confnew \
      "$_deb_path"
  elif has_cmd apt; then
    as_root env DEBIAN_FRONTEND=noninteractive apt install -y \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confnew \
      "$_deb_path"
  else
    as_root dpkg --force-confdef --force-confnew -i "$_deb_path"
  fi
}

start_user_gateway() {
  info "starting openshell-gateway user service as ${TARGET_USER}..."

  if ! as_target_user systemctl --user daemon-reload; then
    info "could not reach the user systemd manager for ${TARGET_USER}"
    info "start the gateway later with: systemctl --user enable --now openshell-gateway"
    info "then register it with: openshell gateway add http://127.0.0.1:17670 --local --name local"
    return 0
  fi

  as_target_user systemctl --user enable --now openshell-gateway
  as_target_user systemctl --user is-active --quiet openshell-gateway

  info "registering local gateway as ${TARGET_USER}..."
  as_target_user openshell gateway add http://127.0.0.1:17670 --local --name local \
    || as_target_user openshell gateway select local
}

main() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
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

  TARGET_USER="$(target_user)"
  TARGET_UID="$(id -u "$TARGET_USER" 2>/dev/null || true)"
  [ -n "$TARGET_UID" ] || error "cannot resolve uid for ${TARGET_USER}"
  TARGET_HOME="$(user_home "$TARGET_USER")"
  if [ "$(id -u)" -eq "$TARGET_UID" ] && [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    TARGET_RUNTIME_DIR="$XDG_RUNTIME_DIR"
  else
    TARGET_RUNTIME_DIR="/run/user/${TARGET_UID}"
  fi

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

  _deb_url="${GITHUB_URL}/releases/download/${RELEASE_TAG}/${_deb_file}"
  _deb_path="${_tmpdir}/${_deb_file}"

  info "selected ${_deb_file}"

  info "downloading ${_deb_file}..."
  download_release_asset "$_deb_file" "$_deb_path" || {
    error "failed to download ${_deb_url}"
  }
  chmod 0644 "$_deb_path"

  info "verifying checksum..."
  verify_checksum "$_deb_path" "${_tmpdir}/${CHECKSUMS_NAME}" "$_deb_file"

  info "installing ${_deb_file}..."
  install_deb_package "$_deb_path"
  info "installed ${APP_NAME} development package"
  start_user_gateway
}

main "$@"
