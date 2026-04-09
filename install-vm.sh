#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install the openshell-vm binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-vm.sh | sh
#
# Or run directly:
#   ./install-vm.sh
#
# Environment variables:
#   OPENSHELL_VM_INSTALL_DIR - Directory to install into (default: ~/.local/bin)
#
set -eu

APP_NAME="openshell-vm"
REPO="NVIDIA/OpenShell"
GITHUB_URL="https://github.com/${REPO}"
RELEASE_TAG="vm-dev"

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
# HTTP helpers
# ---------------------------------------------------------------------------

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

check_downloader() {
  if has_cmd curl; then
    return 0
  elif has_cmd wget; then
    return 0
  else
    error "either 'curl' or 'wget' is required to download files"
  fi
}

download() {
  _url="$1"
  _output="$2"

  if has_cmd curl; then
    curl -fLsS --retry 3 --max-redirs 5 -o "$_output" "$_url"
  elif has_cmd wget; then
    wget -q --tries=3 --max-redirect=5 -O "$_output" "$_url"
  fi
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

get_target() {
  _arch="$(uname -m)"
  _os="$(uname -s)"

  case "$_os" in
    Darwin)
      case "$_arch" in
        arm64|aarch64) echo "aarch64-apple-darwin" ;;
        *) error "macOS x86_64 is not supported; use Apple Silicon" ;;
      esac
      ;;
    Linux)
      case "$_arch" in
        x86_64|amd64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) error "unsupported architecture: $_arch" ;;
      esac
      ;;
    *) error "unsupported OS: $_os" ;;
  esac
}

# ---------------------------------------------------------------------------
# Checksum verification
# ---------------------------------------------------------------------------

verify_checksum() {
  _vc_archive="$1"
  _vc_checksums="$2"
  _vc_filename="$3"

  if ! has_cmd shasum && ! has_cmd sha256sum; then
    error "neither 'shasum' nor 'sha256sum' found; cannot verify download integrity"
  fi

  _vc_expected="$(grep -F "$_vc_filename" "$_vc_checksums" | awk '{print $1}')"

  if [ -z "$_vc_expected" ]; then
    error "no checksum entry found for $_vc_filename in checksums file"
  fi

  if has_cmd sha256sum; then
    echo "$_vc_expected  $_vc_archive" | sha256sum -c --quiet 2>/dev/null
  elif has_cmd shasum; then
    echo "$_vc_expected  $_vc_archive" | shasum -a 256 -c --quiet 2>/dev/null
  fi
}

# ---------------------------------------------------------------------------
# Install location
# ---------------------------------------------------------------------------

get_install_dir() {
  if [ -n "${OPENSHELL_VM_INSTALL_DIR:-}" ]; then
    echo "$OPENSHELL_VM_INSTALL_DIR"
  else
    echo "${HOME}/.local/bin"
  fi
}

is_on_path() {
  case ":${PATH}:" in
    *":$1:"*) return 0 ;;
    *)        return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# macOS codesign
# ---------------------------------------------------------------------------

codesign_binary() {
  _binary="$1"

  if [ "$(uname -s)" != "Darwin" ]; then
    return 0
  fi

  if ! has_cmd codesign; then
    info "warning: codesign not found; the binary will fail without the Hypervisor entitlement"
    return 0
  fi

  info "codesigning with Hypervisor entitlement..."
  _entitlements="$(mktemp)"
  cat > "$_entitlements" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
PLIST
  codesign --entitlements "$_entitlements" --force -s - "$_binary"
  rm -f "$_entitlements"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  for arg in "$@"; do
    case "$arg" in
      --help)
        cat <<EOF
install-vm.sh — Install the openshell-vm MicroVM runtime

USAGE:
    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-vm.sh | sh

ENVIRONMENT VARIABLES:
    OPENSHELL_VM_INSTALL_DIR   Directory to install into (default: ~/.local/bin)
EOF
        exit 0
        ;;
      *) error "unknown option: $arg" ;;
    esac
  done

  check_downloader

  _target="$(get_target)"
  _filename="${APP_NAME}-${_target}.tar.gz"
  _download_url="${GITHUB_URL}/releases/download/${RELEASE_TAG}/${_filename}"
  _checksums_url="${GITHUB_URL}/releases/download/${RELEASE_TAG}/vm-binary-checksums-sha256.txt"
  _install_dir="$(get_install_dir)"

  info "downloading ${APP_NAME} (${_target})..."

  _tmpdir="$(mktemp -d)"
  trap 'rm -rf "$_tmpdir"' EXIT

  if ! download "$_download_url" "${_tmpdir}/${_filename}"; then
    error "failed to download ${_download_url}"
  fi

  info "verifying checksum..."
  if ! download "$_checksums_url" "${_tmpdir}/checksums.txt"; then
    error "failed to download checksums file from ${_checksums_url}"
  fi
  if ! verify_checksum "${_tmpdir}/${_filename}" "${_tmpdir}/checksums.txt" "$_filename"; then
    error "checksum verification failed for ${_filename}"
  fi

  info "extracting..."
  tar -xzf "${_tmpdir}/${_filename}" -C "${_tmpdir}" --no-same-owner --no-same-permissions "${APP_NAME}"

  mkdir -p "$_install_dir" 2>/dev/null || true

  if [ -w "$_install_dir" ] || mkdir -p "$_install_dir" 2>/dev/null; then
    install -m 755 "${_tmpdir}/${APP_NAME}" "${_install_dir}/${APP_NAME}"
  else
    info "elevated permissions required to install to ${_install_dir}"
    sudo mkdir -p "$_install_dir"
    sudo install -m 755 "${_tmpdir}/${APP_NAME}" "${_install_dir}/${APP_NAME}"
  fi

  codesign_binary "${_install_dir}/${APP_NAME}"

  info "installed ${APP_NAME} to ${_install_dir}/${APP_NAME}"

  if ! is_on_path "$_install_dir"; then
    echo ""
    info "${_install_dir} is not on your PATH."
    info ""
    info "Add it by appending the following to your shell config:"
    info ""

    _current_shell="$(basename "${SHELL:-sh}" 2>/dev/null || echo "sh")"
    case "$_current_shell" in
      fish) info "    fish_add_path ${_install_dir}" ;;
      *)    info "    export PATH=\"${_install_dir}:\$PATH\"" ;;
    esac
    info ""
  fi
}

main "$@"
