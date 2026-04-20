#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install the OpenShell gateway + VM compute driver for local MicroVM sandboxes.
#
# This installs two binaries:
#   - openshell-gateway       — control-plane server (from the `dev` release).
#   - openshell-driver-vm     — libkrun-backed VM compute driver (from the
#                               `vm-dev` release). The gateway auto-detects
#                               this driver via its driver directory.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-vm.sh | sh
#
# Or run directly:
#   ./install-vm.sh
#
# Environment variables:
#   OPENSHELL_INSTALL_DIR        Directory for the gateway binary
#                                (default: ~/.local/bin).
#   OPENSHELL_DRIVER_DIR         Directory for compute-driver binaries
#                                (default: ~/.local/libexec/openshell).
#                                If you install elsewhere, pass the same
#                                directory via the gateway's --driver-dir flag.
#
set -eu

REPO="NVIDIA/OpenShell"
GITHUB_URL="https://github.com/${REPO}"

# Release tags
GATEWAY_RELEASE_TAG="dev"
DRIVER_VM_RELEASE_TAG="vm-dev"

# Binary names (must match what the gateway expects to find).
GATEWAY_BIN="openshell-gateway"
DRIVER_VM_BIN="openshell-driver-vm"

# Logging label.
APP_NAME="openshell-vm-install"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

info() {
  printf '%s: %s\n' "$APP_NAME" "$*" >&2
}

warn() {
  printf '%s: warning: %s\n' "$APP_NAME" "$*" >&2
}

error() {
  printf '%s: error: %s\n' "$APP_NAME" "$*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# HTTP helpers — prefer curl, fall back to wget
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

# Follow a URL and print the final resolved URL (for detecting redirect targets).
resolve_redirect() {
  _url="$1"

  if has_cmd curl; then
    curl -fLsS -o /dev/null -w '%{url_effective}' "$_url"
  elif has_cmd wget; then
    wget --spider --max-redirect=10 "$_url" 2>&1 | sed -n 's/^.*Location: \([^ ]*\).*/\1/p' | tail -1
  fi
}

# Validate that a download URL resolves to the expected GitHub origin.
# A MITM or DNS hijack could redirect to an attacker-controlled domain,
# which would also serve a matching checksums file (making checksum
# verification useless). See: https://github.com/NVIDIA/OpenShell/issues/638
validate_download_origin() {
  _vdo_url="$1"
  _resolved="$(resolve_redirect "$_vdo_url")" || return 0  # best-effort

  case "$_resolved" in
    https://github.com/${REPO}/*) ;;
    https://objects.githubusercontent.com/*) ;;
    https://release-assets.githubusercontent.com/*) ;;
    *)
      error "unexpected redirect target: ${_resolved} (expected github.com/${REPO}/...)"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

# Both binaries ship the same set of triples under the same naming scheme.
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

  if has_cmd shasum; then
    echo "$_vc_expected  $_vc_archive" | shasum -a 256 -c --quiet 2>/dev/null
  elif has_cmd sha256sum; then
    echo "$_vc_expected  $_vc_archive" | sha256sum -c --quiet 2>/dev/null
  fi
}

# ---------------------------------------------------------------------------
# Install locations
# ---------------------------------------------------------------------------

get_gateway_install_dir() {
  if [ -n "${OPENSHELL_INSTALL_DIR:-}" ]; then
    echo "$OPENSHELL_INSTALL_DIR"
  else
    echo "${HOME}/.local/bin"
  fi
}

# Default per-user install dir for the VM compute driver. Newer gateways also
# auto-discover conventional system installs under `/usr/local/libexec`.
get_driver_install_dir() {
  if [ -n "${OPENSHELL_DRIVER_DIR:-}" ]; then
    echo "$OPENSHELL_DRIVER_DIR"
  else
    echo "${HOME}/.local/libexec/openshell"
  fi
}

is_on_path() {
  case ":${PATH}:" in
    *":$1:"*) return 0 ;;
    *)        return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# macOS codesign — the VM driver runs libkrun and needs the hypervisor
# entitlement. The gateway does not.
# ---------------------------------------------------------------------------

codesign_driver_vm() {
  _binary="$1"
  _cs_tmpdir="$2"  # reuse caller's tmpdir for cleanup-safe temp files

  if [ "$(uname -s)" != "Darwin" ]; then
    return 0
  fi

  if ! has_cmd codesign; then
    warn "codesign not found; ${DRIVER_VM_BIN} will fail without the Hypervisor entitlement"
    return 0
  fi

  info "codesigning ${DRIVER_VM_BIN} with Hypervisor entitlement..."
  _entitlements="${_cs_tmpdir}/entitlements.plist"
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
}

# ---------------------------------------------------------------------------
# Download + install a single binary release asset
# ---------------------------------------------------------------------------

# Args:
#   $1  binary name (e.g. openshell-gateway)
#   $2  release tag (e.g. dev, vm-dev)
#   $3  target triple (e.g. aarch64-apple-darwin)
#   $4  checksums filename in the release (e.g. openshell-gateway-checksums-sha256.txt)
#   $5  destination directory
#   $6  tmp working dir (caller-owned; will be cleaned up outside)
install_release_binary() {
  _bin="$1"
  _tag="$2"
  _target="$3"
  _checksums_name="$4"
  _dest_dir="$5"
  _work_dir="$6"

  _filename="${_bin}-${_target}.tar.gz"
  _download_url="${GITHUB_URL}/releases/download/${_tag}/${_filename}"
  _checksums_url="${GITHUB_URL}/releases/download/${_tag}/${_checksums_name}"

  info "downloading ${_bin} from release '${_tag}' (${_target})..."

  validate_download_origin "$_download_url"

  if ! download "$_download_url" "${_work_dir}/${_filename}"; then
    error "failed to download ${_download_url}"
  fi

  if ! download "$_checksums_url" "${_work_dir}/${_bin}-checksums.txt"; then
    error "failed to download checksums file from ${_checksums_url}"
  fi

  info "verifying ${_bin} checksum..."
  if ! verify_checksum "${_work_dir}/${_filename}" "${_work_dir}/${_bin}-checksums.txt" "$_filename"; then
    error "checksum verification failed for ${_filename}"
  fi

  info "extracting ${_bin}..."
  tar -xzf "${_work_dir}/${_filename}" -C "${_work_dir}" --no-same-owner --no-same-permissions "${_bin}"

  # Install into destination dir, escalating with sudo if needed.
  if mkdir -p "$_dest_dir" 2>/dev/null && [ -w "$_dest_dir" ]; then
    install -m 755 "${_work_dir}/${_bin}" "${_dest_dir}/${_bin}"
  else
    info "elevated permissions required to install to ${_dest_dir}"
    sudo mkdir -p "$_dest_dir"
    sudo install -m 755 "${_work_dir}/${_bin}" "${_dest_dir}/${_bin}"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

usage() {
  cat <<EOF
install-vm.sh — Install the OpenShell gateway + VM compute driver

USAGE:
    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-vm.sh | sh
    ./install-vm.sh [OPTIONS]

OPTIONS:
    --help    Print this help message

ENVIRONMENT VARIABLES:
    OPENSHELL_INSTALL_DIR   Directory for the gateway binary
                            (default: ~/.local/bin).
    OPENSHELL_DRIVER_DIR    Directory for compute-driver binaries
                            (default: ~/.local/libexec/openshell).
                            If you install elsewhere, pass the same directory
                            via the gateway's --driver-dir flag.

EXAMPLES:
    # Install into defaults
    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-vm.sh | sh

    # Install gateway to /usr/local/bin and driver to /usr/local/libexec/openshell
    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-vm.sh \\
      | OPENSHELL_INSTALL_DIR=/usr/local/bin \\
        OPENSHELL_DRIVER_DIR=/usr/local/libexec/openshell sh
EOF
}

main() {
  for arg in "$@"; do
    case "$arg" in
      --help)
        usage
        exit 0
        ;;
      *) error "unknown option: $arg" ;;
    esac
  done

  check_downloader

  _target="$(get_target)"
  _gateway_dir="$(get_gateway_install_dir)"
  _driver_dir="$(get_driver_install_dir)"

  _tmpdir="$(mktemp -d)"
  trap 'rm -rf "$_tmpdir"' EXIT

  # 1. Gateway — from the rolling `dev` release.
  install_release_binary \
    "$GATEWAY_BIN" \
    "$GATEWAY_RELEASE_TAG" \
    "$_target" \
    "${GATEWAY_BIN}-checksums-sha256.txt" \
    "$_gateway_dir" \
    "$_tmpdir"

  # 2. VM compute driver — from the rolling `vm-dev` release. Shares the
  #    checksum file with openshell-vm (`vm-binary-checksums-sha256.txt`).
  install_release_binary \
    "$DRIVER_VM_BIN" \
    "$DRIVER_VM_RELEASE_TAG" \
    "$_target" \
    "vm-binary-checksums-sha256.txt" \
    "$_driver_dir" \
    "$_tmpdir"

  codesign_driver_vm "${_driver_dir}/${DRIVER_VM_BIN}" "$_tmpdir"

  _gateway_version="$("${_gateway_dir}/${GATEWAY_BIN}" --version 2>/dev/null || echo "${GATEWAY_RELEASE_TAG}")"
  info "installed ${_gateway_version} to ${_gateway_dir}/${GATEWAY_BIN}"
  info "installed ${DRIVER_VM_BIN} to ${_driver_dir}/${DRIVER_VM_BIN}"

  # Warn if the gateway dir isn't on PATH.
  if ! is_on_path "$_gateway_dir"; then
    echo ""
    info "${_gateway_dir} is not on your PATH."
    info ""
    info "Add it by appending the following to your shell configuration file"
    info "(e.g. ~/.bashrc, ~/.zshrc, or ~/.config/fish/config.fish):"
    info ""

    _current_shell="$(basename "${SHELL:-sh}" 2>/dev/null || echo "sh")"
    case "$_current_shell" in
      fish) info "    fish_add_path ${_gateway_dir}" ;;
      *)    info "    export PATH=\"${_gateway_dir}:\$PATH\"" ;;
    esac

    info ""
    info "Then restart your shell or run the command above in your current session."
  fi

  # ---------------------------------------------------------------------------
  # Next steps — print a working command to start the gateway.
  #
  # The VM compute driver requires:
  #   * --driver-dir           — only needed when the driver is installed
  #                               outside the built-in search paths:
  #                               ~/.local/libexec/openshell,
  #                               /usr/local/libexec/openshell,
  #                               /usr/local/libexec, or next to the gateway.
  #   * --grpc-endpoint         — URL the VM guest uses to call the gateway
  #                               back. Loopback is accepted; scheme must
  #                               match TLS mode.
  #   * --ssh-handshake-secret  — shared secret for gateway↔sandbox SSH.
  # ---------------------------------------------------------------------------

  echo ""
  info "Next steps — start the gateway with the VM compute driver:"
  echo ""

  _driver_dir_arg=""
  case "$_driver_dir" in
    "${HOME}/.local/libexec/openshell"|"/usr/local/libexec/openshell"|"/usr/local/libexec") ;;
    *)
      _driver_dir_arg="      --driver-dir '${_driver_dir}' \\
"
      ;;
  esac

  cat >&2 <<EOF
    ${GATEWAY_BIN} \\
      --drivers vm \\
${_driver_dir_arg}      --disable-tls \\
      --disable-gateway-auth \\
      --db-url 'sqlite::memory:' \\
      --grpc-endpoint 'http://127.0.0.1:8080' \\
      --ssh-handshake-secret "\$(openssl rand -hex 32)"
EOF

  echo ""
  info "See '${GATEWAY_BIN} --help' for TLS, persistence, and sandbox flags."
}

main "$@"
