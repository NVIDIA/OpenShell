#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install the OpenShell CLI binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
#
# Environment variables:
#   OPENSHELL_VERSION    - Release tag to install (default: "devel")
#   OPENSHELL_INSTALL_DIR - Directory to install into (default: /usr/local/bin)
#
set -eu

REPO="NVIDIA/OpenShell"
VERSION="${OPENSHELL_VERSION:-devel}"
INSTALL_DIR="${OPENSHELL_INSTALL_DIR:-/usr/local/bin}"

info() {
  echo "openshell: $*" >&2
}

error() {
  echo "openshell: error: $*" >&2
  exit 1
}

get_os() {
  case "$(uname -s)" in
    Darwin) echo "apple-darwin" ;;
    Linux)  echo "unknown-linux-musl" ;;
    *)      error "unsupported OS: $(uname -s)" ;;
  esac
}

get_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    *) error "unsupported architecture: $(uname -m)" ;;
  esac
}

get_target() {
  arch="$(get_arch)"
  os="$(get_os)"
  target="${arch}-${os}"

  # Only these targets have published binaries.
  case "$target" in
    x86_64-unknown-linux-musl|aarch64-unknown-linux-musl|aarch64-apple-darwin) ;;
    x86_64-apple-darwin) error "macOS x86_64 is not supported; use Apple Silicon (aarch64) or Rosetta 2" ;;
    *) error "no prebuilt binary for $target" ;;
  esac

  echo "$target"
}

download() {
  url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    error "curl or wget is required"
  fi
}

verify_checksum() {
  archive="$1" checksums="$2" filename="$3"

  if command -v sha256sum >/dev/null 2>&1; then
    echo "$(grep "$filename" "$checksums" | awk '{print $1}')  $archive" | sha256sum -c --quiet 2>/dev/null
  elif command -v shasum >/dev/null 2>&1; then
    echo "$(grep "$filename" "$checksums" | awk '{print $1}')  $archive" | shasum -a 256 -c --quiet 2>/dev/null
  else
    info "warning: sha256sum/shasum not found, skipping checksum verification"
    return 0
  fi
}

main() {
  target="$(get_target)"
  filename="openshell-${target}.tar.gz"
  base_url="https://github.com/${REPO}/releases/download/${VERSION}"

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  info "downloading ${filename} (${VERSION})..."
  download "${base_url}/${filename}" "${tmpdir}/${filename}"

  info "verifying checksum..."
  download "${base_url}/openshell-checksums-sha256.txt" "${tmpdir}/checksums.txt"
  if ! verify_checksum "${tmpdir}/${filename}" "${tmpdir}/checksums.txt" "$filename"; then
    error "checksum verification failed"
  fi

  info "extracting..."
  tar -xzf "${tmpdir}/${filename}" -C "${tmpdir}"

  info "installing to ${INSTALL_DIR}/openshell..."
  if [ -w "$INSTALL_DIR" ]; then
    mv "${tmpdir}/openshell" "${INSTALL_DIR}/openshell"
  else
    sudo mv "${tmpdir}/openshell" "${INSTALL_DIR}/openshell"
  fi
  chmod +x "${INSTALL_DIR}/openshell"

  info "installed openshell $(${INSTALL_DIR}/openshell --version 2>/dev/null || echo "${VERSION}") to ${INSTALL_DIR}/openshell"
}

main
