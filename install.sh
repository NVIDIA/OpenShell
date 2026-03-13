#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install the OpenShell CLI binary.
#
# Requires the GitHub CLI (gh) to be installed and authenticated, since this
# repository is internal and public HTTP download links are not available.
#
# Usage:
#   ./install.sh
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

verify_checksum() {
  archive="$1" checksums="$2" filename="$3"
  expected="$(grep "$filename" "$checksums" | awk '{print $1}')"

  if [ -z "$expected" ]; then
    info "warning: no checksum found for $filename, skipping verification"
    return 0
  fi

  # Prefer shasum (ships with macOS and most Linux); the macOS /sbin/sha256sum
  # does not support -c / stdin check mode.
  if command -v shasum >/dev/null 2>&1; then
    echo "$expected  $archive" | shasum -a 256 -c --quiet 2>/dev/null
  elif command -v sha256sum >/dev/null 2>&1; then
    echo "$expected  $archive" | sha256sum -c --quiet 2>/dev/null
  else
    info "warning: sha256sum/shasum not found, skipping checksum verification"
    return 0
  fi
}

main() {
  command -v gh >/dev/null 2>&1 || error "the GitHub CLI (gh) is required; install it from https://cli.github.com"

  target="$(get_target)"
  filename="openshell-${target}.tar.gz"

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  info "downloading ${filename} (${VERSION})..."
  gh release download "${VERSION}" \
    --repo "${REPO}" \
    --pattern "${filename}" \
    --output "${tmpdir}/${filename}"

  info "verifying checksum..."
  gh release download "${VERSION}" \
    --repo "${REPO}" \
    --pattern "openshell-checksums-sha256.txt" \
    --output "${tmpdir}/checksums.txt"
  if ! verify_checksum "${tmpdir}/${filename}" "${tmpdir}/checksums.txt" "$filename"; then
    error "checksum verification failed"
  fi

  info "extracting..."
  tar -xzf "${tmpdir}/${filename}" -C "${tmpdir}"

  info "installing to ${INSTALL_DIR}/openshell..."
  if [ -w "$INSTALL_DIR" ]; then
    install -m 755 "${tmpdir}/openshell" "${INSTALL_DIR}/openshell"
  else
    info "sudo access is required to install to ${INSTALL_DIR}"
    sudo install -m 755 "${tmpdir}/openshell" "${INSTALL_DIR}/openshell"
  fi

  info "installed openshell $(${INSTALL_DIR}/openshell --version 2>/dev/null || echo "${VERSION}") to ${INSTALL_DIR}/openshell"
}

main
