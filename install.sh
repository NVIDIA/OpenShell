#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install the OpenShell CLI binary.
#
# Usage:
#   curl -LsSf https://raw.githubusercontent.com/linuxdevel/OpenShell/main/install.sh | sh
#
# Or run directly:
#   ./install.sh
#
# Environment variables:
#   OPENSHELL_VERSION     - Release tag to install (default: latest tagged release)
#   OPENSHELL_INSTALL_DIR - Directory to install into (default: ~/.local/bin)
#   OPENSHELL_RELEASE_REPO - GitHub release repo override (default: linuxdevel/OpenShell)
#   OPENSHELL_TOOL        - Optional setup selection hint (claude-code, opencode)
#   OPENSHELL_VENDOR      - Optional setup selection hint (anthropic, github-copilot)
#   OPENSHELL_MODEL_PATH  - Optional setup model path hint for later setup flow
#
set -eu

APP_NAME="openshell"
DEFAULT_RELEASE_REPO="linuxdevel/OpenShell"

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
# Usage
# ---------------------------------------------------------------------------

usage() {
  cat <<EOF
install.sh — Install the OpenShell CLI

USAGE:
    curl -LsSf https://raw.githubusercontent.com/linuxdevel/OpenShell/main/install.sh | sh
    ./install.sh [OPTIONS]

OPTIONS:
    --help                 Print this help message
    --tool <tool>          Validate later setup tool selection
    --vendor <vendor>      Validate later setup vendor selection
    --model-path <path>    Validate later setup model path selection

ENVIRONMENT VARIABLES:
    OPENSHELL_VERSION       Release tag to install (default: latest tagged release)
    OPENSHELL_INSTALL_DIR   Directory to install into (default: ~/.local/bin)
    OPENSHELL_RELEASE_REPO  GitHub release repo override (default: linuxdevel/OpenShell)
    OPENSHELL_TOOL          Optional setup selection hint (claude-code, opencode)
    OPENSHELL_VENDOR        Optional setup selection hint (anthropic, github-copilot)
    OPENSHELL_MODEL_PATH    Optional setup model path hint for later setup flow

EXAMPLES:
    # Install latest release
    curl -LsSf https://raw.githubusercontent.com/linuxdevel/OpenShell/main/install.sh | sh

    # Install a specific version
    curl -LsSf https://raw.githubusercontent.com/linuxdevel/OpenShell/main/install.sh | OPENSHELL_VERSION=v0.0.9 sh

    # Install to /usr/local/bin
    curl -LsSf https://raw.githubusercontent.com/linuxdevel/OpenShell/main/install.sh | OPENSHELL_INSTALL_DIR=/usr/local/bin sh

    # Install from a different fork release repo
    curl -LsSf https://raw.githubusercontent.com/linuxdevel/OpenShell/main/install.sh | OPENSHELL_RELEASE_REPO=example/custom-openshell sh

    # Validate later setup selections while installing the CLI
    ./install.sh --tool claude-code --vendor anthropic --model-path claude-sonnet-4
EOF
}

# ---------------------------------------------------------------------------
# HTTP helpers — prefer curl, fall back to wget
# ---------------------------------------------------------------------------

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

validate_choice() {
  _value="$1"
  _label="$2"
  shift 2

  [ -z "$_value" ] && return 0

  for _allowed in "$@"; do
    if [ "$_value" = "$_allowed" ]; then
      return 0
    fi
  done

  error "unsupported ${_label}: ${_value}"
}

validate_selection() {
  _tool="${OPENSHELL_TOOL:-}"
  _vendor="${OPENSHELL_VENDOR:-}"
  _model_path="${OPENSHELL_MODEL_PATH:-}"

  validate_choice "$_tool" "tool" "claude-code" "opencode"
  validate_choice "$_vendor" "vendor" "anthropic" "github-copilot"

  if [ -n "$_vendor" ] && [ -z "$_tool" ]; then
    error "OPENSHELL_VENDOR requires OPENSHELL_TOOL"
  fi

  if [ -n "$_model_path" ] && [ -z "$_vendor" ]; then
    error "OPENSHELL_MODEL_PATH requires OPENSHELL_VENDOR"
  fi

  case "${_tool}:${_vendor}" in
    ""|":")
      ;;
    "claude-code:"|"claude-code:anthropic")
      ;;
    "opencode:"|"opencode:github-copilot")
      ;;
    *)
      error "unsupported installer selection: ${_tool} + ${_vendor}"
      ;;
  esac
}

validate_release_repo() {
  _repo="${OPENSHELL_RELEASE_REPO:-$DEFAULT_RELEASE_REPO}"

  case "$_repo" in
    */*)
      _owner="${_repo%%/*}"
      _name="${_repo#*/}"
      ;;
    *)
      error "invalid OPENSHELL_RELEASE_REPO: ${_repo} (expected <owner>/<repo>)"
      ;;
  esac

  case "$_owner" in
    ""|*/*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-]*)
      error "invalid OPENSHELL_RELEASE_REPO: ${_repo} (expected <owner>/<repo>)"
      ;;
  esac

  case "$_name" in
    ""|*/*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-]*)
      error "invalid OPENSHELL_RELEASE_REPO: ${_repo} (expected <owner>/<repo>)"
      ;;
  esac

  printf '%s\n' "$_repo"
}

print_selection() {
  _printed=0

  if [ -n "${OPENSHELL_TOOL:-}" ]; then
    info "validated setup tool selection: ${OPENSHELL_TOOL}"
    _printed=1
  fi

  if [ -n "${OPENSHELL_VENDOR:-}" ]; then
    info "validated setup vendor selection: ${OPENSHELL_VENDOR}"
    _printed=1
  fi

  if [ -n "${OPENSHELL_MODEL_PATH:-}" ]; then
    info "validated setup model path selection: ${OPENSHELL_MODEL_PATH}"
    _printed=1
  fi

  if [ "$_printed" -eq 1 ]; then
    info "selection validation applies to later OpenShell setup and still installs the openshell CLI"
  fi

  return 0
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

# Download a URL to a file. Outputs nothing on success.
download() {
  _url="$1"
  _output="$2"

  if has_cmd curl; then
    curl -fLsS --retry 3 -o "$_output" "$_url"
  elif has_cmd wget; then
    wget -q --tries=3 -O "$_output" "$_url"
  fi
}

download_optional() {
  _url="$1"
  _output="$2"

  rm -f "$_output"

  if download "$_url" "$_output"; then
    return 0
  fi

  rm -f "$_output"
  return 1
}

# Follow a URL and print the final resolved URL (for detecting redirect targets).
resolve_redirect() {
  _url="$1"

  if has_cmd curl; then
    curl -fLsS -o /dev/null -w '%{url_effective}' "$_url"
  elif has_cmd wget; then
    # wget --spider follows redirects; capture the final Location from stderr
    wget --spider --max-redirect=10 "$_url" 2>&1 | sed -n 's/^.*Location: \([^ ]*\).*/\1/p' | tail -1
  fi
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

get_os() {
  case "$(uname -s)" in
    Darwin) echo "apple-darwin" ;;
    Linux)  echo "unknown-linux-musl" ;;
    *)      error "unsupported OS: $(uname -s)" ;;
  esac
}

get_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    *) error "unsupported architecture: $(uname -m)" ;;
  esac
}

get_target() {
  _arch="$(get_arch)"
  _os="$(get_os)"
  _target="${_arch}-${_os}"

  # Only these targets have published binaries.
  case "$_target" in
    x86_64-unknown-linux-musl|aarch64-unknown-linux-musl|aarch64-apple-darwin) ;;
    x86_64-apple-darwin) error "macOS x86_64 is not supported; use Apple Silicon (aarch64) or Rosetta 2" ;;
    *) error "no prebuilt binary for $_target" ;;
  esac

  echo "$_target"
}

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------

resolve_version() {
  _github_url="$1"

  if [ -n "${OPENSHELL_VERSION:-}" ]; then
    echo "$OPENSHELL_VERSION"
    return 0
  fi

  # Resolve "latest" by following the GitHub releases/latest redirect.
  # GitHub redirects /releases/latest -> /releases/tag/<tag>
  info "resolving latest version..."
  _latest_url="${_github_url}/releases/latest"
  _resolved="$(resolve_redirect "$_latest_url")" || error "failed to resolve latest release from ${_latest_url}"

  # Extract the tag from the resolved URL: .../releases/tag/v0.0.4 -> v0.0.4
  _version="${_resolved##*/}"

  if [ -z "$_version" ] || [ "$_version" = "latest" ]; then
    error "could not determine latest release version (resolved URL: ${_resolved})"
  fi

  echo "$_version"
}

# ---------------------------------------------------------------------------
# Checksum verification
# ---------------------------------------------------------------------------

verify_checksum() {
  _vc_archive="$1"
  _vc_checksums="$2"
  _vc_filename="$3"

  _vc_expected="$(grep "$_vc_filename" "$_vc_checksums" | awk '{print $1}')"

  if [ -z "$_vc_expected" ]; then
    error "missing checksum entry for $_vc_filename in ${_vc_checksums##*/}"
  fi

  if has_cmd shasum; then
    echo "$_vc_expected  $_vc_archive" | shasum -a 256 -c --quiet 2>/dev/null
  elif has_cmd sha256sum; then
    echo "$_vc_expected  $_vc_archive" | sha256sum -c --quiet 2>/dev/null
  else
    error "sha256sum/shasum not found, cannot verify release checksum"
  fi
}

# ---------------------------------------------------------------------------
# Install location
# ---------------------------------------------------------------------------

get_install_dir() {
  if [ -n "${OPENSHELL_INSTALL_DIR:-}" ]; then
    echo "$OPENSHELL_INSTALL_DIR"
  else
    echo "${HOME}/.local/bin"
  fi
}

# Check if a directory is already on PATH.
is_on_path() {
  _dir="$1"
  case ":${PATH}:" in
    *":${_dir}:"*) return 0 ;;
    *)             return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help)
        usage
        exit 0
        ;;
      --tool)
        [ "$#" -ge 2 ] || error "missing value for --tool"
        OPENSHELL_TOOL="$2"
        shift 2
        ;;
      --vendor)
        [ "$#" -ge 2 ] || error "missing value for --vendor"
        OPENSHELL_VENDOR="$2"
        shift 2
        ;;
      --model-path)
        [ "$#" -ge 2 ] || error "missing value for --model-path"
        OPENSHELL_MODEL_PATH="$2"
        shift 2
        ;;
      *)
        error "unknown option: $1"
        ;;
    esac
  done

  check_downloader
  validate_selection
  print_selection

  _release_repo="$(validate_release_repo)"
  _github_url="https://github.com/${_release_repo}"
  _version="$(resolve_version "$_github_url")"
  _target="$(get_target)"
  _filename="${APP_NAME}-${_target}.tar.gz"
  _checksums_filename="${APP_NAME}-checksums-sha256.txt"
  _checksums_path="${_tmpdir:-}/unused"
  _download_url="${_github_url}/releases/download/${_version}/${_filename}"
  _checksums_url="${_github_url}/releases/download/${_version}/${_checksums_filename}"
  _install_dir="$(get_install_dir)"

  info "downloading ${APP_NAME} ${_version} (${_target})..."

  _tmpdir="$(mktemp -d)"
  trap 'rm -rf "$_tmpdir"' EXIT
  _checksums_path="${_tmpdir}/${_checksums_filename}"

  if ! download "$_download_url" "${_tmpdir}/${_filename}"; then
    error "failed to download ${_download_url}"
  fi

  if ! download "$_checksums_url" "$_checksums_path"; then
    error "missing checksum manifest: ${_checksums_filename}"
  fi

  # Verify checksum
  info "verifying checksum..."
  if ! verify_checksum "${_tmpdir}/${_filename}" "$_checksums_path" "$_filename"; then
    error "checksum verification failed for ${_filename}"
  fi

  # Extract
  info "extracting..."
  tar -xzf "${_tmpdir}/${_filename}" -C "${_tmpdir}"

  # Install
  mkdir -p "$_install_dir" 2>/dev/null || true

  if [ -w "$_install_dir" ] || mkdir -p "$_install_dir" 2>/dev/null; then
    install -m 755 "${_tmpdir}/${APP_NAME}" "${_install_dir}/${APP_NAME}"
  else
    info "elevated permissions required to install to ${_install_dir}"
    sudo mkdir -p "$_install_dir"
    sudo install -m 755 "${_tmpdir}/${APP_NAME}" "${_install_dir}/${APP_NAME}"
  fi

  _installed_version="$("${_install_dir}/${APP_NAME}" --version 2>/dev/null || echo "${_version}")"
  info "installed ${_installed_version} to ${_install_dir}/${APP_NAME}"

  # If the install directory isn't on PATH, print instructions
  if ! is_on_path "$_install_dir"; then
    echo ""
    info "${_install_dir} is not on your PATH."
    info ""
    info "Add it by appending the following to your shell configuration file"
    info "(e.g. ~/.bashrc, ~/.zshrc, or ~/.config/fish/config.fish):"
    info ""

    _current_shell="$(basename "${SHELL:-sh}" 2>/dev/null || echo "sh")"
    case "$_current_shell" in
      fish)
        info "    fish_add_path ${_install_dir}"
        ;;
      *)
        info "    export PATH=\"${_install_dir}:\$PATH\""
        ;;
    esac

    info ""
    info "Then restart your shell or run the command above in your current session."
  fi
}

main "$@"
