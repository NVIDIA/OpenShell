#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install the OpenShell CLI binary.
#
# Usage:
#   curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
#
# Or run directly:
#   ./install.sh
#
# Environment variables:
#   OPENSHELL_VERSION     - Release tag to install (default: latest tagged release)
#   OPENSHELL_INSTALL_DIR - Directory to install into (default: ~/.local/bin)
#
# CLI flags:
#   --help            - Print usage information
#   --no-modify-path  - Skip PATH modification in shell profiles
#
set -eu

APP_NAME="openshell"
REPO="NVIDIA/OpenShell"
GITHUB_URL="https://github.com/${REPO}"
NO_MODIFY_PATH=0

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
    curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
    ./install.sh [OPTIONS]

OPTIONS:
    --no-modify-path    Don't add the install directory to PATH
    --help              Print this help message

ENVIRONMENT VARIABLES:
    OPENSHELL_VERSION       Release tag to install (default: latest tagged release)
    OPENSHELL_INSTALL_DIR   Directory to install into (default: ~/.local/bin)

EXAMPLES:
    # Install latest release
    curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh

    # Install a specific version
    OPENSHELL_VERSION=v0.0.4 curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh

    # Install to /usr/local/bin
    OPENSHELL_INSTALL_DIR=/usr/local/bin curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
EOF
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

# Follow a URL and print the final resolved URL (for detecting redirect targets).
resolve_redirect() {
  _url="$1"

  if has_cmd curl; then
    curl -fLsS -o /dev/null -w '%{url_effective}' "$_url"
  elif has_cmd wget; then
    # wget --spider follows redirects and prints the final URL
    wget --spider -q --max-redirect=10 "$_url" 2>&1 | grep -oP 'Location: \K\S+' | tail -1
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
  if [ -n "${OPENSHELL_VERSION:-}" ]; then
    echo "$OPENSHELL_VERSION"
    return 0
  fi

  # Resolve "latest" by following the GitHub releases/latest redirect.
  # GitHub redirects /releases/latest -> /releases/tag/<tag>
  info "resolving latest version..."
  _latest_url="${GITHUB_URL}/releases/latest"
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
  _archive="$1"
  _checksums="$2"
  _filename="$3"

  _expected="$(grep "$_filename" "$_checksums" | awk '{print $1}')"

  if [ -z "$_expected" ]; then
    warn "no checksum found for $_filename, skipping verification"
    return 0
  fi

  if has_cmd shasum; then
    echo "$_expected  $_archive" | shasum -a 256 -c --quiet 2>/dev/null
  elif has_cmd sha256sum; then
    echo "$_expected  $_archive" | sha256sum -c --quiet 2>/dev/null
  else
    warn "sha256sum/shasum not found, skipping checksum verification"
    return 0
  fi
}

# ---------------------------------------------------------------------------
# Install location and PATH management
# ---------------------------------------------------------------------------

get_home() {
  if [ -n "${HOME:-}" ]; then
    echo "$HOME"
  elif [ -n "${USER:-}" ]; then
    getent passwd "$USER" | cut -d: -f6
  else
    getent passwd "$(id -un)" | cut -d: -f6
  fi
}

get_default_install_dir() {
  if [ -n "${XDG_BIN_HOME:-}" ]; then
    echo "$XDG_BIN_HOME"
  else
    _home="$(get_home)"
    echo "${_home}/.local/bin"
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

# Write a small env script that conditionally prepends the install dir to PATH.
write_env_script_sh() {
  _install_dir_expr="$1"
  _env_script="$2"

  cat <<ENVEOF > "$_env_script"
#!/bin/sh
# Add OpenShell to PATH if not already present
case ":\${PATH}:" in
  *:"${_install_dir_expr}":*)
    ;;
  *)
    export PATH="${_install_dir_expr}:\$PATH"
    ;;
esac
ENVEOF
}

write_env_script_fish() {
  _install_dir_expr="$1"
  _env_script="$2"

  cat <<ENVEOF > "$_env_script"
# Add OpenShell to PATH if not already present
if not contains "${_install_dir_expr}" \$PATH
    set -gx PATH "${_install_dir_expr}" \$PATH
end
ENVEOF
}

# Add a `. /path/to/env` line to a shell rc file if not already present.
add_source_line() {
  _env_script_path="$1"
  _rcfile="$2"
  _shell_type="$3"

  if [ "$_shell_type" = "fish" ]; then
    _line="source \"${_env_script_path}\""
  else
    _line=". \"${_env_script_path}\""
  fi

  # Check if line already exists
  if [ -f "$_rcfile" ] && grep -qF "$_line" "$_rcfile" 2>/dev/null; then
    return 0
  fi

  # Append with a leading newline in case the file doesn't end with one
  printf '\n%s\n' "$_line" >> "$_rcfile"
  return 1
}

# Set up PATH modification in common shell rc files.
setup_path() {
  _install_dir="$1"
  _home="$(get_home)"
  _env_script="${_install_dir}/env"
  _fish_env_script="${_install_dir}/env.fish"
  _needs_source=0

  # Replace $HOME in the expression for late-bound references in rc files
  if [ -n "${HOME:-}" ]; then
    # shellcheck disable=SC2016
    _install_dir_expr='$HOME'"${_install_dir#"$_home"}"
  else
    _install_dir_expr="$_install_dir"
  fi

  # Write the env scripts
  write_env_script_sh "$_install_dir_expr" "$_env_script"
  write_env_script_fish "$_install_dir_expr" "$_fish_env_script"

  # POSIX shells: .profile, .bashrc, .bash_profile, .zshrc, .zshenv
  for _rcfile_rel in .profile .bashrc .bash_profile .zshrc .zshenv; do
    _rcdir="$_home"
    # zsh respects ZDOTDIR
    case "$_rcfile_rel" in
      .zsh*) _rcdir="${ZDOTDIR:-$_home}" ;;
    esac
    _rcfile="${_rcdir}/${_rcfile_rel}"
    if [ -f "$_rcfile" ]; then
      if ! add_source_line "$_env_script" "$_rcfile" "sh"; then
        _needs_source=1
      fi
    fi
  done

  # If none of the above existed, create .profile
  if [ "$_needs_source" = "0" ]; then
    _found_any=0
    for _rcfile_rel in .profile .bashrc .bash_profile .zshrc .zshenv; do
      if [ -f "${_home}/${_rcfile_rel}" ]; then
        _found_any=1
        break
      fi
    done
    if [ "$_found_any" = "0" ]; then
      if ! add_source_line "$_env_script" "${_home}/.profile" "sh"; then
        _needs_source=1
      fi
    fi
  fi

  # Fish shell
  _fish_conf_dir="${_home}/.config/fish/conf.d"
  if [ -d "${_home}/.config/fish" ]; then
    mkdir -p "$_fish_conf_dir"
    add_source_line "$_fish_env_script" "${_fish_conf_dir}/${APP_NAME}.env.fish" "fish" || true
  fi

  # GitHub Actions: write to GITHUB_PATH for CI environments
  if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$_install_dir" >> "$GITHUB_PATH"
  fi

  if [ "$_needs_source" = "1" ] || ! is_on_path "$_install_dir"; then
    echo ""
    info "to add ${APP_NAME} to your PATH, restart your shell or run:"
    info ""
    info "    source \"${_env_script}\"    (sh, bash, zsh)"
    if [ -d "${_home}/.config/fish" ]; then
      info "    source \"${_fish_env_script}\"    (fish)"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  # Parse CLI flags
  for arg in "$@"; do
    case "$arg" in
      --help)
        usage
        exit 0
        ;;
      --no-modify-path)
        NO_MODIFY_PATH=1
        ;;
      *)
        error "unknown option: $arg"
        ;;
    esac
  done

  check_downloader

  _version="$(resolve_version)"
  _target="$(get_target)"
  _filename="${APP_NAME}-${_target}.tar.gz"
  _download_url="${GITHUB_URL}/releases/download/${_version}/${_filename}"
  _checksums_url="${GITHUB_URL}/releases/download/${_version}/${APP_NAME}-checksums-sha256.txt"

  # Determine install directory
  _using_default_dir=0
  if [ -n "${OPENSHELL_INSTALL_DIR:-}" ]; then
    _install_dir="$OPENSHELL_INSTALL_DIR"
  else
    _install_dir="$(get_default_install_dir)"
    _using_default_dir=1
  fi

  info "downloading ${APP_NAME} ${_version} (${_target})..."

  _tmpdir="$(mktemp -d)"
  trap 'rm -rf "$_tmpdir"' EXIT

  if ! download "$_download_url" "${_tmpdir}/${_filename}"; then
    error "failed to download ${_download_url}"
  fi

  # Verify checksum
  info "verifying checksum..."
  if download "$_checksums_url" "${_tmpdir}/checksums.txt"; then
    if ! verify_checksum "${_tmpdir}/${_filename}" "${_tmpdir}/checksums.txt" "$_filename"; then
      error "checksum verification failed for ${_filename}"
    fi
  else
    warn "could not download checksums file, skipping verification"
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
  info "installed ${APP_NAME} ${_installed_version} to ${_install_dir}/${APP_NAME}"

  # Set up PATH for default install location
  if [ "$_using_default_dir" = "1" ] && [ "$NO_MODIFY_PATH" = "0" ]; then
    if ! is_on_path "$_install_dir"; then
      setup_path "$_install_dir"
    fi
  fi
}

main "$@"
