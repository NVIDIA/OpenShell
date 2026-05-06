#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install the OpenShell development build from a GitHub release.
#
# This script is intended as a convenient installer for development builds. It
# supports Debian packages on Linux amd64/arm64 and a manual per-user install
# on Apple Silicon macOS.
#
set -e

APP_NAME="openshell"
REPO="NVIDIA/OpenShell"
GITHUB_URL="https://github.com/${REPO}"
RELEASE_TAG="${OPENSHELL_VERSION:-dev}"
CHECKSUMS_NAME="openshell-checksums-sha256.txt"
GATEWAY_CHECKSUMS_NAME="openshell-gateway-checksums-sha256.txt"
CLI_BIN="openshell"
GATEWAY_BIN="openshell-gateway"
DRIVER_VM_BIN="openshell-driver-vm"
MACOS_LAUNCH_AGENT_LABEL="com.nvidia.openshell.gateway"
LOCAL_GATEWAY_PORT="17670"

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

usage() {
  cat <<EOF
install-dev.sh - Install the OpenShell development build

USAGE:
    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-dev.sh -o install-dev.sh
    sh install-dev.sh

    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install-dev.sh | sh

OPTIONS:
    --help       Print this help message

ENVIRONMENT VARIABLES:
    OPENSHELL_VERSION       Release tag to install (default: dev).
    OPENSHELL_INSTALL_DIR   macOS directory for openshell and openshell-gateway
                            (default: ~/.local/bin).
    OPENSHELL_DRIVER_DIR    macOS directory for openshell-driver-vm
                            (default: ~/.local/libexec/openshell).

NOTES:
    This installs the selected release from:
    ${GITHUB_URL}/releases/tag/${RELEASE_TAG}

    Linux installs the Debian package on amd64 and arm64.
    macOS installs a per-user Apple Silicon build from release tarballs and
    starts a LaunchAgent-backed local gateway.
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
  _tag="$1"
  _filename="$2"
  _output="$3"

  if curl -fLs --retry 3 --max-redirs 5 -o "$_output" \
    "${GITHUB_URL}/releases/download/${_tag}/${_filename}"; then
    return 0
  fi

  # GitHub normalizes `~` to `.` in release asset names, while the checksum file
  # still records the Debian package filename with `~dev` for correct version
  # ordering. Download the normalized asset but verify it against the checksum
  # entry for the original package filename.
  _normalized="$(printf '%s' "$_filename" | tr '~' '.')"
  if [ "$_normalized" != "$_filename" ]; then
    if download "${GITHUB_URL}/releases/download/${_tag}/${_normalized}" "$_output"; then
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

  if [ "$(uname -s)" = "Darwin" ] && has_cmd dscl; then
    _home="$(dscl . -read "/Users/${_user}" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')"
    if [ -n "$_home" ]; then
      echo "$_home"
      return 0
    fi
  fi

  if [ "$(id -un)" = "$_user" ]; then
    echo "${HOME:-}"
    return 0
  fi

  if [ "$(uname -s)" = "Darwin" ]; then
    echo "/Users/${_user}"
    return 0
  fi

  echo "/home/${_user}"
}

as_target_user() {
  if [ "${PLATFORM:-}" = "darwin" ]; then
    if [ "$(id -u)" -eq "$TARGET_UID" ]; then
      env HOME="$TARGET_HOME" "$@"
    elif has_cmd sudo; then
      sudo -u "$TARGET_USER" env HOME="$TARGET_HOME" "$@"
    else
      error "cannot run commands as ${TARGET_USER}; install sudo or run as ${TARGET_USER}"
    fi
    return
  fi

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

detect_platform() {
  case "$(uname -s)" in
    Linux)
      echo "linux"
      ;;
    Darwin)
      echo "darwin"
      ;;
    *)
      error "unsupported OS: $(uname -s); dev builds support Linux and macOS"
      ;;
  esac
}

check_linux_platform() {
  require_cmd dpkg
}

get_macos_target() {
  _arch="$(uname -m)"

  case "$_arch" in
    arm64|aarch64)
      echo "aarch64-apple-darwin"
      ;;
    x86_64|amd64)
      error "Intel macOS is not supported because no x86_64-apple-darwin dev assets are published"
      ;;
    *)
      error "no macOS dev build is published for architecture: ${_arch}"
      ;;
  esac
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

target_group() {
  id -gn "$TARGET_USER" 2>/dev/null || echo "$TARGET_USER"
}

is_target_home_path() {
  _path="$1"
  case "$_path" in
    "$TARGET_HOME"|"$TARGET_HOME"/*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

chown_to_target_user() {
  _path="$1"

  if [ "${TARGET_UID:-0}" = "0" ] || ! is_target_home_path "$_path"; then
    return 0
  fi

  if [ "$(id -u)" -eq "$TARGET_UID" ]; then
    return 0
  fi

  _owner="${TARGET_USER}:$(target_group)"
  if [ "$(id -u)" -eq 0 ]; then
    chown "$_owner" "$_path" 2>/dev/null || chown "$TARGET_USER" "$_path" 2>/dev/null || true
  elif has_cmd sudo; then
    sudo chown "$_owner" "$_path" 2>/dev/null || sudo chown "$TARGET_USER" "$_path" 2>/dev/null || true
  fi
}

ensure_dir() {
  _dir="$1"

  if mkdir -p "$_dir" 2>/dev/null; then
    :
  else
    as_root mkdir -p "$_dir"
  fi

  chown_to_target_user "$_dir"
}

install_executable() {
  _src="$1"
  _dst="$2"
  _dst_dir="$(dirname "$_dst")"

  if mkdir -p "$_dst_dir" 2>/dev/null && [ -w "$_dst_dir" ]; then
    install -m 0755 "$_src" "$_dst"
  else
    info "elevated permissions required to install to ${_dst_dir}"
    as_root mkdir -p "$_dst_dir"
    as_root install -m 0755 "$_src" "$_dst"
  fi

  chown_to_target_user "$_dst"
}

require_absolute_path() {
  _name="$1"
  _path="$2"

  case "$_path" in
    /*)
      ;;
    *)
      error "${_name} must be an absolute path on macOS; got ${_path}"
      ;;
  esac
}

macos_install_dir() {
  if [ -n "${OPENSHELL_INSTALL_DIR:-}" ]; then
    echo "$OPENSHELL_INSTALL_DIR"
  else
    echo "${TARGET_HOME}/.local/bin"
  fi
}

macos_driver_dir() {
  if [ -n "${OPENSHELL_DRIVER_DIR:-}" ]; then
    echo "$OPENSHELL_DRIVER_DIR"
  else
    echo "${TARGET_HOME}/.local/libexec/openshell"
  fi
}

install_release_binary() {
  _bin="$1"
  _tag="$2"
  _target="$3"
  _checksums_name="$4"
  _dest_dir="$5"
  _work_dir="$6"

  _filename="${_bin}-${_target}.tar.gz"
  _asset_path="${_work_dir}/${_filename}"
  _checksums_path="${_work_dir}/${_bin}-${_tag}-checksums.txt"
  _asset_url="${GITHUB_URL}/releases/download/${_tag}/${_filename}"
  _checksums_url="${GITHUB_URL}/releases/download/${_tag}/${_checksums_name}"

  info "downloading ${_filename}..."
  download_release_asset "$_tag" "$_filename" "$_asset_path" || {
    error "failed to download ${_asset_url}"
  }

  info "downloading ${_tag} release checksums for ${_bin}..."
  download "$_checksums_url" "$_checksums_path" || {
    error "failed to download ${_checksums_url}"
  }

  info "verifying ${_filename}..."
  verify_checksum "$_asset_path" "$_checksums_path" "$_filename"

  info "installing ${_bin}..."
  tar -xzf "$_asset_path" -C "$_work_dir" "$_bin"
  install_executable "${_work_dir}/${_bin}" "${_dest_dir}/${_bin}"
}

codesign_driver_vm() {
  _binary="$1"
  _work_dir="$2"

  if ! has_cmd codesign; then
    warn "codesign not found; ${DRIVER_VM_BIN} will fail without the Hypervisor entitlement"
    return 0
  fi

  info "codesigning ${DRIVER_VM_BIN} with Hypervisor entitlement..."
  _entitlements="${_work_dir}/entitlements.plist"
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

xml_escape() {
  printf '%s' "$1" | sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g' \
    -e 's/"/\&quot;/g'
}

write_macos_launch_agent() {
  _gateway_bin="$1"
  _driver_dir="$2"

  MACOS_GATEWAY_STATE_DIR="${TARGET_HOME}/.local/state/openshell/gateway"
  MACOS_VM_STATE_DIR="${TARGET_HOME}/.local/state/openshell/vm-driver"
  MACOS_LAUNCH_AGENT_DIR="${TARGET_HOME}/Library/LaunchAgents"
  MACOS_LAUNCH_AGENT_PLIST="${MACOS_LAUNCH_AGENT_DIR}/${MACOS_LAUNCH_AGENT_LABEL}.plist"

  ensure_dir "$MACOS_GATEWAY_STATE_DIR"
  ensure_dir "$MACOS_VM_STATE_DIR"
  ensure_dir "$MACOS_LAUNCH_AGENT_DIR"

  _gateway_bin_xml="$(xml_escape "$_gateway_bin")"
  _driver_dir_xml="$(xml_escape "$_driver_dir")"
  _db_url_xml="$(xml_escape "sqlite:${MACOS_GATEWAY_STATE_DIR}/openshell.db")"
  _vm_state_xml="$(xml_escape "$MACOS_VM_STATE_DIR")"
  _stdout_xml="$(xml_escape "${MACOS_GATEWAY_STATE_DIR}/openshell-gateway.out.log")"
  _stderr_xml="$(xml_escape "${MACOS_GATEWAY_STATE_DIR}/openshell-gateway.err.log")"

  cat > "$MACOS_LAUNCH_AGENT_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${MACOS_LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${_gateway_bin_xml}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>OPENSHELL_BIND_ADDRESS</key>
        <string>127.0.0.1</string>
        <key>OPENSHELL_SERVER_PORT</key>
        <string>${LOCAL_GATEWAY_PORT}</string>
        <key>OPENSHELL_DISABLE_TLS</key>
        <string>true</string>
        <key>OPENSHELL_DISABLE_GATEWAY_AUTH</key>
        <string>true</string>
        <key>OPENSHELL_DB_URL</key>
        <string>${_db_url_xml}</string>
        <key>OPENSHELL_DRIVERS</key>
        <string>vm</string>
        <key>OPENSHELL_GRPC_ENDPOINT</key>
        <string>http://127.0.0.1:${LOCAL_GATEWAY_PORT}</string>
        <key>OPENSHELL_SSH_GATEWAY_HOST</key>
        <string>127.0.0.1</string>
        <key>OPENSHELL_SSH_GATEWAY_PORT</key>
        <string>${LOCAL_GATEWAY_PORT}</string>
        <key>OPENSHELL_VM_DRIVER_STATE_DIR</key>
        <string>${_vm_state_xml}</string>
        <key>OPENSHELL_DRIVER_DIR</key>
        <string>${_driver_dir_xml}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>${_stdout_xml}</string>
    <key>StandardErrorPath</key>
    <string>${_stderr_xml}</string>
</dict>
</plist>
EOF

  chmod 0644 "$MACOS_LAUNCH_AGENT_PLIST"
  chown_to_target_user "$MACOS_LAUNCH_AGENT_PLIST"
}

print_macos_manual_commands() {
  _gateway_bin="$1"
  _cli_bin="$2"
  _driver_dir="$3"

  info "start the gateway manually with:"
  cat >&2 <<EOF
OPENSHELL_BIND_ADDRESS=127.0.0.1 \\
OPENSHELL_SERVER_PORT=${LOCAL_GATEWAY_PORT} \\
OPENSHELL_DISABLE_TLS=true \\
OPENSHELL_DISABLE_GATEWAY_AUTH=true \\
OPENSHELL_DB_URL='sqlite:${MACOS_GATEWAY_STATE_DIR}/openshell.db' \\
OPENSHELL_DRIVERS=vm \\
OPENSHELL_GRPC_ENDPOINT=http://127.0.0.1:${LOCAL_GATEWAY_PORT} \\
OPENSHELL_SSH_GATEWAY_HOST=127.0.0.1 \\
OPENSHELL_SSH_GATEWAY_PORT=${LOCAL_GATEWAY_PORT} \\
OPENSHELL_VM_DRIVER_STATE_DIR='${MACOS_VM_STATE_DIR}' \\
OPENSHELL_DRIVER_DIR='${_driver_dir}' \\
'${_gateway_bin}'
EOF
  info "then register it with:"
  info "'${_cli_bin}' gateway add http://127.0.0.1:${LOCAL_GATEWAY_PORT} --local --name local"
}

start_macos_gateway() {
  _gateway_bin="$1"
  _cli_bin="$2"
  _driver_dir="$3"
  _domain="gui/${TARGET_UID}"

  info "restarting ${MACOS_LAUNCH_AGENT_LABEL} LaunchAgent..."

  if ! has_cmd launchctl; then
    warn "launchctl not found; skipping automatic gateway start and registration"
    print_macos_manual_commands "$_gateway_bin" "$_cli_bin" "$_driver_dir"
    return 0
  fi

  launchctl bootout "$_domain" "$MACOS_LAUNCH_AGENT_PLIST" >/dev/null 2>&1 || true

  if launchctl bootstrap "$_domain" "$MACOS_LAUNCH_AGENT_PLIST" >/dev/null 2>&1; then
    if ! launchctl kickstart -k "${_domain}/${MACOS_LAUNCH_AGENT_LABEL}" >/dev/null 2>&1; then
      warn "launchctl kickstart failed; skipping automatic gateway registration"
      print_macos_manual_commands "$_gateway_bin" "$_cli_bin" "$_driver_dir"
      return 0
    fi
  elif launchctl load -w "$MACOS_LAUNCH_AGENT_PLIST" >/dev/null 2>&1; then
    :
  else
    warn "launchctl could not load ${MACOS_LAUNCH_AGENT_PLIST}; skipping automatic gateway registration"
    print_macos_manual_commands "$_gateway_bin" "$_cli_bin" "$_driver_dir"
    return 0
  fi

  if ! launchctl print "${_domain}/${MACOS_LAUNCH_AGENT_LABEL}" >/dev/null 2>&1; then
    warn "LaunchAgent did not appear in launchd; skipping automatic gateway registration"
    print_macos_manual_commands "$_gateway_bin" "$_cli_bin" "$_driver_dir"
    return 0
  fi

  info "registering local gateway as ${TARGET_USER}..."
  OPENSHELL_REGISTER_BIN="$_cli_bin"
  register_local_gateway
}

start_user_gateway() {
  info "restarting openshell-gateway user service as ${TARGET_USER}..."

  if ! as_target_user systemctl --user daemon-reload; then
    info "could not reach the user systemd manager for ${TARGET_USER}"
    info "restart the gateway later with: systemctl --user enable openshell-gateway && systemctl --user restart openshell-gateway"
    info "then register it with: openshell gateway add http://127.0.0.1:17670 --local --name local"
    return 0
  fi

  as_target_user systemctl --user enable openshell-gateway
  as_target_user systemctl --user restart openshell-gateway
  as_target_user systemctl --user is-active --quiet openshell-gateway

  info "registering local gateway as ${TARGET_USER}..."
  register_local_gateway
}

remove_local_gateway_registration() {
  [ -n "$TARGET_HOME" ] || error "cannot resolve home directory for ${TARGET_USER}"
  _config_dir="${TARGET_HOME}/.config/openshell"

  # The install-dev gateway is a user service. Replace the CLI registration
  # directly instead of asking `gateway destroy` to tear down Docker resources.
  # shellcheck disable=SC2016
  as_target_user sh -c '
    config_dir=$1
    rm -rf "${config_dir}/gateways/local"
    active="${config_dir}/active_gateway"
    if [ "$(cat "$active" 2>/dev/null || true)" = "local" ]; then
      rm -f "$active"
    fi
  ' sh "$_config_dir"
}

register_local_gateway() {
  _register_bin="${OPENSHELL_REGISTER_BIN:-openshell}"

  if _add_output="$(as_target_user "$_register_bin" gateway add "http://127.0.0.1:${LOCAL_GATEWAY_PORT}" --local --name local 2>&1)"; then
    [ -z "$_add_output" ] || printf '%s\n' "$_add_output" >&2
    return 0
  else
    _add_status=$?
  fi

  case "$_add_output" in
    *"already exists"*)
      info "local gateway already exists; removing and re-adding it..."
      remove_local_gateway_registration
      as_target_user "$_register_bin" gateway add "http://127.0.0.1:${LOCAL_GATEWAY_PORT}" --local --name local
      ;;
    *)
      printf '%s\n' "$_add_output" >&2
      return "$_add_status"
      ;;
  esac
}

install_linux_deb() {
  check_linux_platform

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
  download_release_asset "$RELEASE_TAG" "$_deb_file" "$_deb_path" || {
    error "failed to download ${_deb_url}"
  }
  chmod 0644 "$_deb_path"

  info "verifying checksum..."
  verify_checksum "$_deb_path" "${_tmpdir}/${CHECKSUMS_NAME}" "$_deb_file"

  info "installing ${_deb_file}..."
  install_deb_package "$_deb_path"
  info "installed ${APP_NAME} package from ${RELEASE_TAG}"
  start_user_gateway
}

install_macos_tarballs() {
  require_cmd tar
  require_cmd install

  _target="$(get_macos_target)"
  _install_dir="$(macos_install_dir)"
  _driver_dir="$(macos_driver_dir)"
  require_absolute_path "OPENSHELL_INSTALL_DIR" "$_install_dir"
  require_absolute_path "OPENSHELL_DRIVER_DIR" "$_driver_dir"

  _tmpdir="$(mktemp -d)"
  chmod 0755 "$_tmpdir"
  trap 'rm -rf "$_tmpdir"' EXIT

  install_release_binary \
    "$CLI_BIN" \
    "$RELEASE_TAG" \
    "$_target" \
    "$CHECKSUMS_NAME" \
    "$_install_dir" \
    "$_tmpdir"

  install_release_binary \
    "$GATEWAY_BIN" \
    "$RELEASE_TAG" \
    "$_target" \
    "$GATEWAY_CHECKSUMS_NAME" \
    "$_install_dir" \
    "$_tmpdir"

  install_release_binary \
    "$DRIVER_VM_BIN" \
    "$RELEASE_TAG" \
    "$_target" \
    "$CHECKSUMS_NAME" \
    "$_driver_dir" \
    "$_tmpdir"

  codesign_driver_vm "${_driver_dir}/${DRIVER_VM_BIN}" "$_tmpdir"
  write_macos_launch_agent "${_install_dir}/${GATEWAY_BIN}" "$_driver_dir"

  info "installed ${CLI_BIN} to ${_install_dir}/${CLI_BIN}"
  info "installed ${GATEWAY_BIN} to ${_install_dir}/${GATEWAY_BIN}"
  info "installed ${DRIVER_VM_BIN} to ${_driver_dir}/${DRIVER_VM_BIN}"
  info "installed LaunchAgent to ${MACOS_LAUNCH_AGENT_PLIST}"

  start_macos_gateway "${_install_dir}/${GATEWAY_BIN}" "${_install_dir}/${CLI_BIN}" "$_driver_dir"
}

main() {
  if [ "$#" -gt 0 ]; then
    case "$1" in
      --help)
        usage
        exit 0
        ;;
      *)
        error "unknown option: $1"
        ;;
    esac
  fi

  require_cmd curl
  PLATFORM="$(detect_platform)"

  TARGET_USER="$(target_user)"
  TARGET_UID="$(id -u "$TARGET_USER" 2>/dev/null || true)"
  [ -n "$TARGET_UID" ] || error "cannot resolve uid for ${TARGET_USER}"
  TARGET_HOME="$(user_home "$TARGET_USER")"

  case "$PLATFORM" in
    linux)
      install_linux_deb
      ;;
    darwin)
      install_macos_tarballs
      ;;
    *)
      error "unsupported platform: ${PLATFORM}"
      ;;
  esac
}

main "$@"
