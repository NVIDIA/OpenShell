#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install OpenShell from a GitHub release.
#
# Linux installs either the Debian or RPM packages from the selected release.
# Apple Silicon macOS installs the generated Homebrew formula, so Homebrew owns
# the binary layout and launchd service lifecycle.
#
set -e

APP_NAME="openshell"
REPO="NVIDIA/OpenShell"
GITHUB_URL="https://github.com/${REPO}"
RELEASE_TAG="${OPENSHELL_VERSION:-}"
CHECKSUMS_NAME="openshell-checksums-sha256.txt"
LOCAL_GATEWAY_PORT="17670"
HOMEBREW_TAP="nvidia/openshell"
HOMEBREW_FORMULA_NAME="openshell"
BREAKING_RELEASE_VERSION="0.0.37"
UPGRADE_NOTICE_ACK="${OPENSHELL_ACK_BREAKING_UPGRADE:-}"

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
install.sh - Install OpenShell

USAGE:
    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh -o install.sh
    sh install.sh

    curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh

OPTIONS:
    --help       Print this help message

ENVIRONMENT VARIABLES:
    OPENSHELL_VERSION   Release tag to install (default: latest tagged release).
                        Set OPENSHELL_VERSION=dev to install the rolling dev build.
    OPENSHELL_ACK_BREAKING_UPGRADE
                        Set to 1 only after backing up and cleaning up a
                        pre-v0.0.37 installation.

NOTES:
    When OPENSHELL_VERSION is unset, this resolves the latest tagged release
    from ${GITHUB_URL}/releases/latest.

    Linux installs the Debian package on amd64/arm64 or the RPM packages on
    x86_64/aarch64, depending on the host package manager.
    macOS installs the release Homebrew formula on Apple Silicon and starts a
    brew services-backed local gateway.
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

semver_core() {
  _version="${1#v}"
  _version="${_version%%[-+]*}"
  printf '%s\n' "$_version"
}

semver_at_least() {
  _version="$(semver_core "$1")"
  _minimum="$(semver_core "$2")"

  _major="${_version%%.*}"
  _rest="${_version#*.}"
  [ "$_rest" != "$_version" ] || return 1
  _minor="${_rest%%.*}"
  _patch="${_rest#*.}"
  _patch="${_patch%%.*}"

  _min_major="${_minimum%%.*}"
  _min_rest="${_minimum#*.}"
  [ "$_min_rest" != "$_minimum" ] || return 1
  _min_minor="${_min_rest%%.*}"
  _min_patch="${_min_rest#*.}"
  _min_patch="${_min_patch%%.*}"

  case "$_major:$_minor:$_patch:$_min_major:$_min_minor:$_min_patch" in
    *[!0-9:]* | *::*)
      return 1
      ;;
  esac

  [ "$_major" -gt "$_min_major" ] && return 0
  [ "$_major" -lt "$_min_major" ] && return 1
  [ "$_minor" -gt "$_min_minor" ] && return 0
  [ "$_minor" -lt "$_min_minor" ] && return 1
  [ "$_patch" -ge "$_min_patch" ]
}

target_uses_breaking_gateway_model() {
  case "$RELEASE_TAG" in
    dev)
      return 0
      ;;
  esac

  semver_at_least "$RELEASE_TAG" "$BREAKING_RELEASE_VERSION"
}

installed_version_needs_breaking_upgrade_notice() {
  _version="$1"

  if [ -z "$_version" ]; then
    return 0
  fi

  ! semver_at_least "$_version" "$BREAKING_RELEASE_VERSION"
}

find_existing_openshell_bin() {
  _path="$(command -v openshell 2>/dev/null || true)"
  if [ -n "$_path" ] && [ -x "$_path" ]; then
    printf '%s\n' "$_path"
    return 0
  fi

  for _candidate in \
    "${TARGET_HOME:-}/.local/bin/openshell" \
    /usr/local/bin/openshell \
    /usr/bin/openshell \
    /opt/homebrew/bin/openshell; do
    if [ -n "$_candidate" ] && [ -x "$_candidate" ]; then
      printf '%s\n' "$_candidate"
      return 0
    fi
  done

  return 1
}

existing_openshell_version() {
  _bin="$1"
  _output="$("$_bin" --version 2>/dev/null | sed -n '1p' || true)"
  printf '%s\n' "$_output" | awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^v?[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.+~-]+)?$/) {
          print $i
          exit
        }
      }
    }
  '
}

print_breaking_upgrade_notice() {
  _bin="$1"
  _version="$2"

  if [ -n "$_version" ]; then
    warn "detected existing OpenShell ${_version} at ${_bin}"
  else
    warn "detected an existing OpenShell installation at ${_bin}"
  fi

  cat >&2 <<EOF

OpenShell ${BREAKING_RELEASE_VERSION} and later are incompatible with gateway
state created by earlier releases. Before installing ${RELEASE_TAG}, back up
any files, artifacts, and configuration you need from existing sandboxes.

Then clean up the old runtime with the currently installed CLI:

    openshell sandbox delete --all
    openshell gateway destroy

Run these commands before upgrading because 'openshell gateway destroy' is not
available in OpenShell ${BREAKING_RELEASE_VERSION} and later.

After cleanup, rerun this installer or follow the installation guide:

    https://docs.nvidia.com/openshell/latest/about/installation

If you have already backed up and cleaned up the old runtime, rerun with:

    curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | OPENSHELL_ACK_BREAKING_UPGRADE=1 sh

EOF
}

guard_breaking_upgrade() {
  target_uses_breaking_gateway_model || return 0

  _bin="$(find_existing_openshell_bin || true)"
  [ -n "$_bin" ] || return 0

  _version="$(existing_openshell_version "$_bin")"
  installed_version_needs_breaking_upgrade_notice "$_version" || return 0

  print_breaking_upgrade_notice "$_bin" "$_version"

  if [ "$UPGRADE_NOTICE_ACK" = "1" ]; then
    warn "continuing because OPENSHELL_ACK_BREAKING_UPGRADE=1 is set"
    return 0
  fi

  error "manual cleanup is required before upgrading from this OpenShell installation"
}

resolve_release_tag() {
  if [ -n "${OPENSHELL_VERSION:-}" ]; then
    echo "$OPENSHELL_VERSION"
    return 0
  fi

  info "resolving latest version..."
  _latest_url="${GITHUB_URL}/releases/latest"
  _resolved="$(curl -fLsS -o /dev/null -w '%{url_effective}' "$_latest_url")" || {
    error "failed to resolve latest release from ${_latest_url}"
  }

  case "$_resolved" in
    https://github.com/${REPO}/releases/*)
      ;;
    *)
      error "unexpected redirect target: ${_resolved} (expected https://github.com/${REPO}/releases/...)"
      ;;
  esac

  _version="${_resolved##*/}"
  if [ -z "$_version" ] || [ "$_version" = "latest" ]; then
    error "could not determine latest release version (resolved URL: ${_resolved})"
  fi

  echo "$_version"
}

download_release_asset() {
  _tag="$1"
  _filename="$2"
  _output="$3"

  if curl -fLs --retry 3 --max-redirs 5 -o "$_output" \
    "${GITHUB_URL}/releases/download/${_tag}/${_filename}"; then
    return 0
  fi

  # GitHub normalizes `~` to `.` in release asset names, while checksum files
  # can still record package filenames with `~dev` for correct version ordering.
  # Download the normalized asset but verify it against the checksum entry for
  # the original package filename.
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
      error "unsupported OS: $(uname -s); this installer supports Linux and macOS"
      ;;
  esac
}

linux_package_method() {
  if has_cmd dpkg; then
    echo "deb"
  elif has_cmd rpm; then
    echo "rpm"
  else
    error "Linux installs require either dpkg or rpm"
  fi
}

set_linux_target_runtime_dir() {
  if [ "$(id -u)" -eq "$TARGET_UID" ] && [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    TARGET_RUNTIME_DIR="$XDG_RUNTIME_DIR"
  else
    TARGET_RUNTIME_DIR="/run/user/${TARGET_UID}"
  fi
}

check_linux_deb_platform() {
  require_cmd dpkg
}

check_macos_platform() {
  _arch="$(uname -m)"

  case "$_arch" in
    arm64|aarch64)
      ;;
    x86_64|amd64)
      error "Intel macOS is not supported because no x86_64-apple-darwin release assets are published"
      ;;
    *)
      error "no macOS release build is published for architecture: ${_arch}"
      ;;
  esac

  if ! as_target_user brew --version >/dev/null 2>&1; then
    error "Homebrew is required for macOS installs; install it from https://brew.sh"
  fi
}

get_deb_arch() {
  _arch="$(dpkg --print-architecture)"

  case "$_arch" in
    amd64|arm64)
      echo "$_arch"
      ;;
    *)
      error "no Debian package is published for architecture: ${_arch}"
      ;;
  esac
}

get_rpm_arch() {
  if has_cmd rpm; then
    _arch="$(rpm --eval '%{_arch}' 2>/dev/null || true)"
  else
    _arch=""
  fi

  if [ -z "$_arch" ]; then
    _arch="$(uname -m)"
  fi

  case "$_arch" in
    x86_64|amd64)
      echo "x86_64"
      ;;
    aarch64|arm64)
      echo "aarch64"
      ;;
    *)
      error "no RPM package is published for architecture: ${_arch}"
      ;;
  esac
}

find_deb_asset() {
  _checksums="$1"
  _arch="$2"

  awk -v arch="$_arch" '
    $2 ~ "^\\*?openshell[-_].*[-_]" arch "\\.deb$" {
      sub("^\\*", "", $2)
      print $2
      exit
    }
  ' "$_checksums"
}

find_rpm_asset() {
  _checksums="$1"
  _arch="$2"
  _package="$3"

  case "$_package" in
    openshell)
      _dev_name="openshell-dev-${_arch}.rpm"
      _fallback_re="^openshell-[0-9].*\\.${_arch}\\.rpm$"
      ;;
    openshell-gateway)
      _dev_name="openshell-gateway-dev-${_arch}.rpm"
      _fallback_re="^openshell-gateway-[0-9].*\\.${_arch}\\.rpm$"
      ;;
    *)
      error "unknown RPM package selector: ${_package}"
      ;;
  esac

  awk -v dev_name="$_dev_name" -v fallback_re="$_fallback_re" '
    {
      name = $2
      sub("^\\*", "", name)

      if (name == dev_name) {
        selected = name
        found = 1
        exit
      }

      if (fallback == "" && name ~ fallback_re) {
        fallback = name
      }
    }
    END {
      if (found) {
        print selected
      } else if (fallback != "") {
        print fallback
      }
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

install_rpm_packages() {
  if has_cmd dnf; then
    as_root dnf install -y "$@"
  elif has_cmd yum; then
    as_root yum install -y "$@"
  elif has_cmd zypper; then
    as_root zypper --non-interactive install --allow-unsigned-rpm "$@"
  elif has_cmd rpm; then
    warn "installing with rpm directly; dependencies must already be installed"
    as_root rpm -Uvh --replacepkgs "$@"
  else
    error "'dnf', 'yum', 'zypper', or 'rpm' is required to install RPM packages"
  fi
}

homebrew_formula_path() {
  _tap="$1"
  _formula="$2"

  if ! as_target_user brew tap-info "$_tap" >/dev/null 2>&1; then
    info "creating local Homebrew tap ${_tap}..."
    as_target_user brew tap-new --no-git "$_tap" >/dev/null
  fi

  _tap_dir="$(as_target_user brew --repository "$_tap" 2>/dev/null || true)"
  [ -n "$_tap_dir" ] || error "could not locate Homebrew tap ${_tap}"

  _formula_dir="${_tap_dir}/Formula"
  as_target_user mkdir -p "$_formula_dir"
  printf '%s/%s.rb\n' "$_formula_dir" "$_formula"
}

patch_homebrew_formula() {
  _formula_file="$1"
  _patched_file="${_formula_file}.patched"

  if grep -q 'entitlements.write <<~XML' "$_formula_file"; then
    info "patching Homebrew formula for idempotent postinstall..."
    sed 's/entitlements\.write <<~XML/entitlements.atomic_write <<~XML/' "$_formula_file" >"$_patched_file"
    mv "$_patched_file" "$_formula_file"
  fi

}

start_user_gateway() {
  info "restarting openshell-gateway user service as ${TARGET_USER}..."

  if ! as_target_user systemctl --user daemon-reload; then
    info "could not reach the user systemd manager for ${TARGET_USER}"
    info "restart the gateway later with: systemctl --user enable openshell-gateway && systemctl --user restart openshell-gateway"
    info "then register it with: openshell gateway add https://127.0.0.1:17670 --local --name openshell"
    return 0
  fi

  as_target_user systemctl --user enable openshell-gateway
  as_target_user systemctl --user restart openshell-gateway
  as_target_user systemctl --user is-active --quiet openshell-gateway

  info "registering local gateway as ${TARGET_USER}..."
  register_local_gateway
  wait_for_local_gateway_listener
  wait_for_local_gateway_status
}

dump_local_gateway_diagnostics() {
  _lines="${OPENSHELL_INSTALL_LOG_LINES:-80}"
  case "$_lines" in
    "" | *[!0-9]*)
      _lines=80
      ;;
  esac

  info "dumping recent local gateway diagnostics..."
  case "${PLATFORM:-}" in
    darwin)
      dump_homebrew_gateway_diagnostics "$_lines"
      ;;
    linux)
      dump_user_service_gateway_diagnostics "$_lines"
      ;;
    *)
      info "no gateway log collector is available for platform: ${PLATFORM:-unknown}"
      ;;
  esac
}

dump_homebrew_gateway_diagnostics() {
  _lines="$1"
  _brew_prefix="$(as_target_user brew --prefix 2>/dev/null || true)"
  [ -n "$_brew_prefix" ] || _brew_prefix="/opt/homebrew"

  info "Homebrew service status:"
  as_target_user brew services info "${HOMEBREW_TAP}/${HOMEBREW_FORMULA_NAME}" >&2 || true

  for _log_file in \
    "${_brew_prefix}/var/log/openshell/openshell-gateway.err.log" \
    "${_brew_prefix}/var/log/openshell/openshell-gateway.out.log"; do
    if [ -f "$_log_file" ]; then
      info "last ${_lines} lines from ${_log_file}:"
      tail -n "$_lines" "$_log_file" >&2 || true
    else
      info "gateway log not found: ${_log_file}"
    fi
  done
}

dump_user_service_gateway_diagnostics() {
  _lines="$1"

  if has_cmd systemctl; then
    info "openshell-gateway user service status:"
    as_target_user systemctl --user status openshell-gateway --no-pager >&2 || true
  fi

  if has_cmd journalctl; then
    info "last ${_lines} lines from openshell-gateway user journal:"
    as_target_user journalctl --user -u openshell-gateway --no-pager -n "$_lines" >&2 || true
  else
    info "journalctl not found; cannot dump openshell-gateway user journal"
  fi
}

wait_for_local_gateway_listener() {
  _timeout="${OPENSHELL_INSTALL_GATEWAY_TIMEOUT:-30}"
  _elapsed=0
  _last_output=""
  _probe_url="https://127.0.0.1:${LOCAL_GATEWAY_PORT}/"
  _mtls_dir="${TARGET_HOME}/.config/openshell/gateways/openshell/mtls"

  info "waiting for local gateway listener to become reachable..."
  while [ "$_elapsed" -lt "$_timeout" ]; do
    if [ ! -f "${_mtls_dir}/ca.crt" ] || [ ! -f "${_mtls_dir}/tls.crt" ] || [ ! -f "${_mtls_dir}/tls.key" ]; then
      _last_output="mTLS client bundle is not ready under ${_mtls_dir}"
    elif _last_output="$(as_target_user curl -sS --max-time 2 --cacert "${_mtls_dir}/ca.crt" --cert "${_mtls_dir}/tls.crt" --key "${_mtls_dir}/tls.key" -o /dev/null "$_probe_url" 2>&1)"; then
      info "local gateway listener is reachable"
      return 0
    fi
    sleep 1
    _elapsed=$((_elapsed + 1))
  done

  [ -z "$_last_output" ] || printf '%s\n' "$_last_output" >&2
  dump_local_gateway_diagnostics
  error "local gateway listener did not become reachable at ${_probe_url} within ${_timeout}s"
}

wait_for_local_gateway_status() {
  _timeout="${OPENSHELL_INSTALL_GATEWAY_TIMEOUT:-30}"
  _elapsed=0
  _status_output=""
  _register_bin="${OPENSHELL_REGISTER_BIN:-openshell}"

  info "waiting for openshell status to report connected..."
  while [ "$_elapsed" -lt "$_timeout" ]; do
    if _status_output="$(as_target_user env NO_COLOR=1 "$_register_bin" status 2>&1)"; then
      case "$_status_output" in
        *"Version:"*)
          info "openshell status reports connected"
          return 0
          ;;
      esac
    fi
    sleep 1
    _elapsed=$((_elapsed + 1))
  done

  [ -z "$_status_output" ] || printf '%s\n' "$_status_output" >&2
  dump_local_gateway_diagnostics
  error "openshell status did not report connected within ${_timeout}s"
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
    mkdir -p "${config_dir}/gateways/openshell"
    rm -f \
      "${config_dir}/gateways/openshell/metadata.json" \
      "${config_dir}/gateways/openshell/edge_token" \
      "${config_dir}/gateways/openshell/cf_token" \
      "${config_dir}/gateways/openshell/oidc_token.json"
    active="${config_dir}/active_gateway"
    active_name="$(cat "$active" 2>/dev/null || true)"
    if [ "$active_name" = "local" ] || [ "$active_name" = "openshell" ]; then
      rm -f "$active"
    fi
  ' sh "$_config_dir"
}

register_local_gateway() {
  _register_bin="${OPENSHELL_REGISTER_BIN:-openshell}"

  if _add_output="$(as_target_user "$_register_bin" gateway add "https://127.0.0.1:${LOCAL_GATEWAY_PORT}" --local --name openshell 2>&1)"; then
    [ -z "$_add_output" ] || print_gateway_add_output "$_add_output"
    return 0
  else
    _add_status=$?
  fi

  case "$_add_output" in
    *"already exists"*)
      info "local gateway already exists; removing and re-adding it..."
      remove_local_gateway_registration
      as_target_user "$_register_bin" gateway add "https://127.0.0.1:${LOCAL_GATEWAY_PORT}" --local --name openshell
      ;;
    *)
      printf '%s\n' "$_add_output" >&2
      return "$_add_status"
      ;;
  esac
}

print_gateway_add_output() {
  printf '%s\n' "$1" | while IFS= read -r _line; do
    case "$_line" in
      *"Gateway is not reachable at https://127.0.0.1:${LOCAL_GATEWAY_PORT}"*) ;;
      *"Verify the gateway is running and the endpoint is correct."*) ;;
      *) printf '%s\n' "$_line" >&2 ;;
    esac
  done
}

install_linux_deb() {
  check_linux_deb_platform
  set_linux_target_runtime_dir

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
    error "no Debian package found for architecture: ${_arch}"
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

install_linux_rpm() {
  require_cmd rpm
  set_linux_target_runtime_dir

  _arch="$(get_rpm_arch)"
  _tmpdir="$(mktemp -d)"
  chmod 0755 "$_tmpdir"
  trap 'rm -rf "$_tmpdir"' EXIT

  _checksums_url="${GITHUB_URL}/releases/download/${RELEASE_TAG}/${CHECKSUMS_NAME}"
  info "downloading ${RELEASE_TAG} release checksums..."
  download "$_checksums_url" "${_tmpdir}/${CHECKSUMS_NAME}" || {
    error "failed to download ${_checksums_url}"
  }

  _rpm_file="$(find_rpm_asset "${_tmpdir}/${CHECKSUMS_NAME}" "$_arch" openshell)"
  if [ -z "$_rpm_file" ]; then
    error "no openshell RPM package found for architecture: ${_arch}"
  fi

  _gateway_rpm_file="$(find_rpm_asset "${_tmpdir}/${CHECKSUMS_NAME}" "$_arch" openshell-gateway)"
  if [ -z "$_gateway_rpm_file" ]; then
    error "no openshell-gateway RPM package found for architecture: ${_arch}"
  fi

  info "selected ${_rpm_file} and ${_gateway_rpm_file}"

  for _package_file in "$_rpm_file" "$_gateway_rpm_file"; do
    _package_url="${GITHUB_URL}/releases/download/${RELEASE_TAG}/${_package_file}"
    _package_path="${_tmpdir}/${_package_file}"

    info "downloading ${_package_file}..."
    download_release_asset "$RELEASE_TAG" "$_package_file" "$_package_path" || {
      error "failed to download ${_package_url}"
    }
    chmod 0644 "$_package_path"

    info "verifying checksum for ${_package_file}..."
    verify_checksum "$_package_path" "${_tmpdir}/${CHECKSUMS_NAME}" "$_package_file"
  done

  info "installing ${_rpm_file} and ${_gateway_rpm_file}..."
  install_rpm_packages "${_tmpdir}/${_rpm_file}" "${_tmpdir}/${_gateway_rpm_file}"
  info "installed ${APP_NAME} RPM packages from ${RELEASE_TAG}"
  start_user_gateway
}

install_macos_homebrew() {
  check_macos_platform

  _tmpdir="$(mktemp -d)"
  chmod 0755 "$_tmpdir"
  trap 'rm -rf "$_tmpdir"' EXIT

  _formula_file="${_tmpdir}/openshell.rb"
  _formula_url="${GITHUB_URL}/releases/download/${RELEASE_TAG}/openshell.rb"

  info "downloading Homebrew formula from ${_formula_url}..."
  download_release_asset "$RELEASE_TAG" "openshell.rb" "$_formula_file" || {
    error "failed to download ${_formula_url}; the selected release may not include a Homebrew formula"
  }
  chmod 0644 "$_formula_file"
  patch_homebrew_formula "$_formula_file"

  _tap_formula_file="$(homebrew_formula_path "$HOMEBREW_TAP" "$HOMEBREW_FORMULA_NAME")"
  info "staging Homebrew formula in tap ${HOMEBREW_TAP}..."
  cp "$_formula_file" "$_tap_formula_file"
  chmod 0644 "$_tap_formula_file"
  if [ "$(id -u)" -eq 0 ]; then
    chown "$TARGET_USER" "$_tap_formula_file" 2>/dev/null || true
  fi

  _formula_ref="${HOMEBREW_TAP}/${HOMEBREW_FORMULA_NAME}"

  if as_target_user brew list --formula openshell >/dev/null 2>&1; then
    info "reinstalling OpenShell with Homebrew..."
    as_target_user brew reinstall --formula "$_formula_ref"
  else
    info "installing OpenShell with Homebrew..."
    as_target_user brew install --formula "$_formula_ref"
  fi

  info "restarting OpenShell Homebrew service..."
  if ! as_target_user brew services restart "$_formula_ref"; then
    warn "could not restart the OpenShell Homebrew service"
    info "restart it later with: brew services restart ${_formula_ref}"
    info "then register it with: openshell gateway add https://127.0.0.1:${LOCAL_GATEWAY_PORT} --local --name openshell"
    return 0
  fi

  _brew_prefix="$(as_target_user brew --prefix 2>/dev/null || true)"
  if [ -n "$_brew_prefix" ] && [ -x "${_brew_prefix}/bin/openshell" ]; then
    OPENSHELL_REGISTER_BIN="${_brew_prefix}/bin/openshell"
  fi

  info "registering local gateway as ${TARGET_USER}..."
  register_local_gateway
  wait_for_local_gateway_listener
  wait_for_local_gateway_status
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
  RELEASE_TAG="$(resolve_release_tag)"
  PLATFORM="$(detect_platform)"

  TARGET_USER="$(target_user)"
  TARGET_UID="$(id -u "$TARGET_USER" 2>/dev/null || true)"
  [ -n "$TARGET_UID" ] || error "cannot resolve uid for ${TARGET_USER}"
  TARGET_HOME="$(user_home "$TARGET_USER")"

  guard_breaking_upgrade

  case "$PLATFORM" in
    linux)
      case "$(linux_package_method)" in
        deb)
          install_linux_deb
          ;;
        rpm)
          install_linux_rpm
          ;;
        *)
          error "unsupported Linux package method"
          ;;
      esac
      ;;
    darwin)
      install_macos_homebrew
      ;;
    *)
      error "unsupported platform: ${PLATFORM}"
      ;;
  esac
}

main "$@"
