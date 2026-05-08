#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Install the OpenShell development build from a GitHub release.
#
# Linux installs either the Debian or RPM packages from the selected release.
# Apple Silicon macOS installs the generated Homebrew formula, so Homebrew owns
# the binary layout and launchd service lifecycle.
#
set -e

APP_NAME="openshell"
REPO="NVIDIA/OpenShell"
GITHUB_URL="https://github.com/${REPO}"
RELEASE_TAG="${OPENSHELL_VERSION:-dev}"
CHECKSUMS_NAME="openshell-checksums-sha256.txt"
LOCAL_GATEWAY_PORT="17670"
HOMEBREW_TAP="nvidia/openshell"
HOMEBREW_FORMULA_NAME="openshell"

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
    OPENSHELL_VERSION   Release tag to install (default: dev).

NOTES:
    This installs the selected release from:
    ${GITHUB_URL}/releases/tag/${RELEASE_TAG}

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
      error "unsupported OS: $(uname -s); dev builds support Linux and macOS"
      ;;
  esac
}

linux_package_method() {
  if has_cmd dpkg; then
    echo "deb"
  elif has_cmd rpm; then
    echo "rpm"
  else
    error "Linux dev installs require either dpkg or rpm"
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
      error "Intel macOS is not supported because no x86_64-apple-darwin dev assets are published"
      ;;
    *)
      error "no macOS dev build is published for architecture: ${_arch}"
      ;;
  esac

  if ! as_target_user brew --version >/dev/null 2>&1; then
    error "Homebrew is required for macOS dev installs; install it from https://brew.sh"
  fi
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
      error "no dev RPM package is published for architecture: ${_arch}"
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

  if ! grep -q 'OPENSHELL_DRIVERS:' "$_formula_file"; then
    info "patching Homebrew formula to use VM driver..."
    awk '
      {
        print
        if ($0 ~ /^[[:space:]]*environment_variables\(/) {
          print "      OPENSHELL_DRIVERS: \"vm\","
        }
      }
    ' "$_formula_file" >"$_patched_file"
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

  wait_for_local_gateway_listener
  info "registering local gateway as ${TARGET_USER}..."
  register_local_gateway
  wait_for_local_gateway_status
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

  printf '%s\n' "$_last_output" >&2
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

  printf '%s\n' "$_status_output" >&2
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
    error "no dev openshell RPM package found for architecture: ${_arch}"
  fi

  _gateway_rpm_file="$(find_rpm_asset "${_tmpdir}/${CHECKSUMS_NAME}" "$_arch" openshell-gateway)"
  if [ -z "$_gateway_rpm_file" ]; then
    error "no dev openshell-gateway RPM package found for architecture: ${_arch}"
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

  wait_for_local_gateway_listener
  info "registering local gateway as ${TARGET_USER}..."
  register_local_gateway
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
  PLATFORM="$(detect_platform)"

  TARGET_USER="$(target_user)"
  TARGET_UID="$(id -u "$TARGET_USER" 2>/dev/null || true)"
  [ -n "$TARGET_UID" ] || error "cannot resolve uid for ${TARGET_USER}"
  TARGET_HOME="$(user_home "$TARGET_USER")"

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
