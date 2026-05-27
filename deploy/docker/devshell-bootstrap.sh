#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Bootstrap an OpenShell development checkout inside a sandbox image.

set -euo pipefail

REPO_SLUG="${OPENSHELL_DEVSHELL_REPO_SLUG:-NVIDIA/OpenShell}"

export HOME=/sandbox
export USER=sandbox
export MISE_CACHE_DIR=/sandbox/.cache/mise
export CARGO_HOME=/sandbox/.cargo

path_prepend() {
  case ":${PATH}:" in
    *":$1:"*) ;;
    *) PATH="$1:${PATH}" ;;
  esac
}

ld_prepend() {
  case ":${LD_LIBRARY_PATH:-}:" in
    *":$1:"*) ;;
    *) LD_LIBRARY_PATH="$1:${LD_LIBRARY_PATH:-}" ;;
  esac
}

preload_prepend() {
  case ":${LD_PRELOAD:-}:" in
    *":$1:"*) ;;
    *) LD_PRELOAD="$1${LD_PRELOAD:+:${LD_PRELOAD}}" ;;
  esac
}

find_libclang_dir() {
  local dir
  for dir in \
    /sandbox/.deps/usr/lib/llvm-*/lib \
    /usr/lib/llvm-*/lib \
    /sandbox/.deps/usr/lib/*-linux-gnu \
    /usr/lib/*-linux-gnu \
    /usr/local/lib \
    /usr/lib64; do
    [ -d "$dir" ] || continue
    if [ -e "$dir/libclang.so" ] \
      || compgen -G "$dir/libclang-*.so" >/dev/null \
      || compgen -G "$dir/libclang.so.*" >/dev/null; then
      printf '%s\n' "$dir"
      return 0
    fi
  done
  return 1
}

find_clang_resource_include() {
  local dir
  for dir in \
    /sandbox/.deps/usr/lib/llvm-*/lib/clang/*/include \
    /usr/lib/llvm-*/lib/clang/*/include; do
    if [ -f "$dir/stddef.h" ]; then
      printf '%s\n' "$dir"
      return 0
    fi
  done
  return 1
}

find_z3_header() {
  local header
  for header in /sandbox/.deps/usr/include/z3.h /usr/local/include/z3.h /usr/include/z3.h; do
    if [ -f "$header" ]; then
      printf '%s\n' "$header"
      return 0
    fi
  done
  return 1
}

find_z3_libdir() {
  local dir
  for dir in /sandbox/.deps/usr/lib/*-linux-gnu /usr/local/lib /usr/lib/*-linux-gnu /usr/lib64; do
    [ -d "$dir" ] || continue
    if [ -e "$dir/libz3.so" ] || [ -e "$dir/libz3.a" ]; then
      printf '%s\n' "$dir"
      return 0
    fi
  done
  return 1
}

find_nss_wrapper() {
  local lib
  for lib in \
    /sandbox/.deps/usr/lib/*-linux-gnu/libnss_wrapper.so \
    /usr/lib/*-linux-gnu/libnss_wrapper.so \
    /usr/lib64/libnss_wrapper.so; do
    if [ -f "$lib" ]; then
      printf '%s\n' "$lib"
      return 0
    fi
  done
  return 1
}

etc_hosts_has_localhost() {
  grep -E '^(127\.0\.0\.1|::1)[[:space:]].*localhost' /etc/hosts >/dev/null 2>&1
}

native_deps_ready() {
  find_libclang_dir >/dev/null \
    && find_clang_resource_include >/dev/null \
    && find_z3_header >/dev/null \
    && find_z3_libdir >/dev/null \
    && { etc_hosts_has_localhost || find_nss_wrapper >/dev/null; }
}

ensure_native_deps() {
  native_deps_ready && return 0
  command -v apt-get >/dev/null 2>&1 || return 0
  command -v dpkg-deb >/dev/null 2>&1 || return 0
  [ -f /etc/apt/sources.list.d/ubuntu.sources ] || return 0

  local apt_root=/sandbox/.apt
  mkdir -p \
    "$apt_root/apt.conf.d" \
    "$apt_root/sources" \
    "$apt_root/lists/partial" \
    "$apt_root/cache/archives/partial" \
    /sandbox/.deps
  cp /etc/apt/sources.list.d/ubuntu.sources "$apt_root/sources/ubuntu.sources"

  local apt_opts=(
    -o Dir::Etc::main=/dev/null
    -o "Dir::Etc::parts=$apt_root/apt.conf.d"
    -o Dir::Etc::sourcelist=/dev/null
    -o "Dir::Etc::sourceparts=$apt_root/sources"
    -o "Dir::State::Lists=$apt_root/lists"
    -o Dir::State::status=/var/lib/dpkg/status
    -o "Dir::Cache=$apt_root/cache"
    -o "Dir::Cache::archives=$apt_root/cache/archives"
    -o Debug::NoLocking=1
    -o Acquire::Languages=none
  )

  if ! compgen -G "$apt_root/lists/*_Packages*" >/dev/null; then
    apt-get "${apt_opts[@]}" update
  fi
  if ! compgen -G "$apt_root/cache/archives/libclang-*.deb" >/dev/null \
    || ! compgen -G "$apt_root/cache/archives/libz3-dev_*.deb" >/dev/null; then
    apt-get "${apt_opts[@]}" --download-only --reinstall -y install \
      libclang-dev \
      libz3-dev \
      libnss-wrapper \
      pkg-config
  fi

  local deb
  for deb in "$apt_root"/cache/archives/*.deb; do
    [ -f "$deb" ] || continue
    dpkg-deb -x "$deb" /sandbox/.deps
  done
}

configure_native_deps_env() {
  local libclang_dir clang_include z3_header z3_libdir nss_wrapper

  if [ -d /sandbox/.deps/usr/bin ]; then
    path_prepend /sandbox/.deps/usr/bin
  fi

  if libclang_dir="$(find_libclang_dir)"; then
    export LIBCLANG_PATH="$libclang_dir"
    ld_prepend "$libclang_dir"
  fi
  if clang_include="$(find_clang_resource_include)"; then
    export BINDGEN_EXTRA_CLANG_ARGS="-I${clang_include}${BINDGEN_EXTRA_CLANG_ARGS:+ ${BINDGEN_EXTRA_CLANG_ARGS}}"
  fi
  if z3_header="$(find_z3_header)"; then
    export Z3_SYS_Z3_HEADER="$z3_header"
  fi
  if z3_libdir="$(find_z3_libdir)"; then
    export Z3_LIBRARY_PATH_OVERRIDE="$z3_libdir"
    ld_prepend "$z3_libdir"
  fi
  if [ -d /sandbox/.deps/usr/lib/aarch64-linux-gnu/pkgconfig ]; then
    export PKG_CONFIG_PATH="/sandbox/.deps/usr/lib/aarch64-linux-gnu/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
    export PKG_CONFIG_SYSROOT_DIR=/sandbox/.deps
  fi

  if ! etc_hosts_has_localhost && nss_wrapper="$(find_nss_wrapper)"; then
    {
      printf '127.0.0.1 localhost localhost.localdomain\n'
      printf '::1 localhost ip6-localhost ip6-loopback\n'
      printf '8.8.8.8 dns.google\n'
      grep -v -E '^(127\.0\.0\.1|::1)[[:space:]]' /etc/hosts || true
    } > /sandbox/.nss-hosts
    cat /etc/passwd > /sandbox/.nss-passwd
    if ! grep -q -E "^$(id -un):" /sandbox/.nss-passwd; then
      printf '%s:x:%s:%s::%s:%s\n' \
        "$(id -un)" "$(id -u)" "$(id -g)" "$HOME" "${SHELL:-/bin/bash}" \
        >> /sandbox/.nss-passwd
    fi
    cat /etc/group > /sandbox/.nss-group
    if ! grep -q -E "^$(id -gn):" /sandbox/.nss-group; then
      printf '%s:x:%s:%s\n' "$(id -gn)" "$(id -g)" "$(id -un)" \
        >> /sandbox/.nss-group
    fi
    export NSS_WRAPPER_HOSTS=/sandbox/.nss-hosts
    export NSS_WRAPPER_PASSWD=/sandbox/.nss-passwd
    export NSS_WRAPPER_GROUP=/sandbox/.nss-group
    export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
    preload_prepend "$nss_wrapper"
  fi

  export PATH LD_LIBRARY_PATH LD_PRELOAD
}

write_shell_profile() {
  {
    printf 'export HOME=%q\n' "$HOME"
    printf 'export USER=%q\n' "$USER"
    printf 'export MISE_CACHE_DIR=%q\n' "$MISE_CACHE_DIR"
    printf 'export CARGO_HOME=%q\n' "$CARGO_HOME"
    printf 'export MISE_DATA_DIR=%q\n' "$MISE_DATA_DIR"
    printf 'export RUSTUP_HOME=%q\n' "$RUSTUP_HOME"
    printf 'export PATH=%q\n' "$PATH"
    [ -z "${LD_LIBRARY_PATH:-}" ] || printf 'export LD_LIBRARY_PATH=%q\n' "$LD_LIBRARY_PATH"
    [ -z "${LD_PRELOAD:-}" ] || printf 'export LD_PRELOAD=%q\n' "$LD_PRELOAD"
    [ -z "${LIBCLANG_PATH:-}" ] || printf 'export LIBCLANG_PATH=%q\n' "$LIBCLANG_PATH"
    [ -z "${BINDGEN_EXTRA_CLANG_ARGS:-}" ] || printf 'export BINDGEN_EXTRA_CLANG_ARGS=%q\n' "$BINDGEN_EXTRA_CLANG_ARGS"
    [ -z "${PKG_CONFIG_PATH:-}" ] || printf 'export PKG_CONFIG_PATH=%q\n' "$PKG_CONFIG_PATH"
    [ -z "${PKG_CONFIG_SYSROOT_DIR:-}" ] || printf 'export PKG_CONFIG_SYSROOT_DIR=%q\n' "$PKG_CONFIG_SYSROOT_DIR"
    [ -z "${Z3_SYS_Z3_HEADER:-}" ] || printf 'export Z3_SYS_Z3_HEADER=%q\n' "$Z3_SYS_Z3_HEADER"
    [ -z "${Z3_LIBRARY_PATH_OVERRIDE:-}" ] || printf 'export Z3_LIBRARY_PATH_OVERRIDE=%q\n' "$Z3_LIBRARY_PATH_OVERRIDE"
    [ -z "${NSS_WRAPPER_HOSTS:-}" ] || printf 'export NSS_WRAPPER_HOSTS=%q\n' "$NSS_WRAPPER_HOSTS"
    [ -z "${NSS_WRAPPER_PASSWD:-}" ] || printf 'export NSS_WRAPPER_PASSWD=%q\n' "$NSS_WRAPPER_PASSWD"
    [ -z "${NSS_WRAPPER_GROUP:-}" ] || printf 'export NSS_WRAPPER_GROUP=%q\n' "$NSS_WRAPPER_GROUP"
    [ -z "${RUST_TEST_THREADS:-}" ] || printf 'export RUST_TEST_THREADS=%q\n' "$RUST_TEST_THREADS"
  } > /sandbox/.profile
  cp /sandbox/.profile /sandbox/.bash_profile
  printf 'source /sandbox/.profile\n' > /sandbox/.bashrc
}

configure_mise() {
  if command -v mise >/dev/null 2>&1 && [ -d /usr/local/share/openshell/mise ]; then
    export MISE_DATA_DIR=/usr/local/share/openshell/mise
    export RUSTUP_HOME=/usr/local/share/openshell/mise/rustup
    path_prepend /usr/local/share/openshell/mise/cargo/bin
    path_prepend /usr/local/bin
    path_prepend /usr/local/share/openshell/mise/shims
    return
  fi

  if command -v mise >/dev/null 2>&1 && [ -d /opt/mise ]; then
    export MISE_DATA_DIR=/opt/mise
    export RUSTUP_HOME=/opt/mise/rustup
    path_prepend /opt/mise/cargo/bin
    path_prepend /usr/local/bin
    path_prepend /opt/mise/shims
    return
  fi

  export MISE_DATA_DIR=/sandbox/.local/share/mise
  export RUSTUP_HOME=/sandbox/.rustup
  path_prepend /sandbox/.cargo/bin
  path_prepend /sandbox/.local/bin
  path_prepend /sandbox/.local/share/mise/shims
  if ! command -v mise >/dev/null 2>&1; then
    mkdir -p /sandbox/.local/bin
    curl -fsSL https://mise.run | sh
  fi
}

clone_repo() {
  if [ -d /sandbox/openshell/.git ]; then
    return
  fi

  if command -v gh >/dev/null 2>&1; then
    gh repo clone "$REPO_SLUG" /sandbox/openshell \
      || git clone "https://github.com/${REPO_SLUG}.git" /sandbox/openshell
  else
    git clone "https://github.com/${REPO_SLUG}.git" /sandbox/openshell
  fi
}

mkdir -p /sandbox /sandbox/.cargo /sandbox/.cache/mise
configure_mise
ensure_native_deps
configure_native_deps_env
write_shell_profile
clone_repo

cd /sandbox/openshell
mise trust >/dev/null
MISE_YES=1 mise install
if [ -f pyproject.toml ] && ! .venv/bin/python -c 'import grpc_tools.protoc' >/dev/null 2>&1; then
  uv sync --locked
fi
exec "$@"
