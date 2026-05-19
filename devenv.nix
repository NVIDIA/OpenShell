# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs, lib, ... }:

let
  isLinux = pkgs.stdenv.isLinux;
  isDarwin = pkgs.stdenv.isDarwin;

  z3Dev = lib.getDev pkgs.z3;
  z3Lib = lib.getLib pkgs.z3;
  opensslDev = lib.getDev pkgs.openssl;
  opensslLib = lib.getLib pkgs.openssl;
  elfutilsDev = lib.getDev pkgs.elfutils;
  elfutilsLib = lib.getLib pkgs.elfutils;
  libcapNgDev = lib.getDev pkgs.libcap_ng;
  libcapNgLib = lib.getLib pkgs.libcap_ng;
  libclangLib = pkgs.llvmPackages.libclang.lib;

  pkgConfigInputs = [
    z3Dev
    opensslDev
  ] ++ lib.optionals isLinux [
    elfutilsDev
    libcapNgDev
  ];

  nativeLibs = [
    z3Lib
    opensslLib
    libclangLib
  ] ++ lib.optionals isLinux [
    elfutilsLib
    libcapNgLib
  ];

  libclangSharedLibrary = if isDarwin then "libclang.dylib" else "libclang.so";

  pythonWithPyelftools = pkgs.python3.withPackages (ps: [
    ps.pyelftools
  ]);

  zigMuslWrapper = name: tool: target:
    pkgs.writeShellScriptBin name ''
      set -euo pipefail

      args=()
      for arg in "$@"; do
        case "$arg" in
          --target=*) ;;
          *) args+=("$arg") ;;
        esac
      done

      exec zig ${tool} --target=${target} "''${args[@]}"
    '';

  aarch64MuslCc = zigMuslWrapper "openshell-zig-aarch64-linux-musl-cc" "cc" "aarch64-linux-musl";
  aarch64MuslCxx = zigMuslWrapper "openshell-zig-aarch64-linux-musl-cxx" "c++" "aarch64-linux-musl";
  x86_64MuslCc = zigMuslWrapper "openshell-zig-x86_64-linux-musl-cc" "cc" "x86_64-linux-musl";
  x86_64MuslCxx = zigMuslWrapper "openshell-zig-x86_64-linux-musl-cxx" "c++" "x86_64-linux-musl";
in
{
  packages = with pkgs; [
    # Project task runner. mise installs the version-pinned Rust, Python, Node,
    # Kubernetes, documentation, and SBOM tools from mise.toml.
    mise

    # Core source-control and scripting tools.
    cacert
    coreutils
    curl
    file
    findutils
    gawk
    git
    gnugrep
    gnused
    gnutar
    gzip
    jq
    patch
    perl
    xz
    zstd

    # Native build prerequisites used by Rust crates and VM runtime builds.
    bc
    bison
    cmake
    cpio
    e2fsprogs
    flex
    gnumake
    openssl
    pkg-config
    z3

    # Local workflow CLIs. The daemon or machine still needs host setup.
    # Podman is intentionally not installed here: Linux rootless Podman also
    # needs host uidmap helpers and /etc/subuid + /etc/subgid entries, so use a
    # host-installed Podman when that driver is required.
    docker-client
    gh
  ] ++ lib.optionals isLinux [
    # Linux-only VM runtime build dependencies.
    elfutils
    gcc
    libcap_ng
    llvmPackages.libclang
  ] ++ lib.optionals isDarwin [
    # macOS VM runtime build dependencies that are otherwise documented as
    # Homebrew prerequisites. Darwin uses the host Xcode/CLT compiler so C++
    # probes can see the Apple SDK and libc++ headers.
    dtc
    llvmPackages.lld
  ] ++ [
    pythonWithPyelftools
  ];

  env = {
    PKG_CONFIG_PATH = lib.concatStringsSep ":" [
      (lib.makeSearchPathOutput "dev" "lib/pkgconfig" pkgConfigInputs)
      (lib.makeSearchPathOutput "dev" "share/pkgconfig" pkgConfigInputs)
    ];
    LIBRARY_PATH = lib.makeLibraryPath nativeLibs;

    LIBCLANG_PATH = "${libclangLib}/lib";
    OPENSHELL_LIBKRUNFW_PYTHON = "${pythonWithPyelftools}/bin/python3";
    OPENSHELL_SKIP_SYSTEM_DEPS = "1";

    Z3_SYS_Z3_HEADER = "${z3Dev}/include/z3.h";
    Z3_LIBRARY_PATH_OVERRIDE = "${z3Lib}/lib";

    # Match CI's Zig-backed musl toolchain so native Nix shells do not leak
    # glibc-built C objects into static supervisor/CLI links.
    CC_aarch64_unknown_linux_musl = "${aarch64MuslCc}/bin/openshell-zig-aarch64-linux-musl-cc";
    CXX_aarch64_unknown_linux_musl = "${aarch64MuslCxx}/bin/openshell-zig-aarch64-linux-musl-cxx";
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = "${aarch64MuslCc}/bin/openshell-zig-aarch64-linux-musl-cc";
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-Clink-self-contained=no";

    CC_x86_64_unknown_linux_musl = "${x86_64MuslCc}/bin/openshell-zig-x86_64-linux-musl-cc";
    CXX_x86_64_unknown_linux_musl = "${x86_64MuslCxx}/bin/openshell-zig-x86_64-linux-musl-cxx";
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${x86_64MuslCc}/bin/openshell-zig-x86_64-linux-musl-cc";
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-Clink-self-contained=no";
  } // lib.optionalAttrs isLinux {
    LD_LIBRARY_PATH = lib.makeLibraryPath nativeLibs;
  } // lib.optionalAttrs isDarwin {
    DYLD_FALLBACK_LIBRARY_PATH = lib.makeLibraryPath nativeLibs;
  };

  enterShell = ''
    desired_open_files=8192
    current_open_files="$(ulimit -Sn 2>/dev/null || ulimit -n 2>/dev/null || echo 0)"

    case "$current_open_files" in
      ""|*[!0-9]*)
        ;;
      *)
        if [ "$current_open_files" -lt "$desired_open_files" ]; then
          ulimit -Sn "$desired_open_files" 2>/dev/null \
            || ulimit -n "$desired_open_files" 2>/dev/null \
            || echo "Warning: could not raise open file limit to $desired_open_files"
        fi
        ;;
    esac

    mise_trust_status="$(mise trust --show 2>/dev/null || true)"
    if printf '%s\n' "$mise_trust_status" | grep -q ': untrusted$'; then
      echo "OpenShell devenv ready. Run 'mise trust' once, then 'mise install --locked'."
    else
      echo "OpenShell devenv ready. Run 'mise install --locked'."
    fi
  '';

  enterTest = ''
    pkg-config --exists z3
    test -f "$Z3_SYS_Z3_HEADER"
    test -d "$Z3_LIBRARY_PATH_OVERRIDE"
    test -e "$LIBCLANG_PATH/${libclangSharedLibrary}"
    "$OPENSHELL_LIBKRUNFW_PYTHON" -c 'from elftools.elf.elffile import ELFFile'
    test -x "$(command -v mise)"
    test -x "$(command -v mke2fs)"
    test -x "$(command -v docker)"
    test -x "$CC_aarch64_unknown_linux_musl"
    test -x "$CXX_aarch64_unknown_linux_musl"
    test -x "$CC_x86_64_unknown_linux_musl"
    test -x "$CXX_x86_64_unknown_linux_musl"
  '';
}
