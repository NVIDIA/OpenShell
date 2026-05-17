# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs, lib, ... }:

let
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
    elfutilsDev
    libcapNgDev
  ];

  nativeLibs = [
    z3Lib
    opensslLib
    elfutilsLib
    libcapNgLib
    libclangLib
  ];

  pythonWithPyelftools = pkgs.python3.withPackages (ps: [
    ps.pyelftools
  ]);
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
    elfutils
    flex
    gcc
    gnumake
    libcap_ng
    llvmPackages.libclang
    openssl
    pkg-config
    z3

    # Local workflow CLIs. The daemon or machine still needs host setup.
    # Podman is intentionally not installed here: Linux rootless Podman also
    # needs host uidmap helpers and /etc/subuid + /etc/subgid entries, so use a
    # host-installed Podman when that driver is required.
    docker-client
    gh
  ] ++ [
    pythonWithPyelftools
  ];

  env.PKG_CONFIG_PATH = lib.concatStringsSep ":" [
    (lib.makeSearchPathOutput "dev" "lib/pkgconfig" pkgConfigInputs)
    (lib.makeSearchPathOutput "dev" "share/pkgconfig" pkgConfigInputs)
  ];
  env.LD_LIBRARY_PATH = lib.makeLibraryPath nativeLibs;
  env.LIBRARY_PATH = lib.makeLibraryPath nativeLibs;

  env.LIBCLANG_PATH = "${libclangLib}/lib";
  env.OPENSHELL_LIBKRUNFW_PYTHON = "${pythonWithPyelftools}/bin/python3";
  env.OPENSHELL_SKIP_SYSTEM_DEPS = "1";

  env.Z3_SYS_Z3_HEADER = "${z3Dev}/include/z3.h";
  env.Z3_LIBRARY_PATH_OVERRIDE = "${z3Lib}/lib";

  enterShell = ''
    echo "OpenShell devenv ready. Run 'mise trust' once, then 'mise install --locked'."
  '';

  enterTest = ''
    pkg-config --exists z3
    test -f "$Z3_SYS_Z3_HEADER"
    test -d "$Z3_LIBRARY_PATH_OVERRIDE"
    test -e "$LIBCLANG_PATH/libclang.so"
    "$OPENSHELL_LIBKRUNFW_PYTHON" -c 'from elftools.elf.elffile import ELFFile'
    test -x "$(command -v mise)"
    test -x "$(command -v mke2fs)"
    test -x "$(command -v docker)"
  '';
}
