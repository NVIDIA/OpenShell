# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  stdenv,
  fetchurl,
  linuxHeaders,
  bison,
  gawk,
  python3,
}:

stdenv.mkDerivation {
  pname = "glibc";
  version = "2.28";
  enableParallelBuilding = true;
  hardeningDisable = [
    "fortify"
    "pic"
  ];

  src = fetchurl {
    url = "https://ftp.gnu.org/gnu/glibc/glibc-2.28.tar.gz";
    hash = "sha256-8xjW4/H07Qt00oMqxPSR0PuSjkUcntpZTL8cO+569Hw=";
  };

  postPatch = ''
    substituteInPlace sysdeps/gnu/Makefile \
      --replace-fail \
        '$(object-suffixes) $(object-suffixes:=.d)' \
        '$(object-suffixes)'
  '';

  nativeBuildInputs = [
    bison
    gawk
    python3
  ];

  configureFlags = [
    "--with-headers=${linuxHeaders}/include"
    "--disable-werror"
  ];

  preConfigure = ''
    mkdir build
    cd build
    configureScript=../configure
  '';

  postConfigure = ''
    export NIX_DONT_SET_RPATH=1
  '';

  postFixup = ''
    if grep -q "$out/lib64/" "$out/bin/ldd"; then
      substituteInPlace "$out/bin/ldd" \
        --replace-fail "$out/lib64/" "$out/lib/"
    fi
  '';

  env.NIX_NO_SELF_RPATH = true;
  passthru.threadModel = "posix";
}
