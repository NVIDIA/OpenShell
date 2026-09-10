# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  lib,
  stdenv,
  callPackage,
  fetchurl,
}:

let
  nixpkgs = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/f6519103bf8c8217c4007baaeb8bcaa1fcf95f1f.tar.gz";
    sha256 = "sha256-391FrgZ+VwYYg7poRQBmWwUMkK7dan66m6QhomEWkPE=";
  };
  glibc = callPackage "${nixpkgs}/pkgs/development/libraries/glibc" {
    # Provide the stdenv attributes used by the historical recipe.
    stdenv = stdenv // {
      inherit lib;
      inherit (stdenv.hostPlatform) is64bit isx86_64;
    };
  };
in
glibc.overrideAttrs (old: {
  pname = "glibc";
  name = "glibc-2.28";
  version = "2.28";
  src = fetchurl {
    url = "https://ftp.gnu.org/gnu/glibc/glibc-2.28.tar.gz";
    hash = "sha256-8xjW4/H07Qt00oMqxPSR0PuSjkUcntpZTL8cO+569Hw=";
  };
  hardeningDisable = old.hardeningDisable ++ [ "pic" ];
  configureFlags = lib.remove "--enable-obsolete-rpc" old.configureFlags ++ [ "--disable-werror" ];
  postPatch = old.postPatch + ''
    # Fixes a bug in Make that triggers infinte recursion on expansion.
    substituteInPlace sysdeps/gnu/Makefile \
      --replace-fail \
        '$(object-suffixes) $(object-suffixes:=.d)' \
        '$(object-suffixes)'

    # Keep the cross tools selected by Nix instead of GCC's bare tool names.
    sed -i -e '/^AR=/d' -e '/^AS=/d' -e '/^LD=/d' \
      -e '/^OBJCOPY=/d' -e '/^OBJDUMP=/d' configure
  '';
})
