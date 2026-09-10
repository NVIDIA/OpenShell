# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs }:

let
  glibc = pkgs.callPackage ./libc.nix { };
  baseGcc = pkgs.gcc15Stdenv.cc.cc;
  bintools = pkgs.buildPackages.wrapBintoolsWith {
    bintools = pkgs.buildPackages.binutils-unwrapped;
    libc = glibc;
  };
  bootstrap = pkgs.overrideCC pkgs.stdenv (
    pkgs.buildPackages.wrapCCWith {
      cc = baseGcc;
      inherit bintools;
    }
  );
  gcc = baseGcc.override (
    if pkgs.stdenv.buildPlatform.config == pkgs.stdenv.hostPlatform.config then
      { stdenv = bootstrap; }
    else
      { libcCross = glibc; }
  );
  stdenv = pkgs.overrideCC pkgs.stdenv (
    pkgs.buildPackages.wrapCCWith {
      cc = gcc;
      inherit bintools;
      libcxx = gcc.lib;
    }
  );
in
{
  inherit glibc gcc stdenv;
}
