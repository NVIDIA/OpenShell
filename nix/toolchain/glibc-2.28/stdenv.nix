# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs }:

let
  glibc = pkgs.callPackage ./libc.nix { };
  gcc = pkgs.buildPackages.gccNGPackages.gcc-unwrapped.overrideAttrs (old: {
    postPatch =
      builtins.replaceStrings [ "gcc/config/darwin-c.c" ] [ "gcc/config/darwin-c.cc" ] old.postPatch
      + ''
        substituteInPlace gcc/collect2.cc \
          --replace-fail 'basename(c_file_name)' 'lbasename(c_file_name)'
      '';
    configureFlags = old.configureFlags ++ [
      "--disable-fixincludes"
      "--with-native-system-header-dir=/include"
    ];
  });
  mkRuntime =
    libraryPaths:
    pkgs.buildEnv {
      name = "gcc-static-runtime";
      paths = libraryPaths ++ map pkgs.lib.getDev libraryPaths;
      pathsToLink = [
        "/include"
        "/include-cxx"
        "/lib"
      ];
      postBuild = ''
        mkdir -p $out/lib
        find $out/lib -type l ! \( -name '*.a' -o -name 'crt*.o' \) -delete
        printf 'GROUP ( libgcc.a libgcc_eh.a )\n' > $out/lib/libgcc_s.a
      '';
      passthru.isGNU = true;
    };
  mkStdenv =
    {
      libraryPaths ? [ ],
      ldflags ? null,
    }:
    let
      runtime = mkRuntime libraryPaths;
    in
    pkgs.overrideCC pkgs.stdenv (
      pkgs.buildPackages.wrapCCWith {
        cc = gcc;
        bintools = pkgs.buildPackages.wrapBintoolsWith {
          bintools = pkgs.buildPackages.binutils-unwrapped;
          libc = glibc;
        };
        extraPackages = [ runtime ];
        libcxx = runtime;
        nixSupport = {
          cc-cflags = [
            "-isystem${pkgs.linuxHeaders}/include"
            "-static-libgcc"
            "-B${runtime}/lib"
          ];
        }
        // pkgs.lib.optionalAttrs (ldflags != null) { cc-ldflags = ldflags; };
      }
    );
  libgcc =
    (pkgs.gccNGPackages.libgcc.override {
      stdenv = mkStdenv { };
    }).overrideAttrs
      (old: {
        makeFlags = old.makeFlags ++ [ "SHLIB_LC=-lc" ];
      });
  libssp =
    (pkgs.gccNGPackages.libssp.override {
      stdenv = mkStdenv { libraryPaths = [ libgcc ]; };
    }).overrideAttrs
      {
        dontDisableStatic = true;
      };
  libstdcxxStdenv = mkStdenv {
    libraryPaths = [
      libgcc
      libssp
    ];
  };
  libstdcxx =
    (pkgs.gccNGPackages.libstdcxx.override {
      stdenv = libstdcxxStdenv;
      inherit libgcc;
      libbacktrace = pkgs.libbacktrace.override {
        stdenv = libstdcxxStdenv;
      };
    }).overrideAttrs
      {
        dontDisableStatic = true;
      };
  runtimeLibraries = [
    libgcc
    libssp
    libstdcxx
  ];
  runtime = mkRuntime runtimeLibraries;
  stdenv = mkStdenv {
    libraryPaths = runtimeLibraries;
    ldflags = [ "-lssp" ];
  };
in
{
  inherit
    glibc
    gcc
    runtime
    stdenv
    ;
}
