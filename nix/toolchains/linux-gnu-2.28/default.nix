# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs }:

let
  glibc = pkgs.callPackage ./libc.nix { };
  mkStdenv =
    {
      libraryPaths ? [ ],
      ldflags ? null,
    }:
    let
      runtime = pkgs.buildEnv {
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
    in
    pkgs.stdenvAdapters.useMoldLinker (
      pkgs.overrideCC pkgs.stdenv (
        pkgs.wrapCCWith {
          cc = pkgs.gccNGPackages.gcc-unwrapped.overrideAttrs (old: {
            configureFlags = old.configureFlags ++ [ "--disable-fixincludes" ];
          });
          bintools = pkgs.wrapBintoolsWith {
            bintools = pkgs.binutils-unwrapped;
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
      )
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
  sharedRuntime = pkgs.buildEnv {
    name = "gcc-shared-runtime";
    paths = [
      libgcc
      libstdcxx
    ];
    pathsToLink = [ "/lib" ];
  };
  stdenv = mkStdenv {
    libraryPaths = [
      libgcc
      libssp
      libstdcxx
    ];
    ldflags = [ "-lssp" ];
  };
in
{
  inherit sharedRuntime stdenv;
}
