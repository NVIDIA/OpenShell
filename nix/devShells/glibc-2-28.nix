# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  rust-overlay,
  commonDevShellPackages,
}:

let
  toolchain = import ../toolchains/linux-gnu-2.28 { inherit pkgs; };
  z3-static = pkgs.callPackage ../pkgs/z3-static.nix {
    stdenv = toolchain.stdenv;
  };
  aws-lc-static = pkgs.callPackage ../pkgs/aws-lc-static.nix {
    stdenv = toolchain.stdenv;
  };
  rustScope = {
    stdenv = toolchain.stdenv;
    gccForLibs.lib = toolchain.sharedRuntime;
    pkgsTargetTarget = pkgs.pkgsTargetTarget // {
      stdenv = toolchain.stdenv;
    };
  };
  rust-bin = rust-overlay.lib.mkRustBin { } (
    pkgs
    // rustScope
    // {
      callPackage = pkgs.newScope rustScope;
    }
  );
in
(pkgs.mkShell.override { stdenv = toolchain.stdenv; }) {
  packages = [
    (rust-bin.fromRustupToolchainFile ../../rust-toolchain.toml)
    z3-static
    aws-lc-static
  ]
  ++ commonDevShellPackages;
}
