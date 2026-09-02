# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  rust-overlay,
  commonDevShellPackages,
}:

let
  muslPkgs = pkgs.pkgsMusl;
  stdenv = muslPkgs.stdenv;
  rust-bin = rust-overlay.lib.mkRustBin { } muslPkgs;
  rustToolchain = (rust-bin.fromRustupToolchainFile ../../rust-toolchain.toml).override {
    enableLibsecret = false;
  };
in
(muslPkgs.mkShell.override { inherit stdenv; }) {
  packages = [
    rustToolchain
    (muslPkgs.callPackage ../pkgs/z3-static.nix { })
    (muslPkgs.callPackage ../pkgs/aws-lc-static.nix {
      rust-bindgen = pkgs.rust-bindgen;
    })
  ]
  ++ commonDevShellPackages;
}
