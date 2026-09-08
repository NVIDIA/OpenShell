# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  rust-overlay,
  commonDevShellPackages,
}:

let
  target = "aarch64-unknown-linux-gnu";
  zigTarget = "${target}.2.28";
  crossPkgs = pkgs.pkgsCross.aarch64-multiplatform;
  z3-static = crossPkgs.callPackage ../pkgs/z3-static.nix { };
  rust-bin = rust-overlay.lib.mkRustBin { } pkgs;
  rustToolchain = (rust-bin.fromRustupToolchainFile ../../rust-toolchain.toml).override {
    enableLibsecret = false;
    targets = [ target ];
  };
  cargo = pkgs.writeShellScriptBin "cargo" ''
    if [[ $# -gt 0 && $1 == build ]]; then
      shift
      # Keep the real Cargo ahead of this shim so cargo-zigbuild can invoke it
      # without recursively dispatching back into this script.
      export PATH=${rustToolchain}/bin:${pkgs.cargo-zigbuild}/bin:${pkgs.zig}/bin:$PATH
      exec ${pkgs.cargo-zigbuild}/bin/cargo-zigbuild zigbuild --target ${zigTarget} "$@"
    fi

    exec ${rustToolchain}/bin/cargo "$@"
  '';
in
pkgs.mkShell {
  packages = [
    cargo
    rustToolchain
    pkgs.cargo-zigbuild
    pkgs.zig
    z3-static
  ]
  ++ commonDevShellPackages;

  # CI builds the gateway against a Nix-provided static Z3. Keep the same
  # default-feature behavior while supplying the ARM64 Linux target library.
  Z3_LIBRARY_PATH_OVERRIDE = "${z3-static}/lib";
}
