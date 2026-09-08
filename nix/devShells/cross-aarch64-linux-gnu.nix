# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  rust-overlay,
  commonDevShellPackages,
}:

let
  crossPkgs = pkgs.pkgsCross.aarch64-multiplatform;
  z3-static = crossPkgs.callPackage ../pkgs/z3-static.nix { };
in
import ./cross-rust.nix {
  inherit pkgs rust-overlay commonDevShellPackages;
  rustTarget = "aarch64-unknown-linux-gnu";
  zigTarget = "aarch64-unknown-linux-gnu.2.28";
  extraPackages = [ z3-static ];
  # CI builds the gateway against a Nix-provided static Z3. Keep the same
  # default-feature behavior while supplying the ARM64 Linux target library.
  shellAttributes.Z3_LIBRARY_PATH_OVERRIDE = "${z3-static}/lib";
}
