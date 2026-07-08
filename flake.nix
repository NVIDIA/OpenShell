# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  description = "OpenShell development environment";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      flake-utils,
      nixpkgs,
      rust-overlay,
      treefmt-nix,
      ...
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        limaForDevShell =
          (pkgs.lima.override {
            withAdditionalGuestAgents = true;
          }).overrideAttrs
            (previous: {
              # Backport https://github.com/NixOS/nixpkgs/commit/5ce128c4d99036a72c5c4c2044a954ebcd8e0801
              # until the fix reaches nixos-unstable.
              nativeBuildInputs =
                (previous.nativeBuildInputs or [ ])
                ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
                  pkgs.llvmPackages.lld
                ];
              env =
                (previous.env or { })
                // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
                  NIX_CFLAGS_LINK = "-fuse-ld=${pkgs.lib.getExe' pkgs.llvmPackages.lld "ld64.lld"}";
                };
            });
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            # Required for running xtasks that use a lima provider
            limaForDevShell
            # Required to find packages
            pkg-config
            # Required for bindgen generation.
            llvmPackages.libclang
            # system dependency for openshell-prover
            z3
          ];

          env = {
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          };
        };

        formatter = treefmtEval.config.build.wrapper;
      }
    );
}
