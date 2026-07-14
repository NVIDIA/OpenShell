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
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        daggerConfig = builtins.fromJSON (builtins.readFile ./dagger.json);
        dagger = pkgs.callPackage ./nix/dagger.nix {
          version = pkgs.lib.removePrefix "v" daggerConfig.engineVersion;
        };
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            # Reproducible local build and packaging pipelines.
            dagger
            # Required for running packaging tests.
            (lima.override {
              withAdditionalGuestAgents = true;
            })
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
