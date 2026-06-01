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
    crane.url = "github:ipetkov/crane";
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
      crane,
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
        lib = pkgs.lib;
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

        # Crate-by-crate crane helpers (workspace graph, minimal per-crate
        # source, buildWorkspaceCrate). See nix/workspace.nix.
        workspace = import ./nix/workspace.nix {
          inherit lib pkgs craneLib;
          root = ./.;
        };
        inherit (workspace) buildWorkspaceCrate;

        # z3 (found via pkg-config) and libclang (for z3-sys bindgen) are only
        # needed by crates whose closure contains openshell-prover.
        withZ3 = {
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.z3 ];
          env.LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };

        # Each crate declares the compile-time assets its build needs — its own
        # plus those of its workspace deps (proto/ arrives via openshell-core,
        # providers/ via openshell-providers, registry/ via openshell-prover).
        crates = {
          openshell-cli = buildWorkspaceCrate (
            {
              dir = "openshell-cli";
              assets = [
                ./proto
                ./providers
                ./crates/openshell-prover/registry
              ];
            }
            // withZ3
          );
          openshell-server = buildWorkspaceCrate (
            {
              dir = "openshell-server";
              assets = [
                ./proto
                ./providers
                ./crates/openshell-prover/registry
                ./crates/openshell-server/migrations
              ];
            }
            // withZ3
          );
          openshell-sandbox = buildWorkspaceCrate {
            dir = "openshell-sandbox";
            assets = [
              ./proto
              ./crates/openshell-sandbox/data
              ./crates/openshell-sandbox/src/skills
            ];
          };
          openshell-driver-vm = buildWorkspaceCrate {
            dir = "openshell-driver-vm";
            assets = [
              ./proto
              ./crates/openshell-driver-vm/scripts
            ];
          };
          openshell-driver-kubernetes = buildWorkspaceCrate {
            dir = "openshell-driver-kubernetes";
            assets = [ ./proto ];
          };
          openshell-driver-podman = buildWorkspaceCrate {
            dir = "openshell-driver-podman";
            assets = [ ./proto ];
          };
        };

        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
        };
      in
      {
        packages = crates // {
          default = pkgs.symlinkJoin {
            name = "openshell-0.0.0";
            paths = lib.attrValues crates;
          };
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
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
