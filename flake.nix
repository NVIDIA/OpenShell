# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  description = "OpenShell development environment";

  nixConfig = {
    extra-substituters = [ "https://openshell.cachix.org" ];
    extra-trusted-public-keys = [
      "openshell.cachix.org-1:OAr5MunsfH5PZvUsfD08OtGx5RtcwdNZGJdU5FqLm5w="
    ];
  };

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

        crateSpecs = import ./nix/crate.nix {
          inherit pkgs;
          root = ./.;
        };

        # Crate-by-crate crane helpers (workspace graph, minimal per-crate
        # source, buildWorkspaceCrate). See nix/workspace.nix.
        workspace = import ./nix/workspace.nix {
          inherit lib pkgs craneLib;
          root = ./.;
          inherit crateSpecs;
        };
        inherit (workspace) buildWorkspaceCrate;

        workspaceCrates = lib.mapAttrs (_: buildWorkspaceCrate) crateSpecs;
        crates = {
          openshell = workspaceCrates.openshell-cli.package;
          openshell-gateway = workspaceCrates.openshell-server.package;
          openshell-sandbox = workspaceCrates.openshell-sandbox.package;
          openshell-driver-vm = workspaceCrates.openshell-driver-vm.package;
          openshell-driver-kubernetes = workspaceCrates.openshell-driver-kubernetes.package;
          openshell-driver-podman = workspaceCrates.openshell-driver-podman.package;
        };

        crateTests = lib.mapAttrs' (
          name: crate: lib.nameValuePair "${name}-test" crate.test
        ) workspaceCrates;
        crateClippy = lib.mapAttrs' (
          name: crate: lib.nameValuePair "${name}-clippy" crate.clippy
        ) workspaceCrates;

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

        checks =
          crateTests
          // crateClippy
          // {
            rustfmt = craneLib.cargoFmt {
              pname = "openshell-workspace";
              src = craneLib.cleanCargoSource ./.;
              cargoExtraArgs = "--all";
            };
          };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            # Required to find packages
            pkg-config
            # Required for protobuf code generation.
            protobuf
            # Required for bindgen generation.
            llvmPackages.libclang
            # system dependency for openshell-prover
            z3
            # caching utility
            cachix
          ];

          env = {
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          };
        };

        formatter = treefmtEval.config.build.wrapper;
      }
    );
}
