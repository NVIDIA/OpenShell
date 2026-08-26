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
    # Keep the QEMU and OVMF runtime used by Apple Silicon test guests on a
    # known-good release. Development shells and cross toolchains use nixpkgs.
    nixpkgs-test-guest.url = "github:NixOS/nixpkgs/0954f7ee2f6bb3dc7d4e3d0d8bcb8fd4bde4cfc5";
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
      nixpkgs-test-guest,
      treefmt-nix,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        testGuestPkgs = import nixpkgs-test-guest { inherit system; };
        commonDevShellPackages = with pkgs; [
          cargo-deny
          cargo-nextest
          # Assemble Debian artifacts on macOS and Linux.
          dpkg
          # Required to find packages.
          pkg-config
          # Coverage.
          lcov
          uv
        ];
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
        };
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        z3-static = pkgs.callPackage ./nix/pkgs/z3-static.nix { };
        aws-lc-static = pkgs.callPackage ./nix/pkgs/aws-lc-static.nix { };
        testGuest = import ./nix/test-guest {
          inherit pkgs;
          qemuPkgs = testGuestPkgs;
          firmwarePkgs = testGuestPkgs;
        };
      in
      {
        apps.test-guest = testGuest.app;
        apps.test-guest-cache = testGuest.cacheApp;

        devShells = {
          default =
            (pkgs.mkShell.override {
              stdenv =
                if pkgs.stdenv.hostPlatform.isLinux then
                  pkgs.stdenvAdapters.useMoldLinker pkgs.stdenv
                else
                  pkgs.stdenv;
            })
              {
                packages = [
                  rustToolchain
                  z3-static
                  aws-lc-static
                ]
                ++ commonDevShellPackages;
              };
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          glibc-2-28 = import ./nix/devShells/glibc-2-28.nix {
            inherit pkgs rust-overlay commonDevShellPackages;
          };
          musl = import ./nix/devShells/musl.nix {
            inherit pkgs rust-overlay commonDevShellPackages;
          };
        };

        formatter = treefmtEval.config.build.wrapper;
      }
    );
}
