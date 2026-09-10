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
          actionlint
          cargo-auditable
          cargo-deny
          cargo-nextest
          # Assemble Debian artifacts on macOS and Linux.
          dpkg
          git
          # Required to find packages.
          pkg-config
          # Coverage.
          lcov
          kubernetes-helm
          syft
          trivy
          uv
          yq-go
          zizmor
          zstd
        ];
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
        };
        rustToolchain =
          ((pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
            targets = map (toolchain: toolchain.target) (builtins.attrValues toolchains);
          }).overrideAttrs
            {
              propagatedBuildInputs = [ ];
              depsHostHostPropagated = [ ];
              depsTargetTargetPropagated = [ ];
            };
        buildInputs = { pkgs, stdenv }: [
          (pkgs.callPackage ./nix/pkgs/z3.nix { inherit stdenv; })
          (pkgs.callPackage ./nix/pkgs/aws-lc.nix { inherit stdenv; })
        ];
        inherit (import ./nix/toolchain) mkToolchain;
        toolchains = {
          x86_64-gnu = mkToolchain {
            pkgs = pkgs.pkgsCross.gnu64;
            inherit buildInputs;
          };
          x86_64-musl = mkToolchain {
            pkgs = pkgs.pkgsCross.musl64;
            inherit buildInputs;
          };
          aarch64-gnu = mkToolchain {
            pkgs = pkgs.pkgsCross.aarch64-multiplatform;
            inherit buildInputs;
          };
          aarch64-musl = mkToolchain {
            pkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
            inherit buildInputs;
          };
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
          aarch64-darwin = mkToolchain {
            inherit pkgs buildInputs;
          };
        };
        vmRuntime = pkgs.callPackage ./nix/pkgs/vm-runtime.nix { };
        testGuest = import ./nix/test-guest {
          inherit pkgs;
          qemuPkgs = testGuestPkgs;
          firmwarePkgs = testGuestPkgs;
        };
      in
      {
        apps.test-guest = testGuest.app;
        apps.test-guest-cache = testGuest.cacheApp;

        packages.vm-runtime = vmRuntime;

        devShells.default = pkgs.mkShellNoCC {
          packages = [ rustToolchain ] ++ commonDevShellPackages;

          env = pkgs.lib.foldl' (env: toolchain: env // toolchain.env) { } (builtins.attrValues toolchains);
        };

        formatter = treefmtEval.config.build.wrapper;
      }
    );
}
