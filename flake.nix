# Quick start:
#
#   nix build                          Build all 3 binaries (openshell, openshell-server, openshell-sandbox)
#   nix run                            Run openshell (default binary)
#   nix run -- --help                  Show CLI help
#   nix run -- --version               Show version
#   nix develop                        Enter the dev shell (rustc, cargo, clippy, protoc, kubectl, helm, ...)
#   nix develop -c cargo build         Run a single command inside the dev shell
#   nix develop -c rustc --version     Check Rust version available in the dev shell
#
# Container:
#
#   nix build .#container              Build the OCI container image (creates ./result symlink)
#   docker load < result               Load it into Docker
#   docker run --rm openshell:0.0.0    Run container (default entrypoint shows help)
#   docker run --rm -it --entrypoint /bin/bash openshell:0.0.0   Interactive shell
#   docker image inspect openshell:0.0.0 --format='{{.Size}}'    Check uncompressed size
#
# Testing:
#
#   nix run .#container-test           Run 15 container smoke tests (requires Docker)
#   nix flake check                    Run all checks (builds package + dev shell)
#
# Formatting:
#
#   nix fmt                            Format all Nix files
#   nix fmt -- --check flake.nix nix/*.nix   Check formatting without modifying
#
{
  description = "OpenShell — safe, sandboxed runtimes for autonomous AI agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Pure data — no pkgs needed
        constants = import ./nix/constants.nix;

        # Source filters
        sources = pkgs.callPackage ./nix/source-filter.nix { inherit constants; };

        # OpenShell package (all workspace binaries)
        openshell = pkgs.callPackage ./nix/package.nix {
          inherit constants sources;
        };

        # OCI container image
        container = pkgs.callPackage ./nix/container.nix {
          inherit constants openshell;
        };

        # Container smoke-test script
        container-test = pkgs.callPackage ./nix/container-test.nix {
          inherit constants container;
          docker = pkgs.docker-client;
        };

      in
      {
        packages = {
          default = openshell;
          inherit
            openshell
            container
            container-test
            ;
        };

        devShells.default = pkgs.callPackage ./nix/shell.nix {
          inherit openshell;
        };

        formatter = pkgs.nixfmt;

        checks = {
          inherit openshell;
          shell = self.devShells.${system}.default;
        };
      }
    );
}
