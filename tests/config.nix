# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs, toolchains }:

let
  isAarch64 = pkgs.stdenv.hostPlatform.isAarch64;
  gnuTarget = toolchains.${if isAarch64 then "aarch64-gnu" else "x86_64-gnu"}.target;
  muslTarget = toolchains.${if isAarch64 then "aarch64-musl" else "x86_64-musl"}.target;
  images = import ./images.nix { inherit pkgs; };
  tmachine = pkgs.callPackage ./tmachine { };
  config = (pkgs.formats.yaml { }).generate "tmachine-config.yaml" {
    machines = [
      {
        name = "ubuntu";
        base_image = "${images.ubuntu}";
      }
      {
        name = "fedora";
        base_image = "${images.fedora}";
      }
    ];

    scenarios = [
      {
        name = "ubuntu-docker-rootful";
        machine = "ubuntu";
        setup = {
          use_galaxy = true;
          playbooks = [ "ansible/playbooks/docker.yaml" ];
        };
        install = {
          use_galaxy = false;
          playbooks = [
            "ansible/playbooks/openshell.yaml"
            "ansible/playbooks/gateway.yaml"
          ];
          inputs = {
            openshell_cli_binary = "../target/${muslTarget}/debug/openshell";
            openshell_gateway_binary = "../target/${gnuTarget}/debug/openshell-gateway";
            openshell_sandbox_binary = "../target/${muslTarget}/debug/openshell-sandbox";
          };
        };
      }
      {
        name = "fedora-podman-rootful";
        machine = "fedora";
        setup = {
          use_galaxy = false;
          playbooks = [ "ansible/playbooks/podman-rootful.yaml" ];
        };
        install = {
          use_galaxy = false;
          playbooks = [
            "ansible/playbooks/openshell.yaml"
            "ansible/playbooks/gateway.yaml"
          ];
          inputs = {
            openshell_cli_binary = "../target/${muslTarget}/debug/openshell";
            openshell_gateway_binary = "../target/${gnuTarget}/debug/openshell-gateway";
            openshell_supervisor_image = "../target/openshell-supervisor-tmachine.tar";
          };
        };
      }
      {
        name = "fedora-podman-rootless";
        machine = "fedora";
        setup = {
          use_galaxy = false;
          playbooks = [ "ansible/playbooks/podman-rootless.yaml" ];
        };
        install = {
          use_galaxy = false;
          playbooks = [
            "ansible/playbooks/openshell.yaml"
            "ansible/playbooks/gateway.yaml"
          ];
          inputs = {
            openshell_cli_binary = "../target/${muslTarget}/debug/openshell";
            openshell_gateway_binary = "../target/${gnuTarget}/debug/openshell-gateway";
            openshell_supervisor_image = "../target/openshell-supervisor-tmachine.tar";
          };
        };
      }
    ];

    testsuites = [
      {
        name = "smoke";
        playbooks = [ "ansible/playbooks/smoke.yaml" ];
        inputs = {
          openshell_conformance_binary = "../target/${muslTarget}/debug/openshell-conformance";
        };
      }
    ];
  };

  runner = pkgs.writeShellApplication {
    name = "tmachine";
    runtimeInputs = [
      pkgs.qemu
      pkgs.python3Packages.ansible-core
      pkgs.sshpass
    ];
    text = ''
      exec ${tmachine}/bin/tmachine --config ${config} "$@"
    '';
  };
in
{
  package = runner;
  unwrapped = tmachine;
  inherit config;
}
