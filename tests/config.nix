# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs }:

let
  images = import ./images.nix { inherit pkgs; };
  tmachine = pkgs.callPackage ./tmachine { };
  config = (pkgs.formats.yaml { }).generate "tmachine-config.yaml" {
    machines = [
      {
        name = "ubuntu";
        base_image = "${images.ubuntu}";
      }
    ];

    scenarios = [
      {
        name = "docker";
        machine = "ubuntu";
        setup = {
          use_galaxy = true;
          playbooks = [ "ansible/playbooks/docker.yaml" ];
        };
        install = {
          use_galaxy = false;
          playbooks = [ ];
          inputs = { };
        };
      }
    ];

    testsuites = [
      {
        name = "docker";
        playbooks = [ "ansible/playbooks/docker-test.yaml" ];
        inputs = { };
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
