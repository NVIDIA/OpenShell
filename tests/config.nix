# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  toolchains,
  qemuPkgs ? pkgs,
  firmwarePkgs ? pkgs,
}:

let
  isAarch64 = pkgs.stdenv.hostPlatform.isAarch64;
  gnuTarget = toolchains.${if isAarch64 then "aarch64-gnu" else "x86_64-gnu"}.target;
  muslTarget = toolchains.${if isAarch64 then "aarch64-musl" else "x86_64-musl"}.target;
  images = import ./images.nix {
    inherit pkgs qemuPkgs firmwarePkgs;
  };
  tmachine = pkgs.callPackage ./tmachine {
    OVMF = firmwarePkgs.OVMF;
  };
  qemu = qemuPkgs.qemu.override { hostCpuOnly = true; };
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
          playbooks = [
            "ansible/playbooks/nextest.yaml"
            "ansible/playbooks/docker.yaml"
          ];
        };
        install = {
          use_galaxy = false;
          playbooks = [
            "ansible/playbooks/openshell.yaml"
            "ansible/playbooks/gateway.yaml"
          ];
          inputs = {
            openshell_cli_binary = "../artifacts/binaries/${muslTarget}/openshell";
            openshell_gateway_binary = "../artifacts/binaries/${gnuTarget}/openshell-gateway";
            openshell_supervisor_image = "../artifacts/images/openshell-supervisor-tmachine.tar";
            openshell_sandbox_image = "../artifacts/images/openshell-sandbox-tmachine.tar";
          };
        };
      }
      {
        name = "fedora-podman-rootful";
        machine = "fedora";
        setup = {
          use_galaxy = false;
          playbooks = [
            "ansible/playbooks/nextest.yaml"
            "ansible/playbooks/selinux.yaml"
            "ansible/playbooks/podman-rootful.yaml"
          ];
        };
        install = {
          use_galaxy = false;
          playbooks = [
            "ansible/playbooks/openshell.yaml"
            "ansible/playbooks/gateway.yaml"
          ];
          inputs = {
            openshell_cli_binary = "../artifacts/binaries/${muslTarget}/openshell";
            openshell_gateway_binary = "../artifacts/binaries/${gnuTarget}/openshell-gateway";
            openshell_supervisor_image = "../artifacts/images/openshell-supervisor-tmachine.tar";
            openshell_sandbox_image = "../artifacts/images/openshell-sandbox-tmachine.tar";
          };
        };
      }
      {
        name = "fedora-podman-rootless";
        machine = "fedora";
        setup = {
          use_galaxy = false;
          playbooks = [
            "ansible/playbooks/nextest.yaml"
            "ansible/playbooks/selinux.yaml"
            "ansible/playbooks/podman-rootless.yaml"
          ];
        };
        install = {
          use_galaxy = false;
          playbooks = [
            "ansible/playbooks/openshell.yaml"
            "ansible/playbooks/gateway.yaml"
          ];
          inputs = {
            openshell_cli_binary = "../artifacts/binaries/${muslTarget}/openshell";
            openshell_gateway_binary = "../artifacts/binaries/${gnuTarget}/openshell-gateway";
            openshell_supervisor_image = "../artifacts/images/openshell-supervisor-tmachine.tar";
            openshell_sandbox_image = "../artifacts/images/openshell-sandbox-tmachine.tar";
          };
        };
      }
    ];

    testsuites = [
      {
        name = "conformance";
        playbooks = [ "ansible/playbooks/conformance/cli.yaml" ];
        inputs = {
          openshell_conformance_test_bundle = "../artifacts/test-archives/${muslTarget}/openshell-conformance-tests.tar";
        };
      }
    ];
  };

  runner = pkgs.writeShellApplication {
    name = "tmachine";
    runtimeInputs = [
      qemu
      pkgs.ansible
      pkgs.git
      pkgs.sshpass
    ];
    text = ''
      root=$(git rev-parse --show-toplevel)
      cd "$root/tests"
      export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
      exec ${tmachine}/bin/tmachine --config ${config} "$@"
    '';
  };
in
{
  package = runner;
  unwrapped = tmachine;
  inherit config;
}
