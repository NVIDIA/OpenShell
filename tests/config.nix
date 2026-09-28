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

    environments = [
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
      }
    ];

    installers = [
      {
        name = "none";
        use_galaxy = false;
        playbooks = [ ];
        inputs = { };
      }
      {
        name = "binaries";
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
      }
      {
        name = "deb";
        use_galaxy = false;
        playbooks = [
          "ansible/playbooks/openshell-deb.yaml"
        ];
        inputs = {
          openshell_deb = "../artifacts/packages/openshell.deb";
          openshell_supervisor_image = "../artifacts/images/openshell-supervisor-tmachine.tar";
          openshell_sandbox_image = "../artifacts/images/openshell-sandbox-tmachine.tar";
        };
      }
    ];

    testsuites = [
      {
        name = "shell";
        playbooks = [ "ansible/playbooks/shell.yaml" ];
        inputs = { };
        interactive = true;
      }
      {
        name = "conformance";
        playbooks = [ "ansible/playbooks/conformance/cli.yaml" ];
        inputs = {
          openshell_conformance_test_bundle = "../artifacts/test-archives/${muslTarget}/openshell-conformance-tests.tar";
        };
      }
      {
        name = "policy-advisor";
        playbooks = [ "ansible/playbooks/conformance/policy-advisor.yaml" ];
        inputs = {
          openshell_conformance_test_bundle = "../artifacts/test-archives/${muslTarget}/openshell-conformance-tests.tar";
        };
      }
      {
        name = "provider-refresh";
        playbooks = [ "ansible/playbooks/features/provider-refresh/keycloak.yaml" ];
        inputs = {
          keycloak_realm_file = "../scripts/keycloak-realm.json";
          provider_refresh_keycloak_test_bundle = "../artifacts/test-archives/${muslTarget}/provider-refresh-keycloak-tests.tar";
        };
      }
      {
        name = "driver-podman";
        playbooks = [
          "ansible/playbooks/drivers/podman/default-userns-baseline.yaml"
          "ansible/playbooks/drivers/podman/tests.yaml"
          "ansible/playbooks/drivers/podman/userns-auto.yaml"
          "ansible/playbooks/drivers/podman/tests.yaml"
          "ansible/playbooks/drivers/podman/userns-keep-id.yaml"
          "ansible/playbooks/drivers/podman/tests.yaml"
          "ansible/playbooks/drivers/podman/userns-private.yaml"
          "ansible/playbooks/drivers/podman/tests.yaml"
        ];
        inputs = {
          openshell_podman_test_bundle = "../artifacts/test-archives/${muslTarget}/openshell-podman-tests.tar";
          # Match OpenShell's compiled-in default so direct Podman and
          # OpenShell containers resolve the same workload image metadata.
          openshell_podman_reference_image = "nvcr.io/nvidia/base/ubuntu:24.04";
          openshell_podman_userns_auto_config = "suites/drivers/podman/fixtures/userns-auto.toml";
          openshell_podman_userns_keep_id_config = "suites/drivers/podman/fixtures/userns-keep-id.toml";
          openshell_podman_userns_private_config = "suites/drivers/podman/fixtures/userns-private.toml";
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
