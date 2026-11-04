# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  toolchains,
  rustToolchain,
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
  tmachine = pkgs.callPackage ./. {
    OVMF = firmwarePkgs.OVMF;
  };
  testRunnerUnwrapped = pkgs.callPackage ../runner {
    OVMF = firmwarePkgs.OVMF;
  };
  qemu = qemuPkgs.qemu.override { hostCpuOnly = true; };
  k3sInputs = {
    agent_sandbox_version = "0.5.0";
    openshell_cli_binary = "../../artifacts/binaries/${muslTarget}/openshell";
    openshell_gateway_image = "../../artifacts/images/openshell-gateway-tmachine.tar";
    openshell_helm_chart = "../../artifacts/helm/helm-chart-0.0.0.tgz";
    openshell_sandbox_image = "../../artifacts/images/openshell-sandbox-tmachine.tar";
    openshell_supervisor_image = "../../artifacts/images/openshell-supervisor-tmachine.tar";
  };
  # A fedora-podman-<podman> environment ("rootful" or "rootless") with more
  # setup playbooks after the base ones.
  fedoraPodman =
    {
      name,
      podman,
      playbooks,
      inputs,
    }:
    {
      inherit name;
      machine = "fedora";
      setup = {
        use_galaxy = false;
        playbooks = [
          "ansible/playbooks/nextest.yaml"
          "ansible/playbooks/test-tools.yaml"
          "ansible/playbooks/selinux.yaml"
          "ansible/playbooks/podman-${podman}.yaml"
        ]
        ++ playbooks;
        inherit inputs;
      };
    };
  # fedora-podman-{rootful,rootless}-keycloak run Keycloak for the
  # keycloak-provider-refresh suite.
  keycloakEnvironments = map (
    podman:
    fedoraPodman {
      name = "fedora-podman-${podman}-keycloak";
      inherit podman;
      playbooks = [ "ansible/playbooks/keycloak.yaml" ];
      inputs.keycloak_realm_file = "../../scripts/keycloak-realm.json";
    }
  ) podmanModes;
  # fedora-podman-{rootful,rootless}-userns-{default,auto,keep-id,private}
  # configure the Podman gateway's user-namespace mode, for the Podman driver
  # suite. Only the binaries installer applies the mode.
  podmanUsernsEnvironments = pkgs.lib.concatMap (
    podman:
    map (
      userns:
      fedoraPodman {
        name = "fedora-podman-${podman}-userns-${userns}";
        inherit podman;
        playbooks = [ "ansible/playbooks/drivers/podman/userns.yaml" ];
        inputs.podman_userns_mode = userns;
      }
    ) podmanUsernsModes
  ) podmanModes;
  podmanModes = [
    "rootful"
    "rootless"
  ];
  podmanUsernsModes = [
    "default"
    "auto"
    "keep-id"
    "private"
  ];
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
            "ansible/playbooks/test-tools.yaml"
            "ansible/playbooks/docker.yaml"
          ];
        };
      }
      {
        name = "ubuntu-docker-rootful-keycloak";
        machine = "ubuntu";
        setup = {
          use_galaxy = true;
          playbooks = [
            "ansible/playbooks/nextest.yaml"
            "ansible/playbooks/docker.yaml"
            "ansible/playbooks/keycloak.yaml"
          ];
          inputs = {
            keycloak_realm_file = "../../scripts/keycloak-realm.json";
          };
        };
      }
      {
        name = "ubuntu-k3s";
        machine = "ubuntu";
        setup = {
          use_galaxy = false;
          playbooks = [
            "ansible/playbooks/nextest.yaml"
            "ansible/playbooks/test-tools.yaml"
            "ansible/playbooks/k3s.yaml"
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
            "ansible/playbooks/test-tools.yaml"
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
            "ansible/playbooks/test-tools.yaml"
            "ansible/playbooks/selinux.yaml"
            "ansible/playbooks/podman-rootless.yaml"
          ];
        };
      }
    ]
    ++ keycloakEnvironments
    ++ podmanUsernsEnvironments;

    installers = [
      {
        name = "k3s";
        use_galaxy = false;
        playbooks = [ "ansible/playbooks/openshell-k3s.yaml" ];
        inputs = k3sInputs;
      }
      {
        name = "k3s-ha";
        use_galaxy = false;
        playbooks = [ "ansible/playbooks/openshell-k3s-ha.yaml" ];
        inputs = k3sInputs // {
          openshell_postgres_fixture = "../../e2e/kubernetes/postgres-fixture.yaml";
        };
      }
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
          openshell_cli_binary = "../../artifacts/binaries/${muslTarget}/openshell";
          openshell_gateway_binary = "../../artifacts/binaries/${gnuTarget}/openshell-gateway";
          openshell_supervisor_image = "../../artifacts/images/openshell-supervisor-tmachine.tar";
          openshell_sandbox_image = "../../artifacts/images/openshell-sandbox-tmachine.tar";
        };
      }
      {
        name = "deb";
        use_galaxy = false;
        playbooks = [
          "ansible/playbooks/openshell-deb.yaml"
        ];
        inputs = {
          openshell_deb = "../../artifacts/packages/openshell.deb";
          openshell_supervisor_image = "../../artifacts/images/openshell-supervisor-tmachine.tar";
          openshell_sandbox_image = "../../artifacts/images/openshell-sandbox-tmachine.tar";
        };
      }
      {
        name = "rpm";
        use_galaxy = false;
        playbooks = [ "ansible/playbooks/openshell-rpm.yaml" ];
        inputs = {
          openshell_rpm = "../../artifacts/packages/rpm/openshell.rpm";
          openshell_gateway_rpm = "../../artifacts/packages/rpm/openshell-gateway.rpm";
          openshell_supervisor_image = "../../artifacts/images/openshell-supervisor-tmachine.tar";
          openshell_sandbox_image = "../../artifacts/images/openshell-sandbox-tmachine.tar";
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
        name = "e2e-podman";
        playbooks = [ "ansible/playbooks/drivers/podman/e2e.yaml" ];
        inputs = {
          openshell_podman_e2e_test_bundle = "../../artifacts/test-archives/${muslTarget}/openshell-podman-e2e-tests.tar";
          openshell_podman_e2e_workload_image = "../../artifacts/images/openshell-e2e-python-dev.tar";
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
      cd "$root/tests/tmachine"
      export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
      exec ${tmachine}/bin/tmachine --config ${config} "$@"
    '';
  };

  # Runs a test family in a tmachine environment with tests/runner
  # (`nix run .#openshell-test-runner -- --environment ubuntu-docker-rootful
  # --installer deb --family conformance`). It cross-builds guest test bundles
  # and drives tmachine sessions, so it needs the toolchains and the VM tools.
  testRunner = pkgs.writeShellApplication {
    name = "openshell-test-runner";
    runtimeInputs = [
      qemu
      pkgs.ansible
      pkgs.cargo-nextest
      pkgs.coreutils
      pkgs.git
      pkgs.sshpass
      rustToolchain
    ];
    runtimeEnv =
      pkgs.lib.foldl' (env: toolchain: env // toolchain.env) { } (builtins.attrValues toolchains)
      // {
        TMACHINE_CONFIG = "${config}";
      };
    text = ''
      root=$(git rev-parse --show-toplevel)
      export ANSIBLE_CONFIG="$root/tests/tmachine/ansible/ansible.cfg"
      exec ${testRunnerUnwrapped}/bin/openshell-test-runner "$@"
    '';
  };
in
{
  package = runner;
  unwrapped = tmachine;
  inherit config testRunner;
}
