# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# PROTOTYPE: Composable distro VMs for installing and exercising artifacts.

{ pkgs }:

let
  isAarch64 = pkgs.stdenv.hostPlatform.isAarch64;
  isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
  architecture = if isAarch64 then "aarch64" else "x86_64";
  qemu = pkgs.qemu.override { hostCpuOnly = true; };
  qemuBinary =
    if isAarch64 then "${qemu}/bin/qemu-system-aarch64" else "${qemu}/bin/qemu-system-x86_64";

  distros = {
    ubuntu = import ./distros/ubuntu.nix { inherit pkgs architecture; };
    centos = import ./distros/centos.nix { inherit pkgs architecture; };
    fedora = import ./distros/fedora.nix { inherit pkgs architecture; };
    rocky = import ./distros/rocky.nix { inherit pkgs architecture; };
  };

  configurations = {
    docker = ./configuration/docker.yml;
    podman = ./configuration/podman.yml;
    selinux = ./configuration/selinux.yml;
  };

  mkDistroProfile =
    name: distro:
    pkgs.writeText "openshell-test-guest-${name}" ''
      TEST_GUEST_IMAGE_DRV=${builtins.unsafeDiscardStringContext distro.image.drvPath}
      TEST_GUEST_IMAGE_URL=${pkgs.lib.escapeShellArg distro.imageUrl}
      TEST_GUEST_IMAGE_HASH=${pkgs.lib.escapeShellArg distro.imageHash}
      TEST_GUEST_OS_ID=${pkgs.lib.escapeShellArg distro.osId}
      TEST_GUEST_OS_VERSION=${pkgs.lib.escapeShellArg distro.osVersion}
      TEST_GUEST_PACKAGE_FAMILY=${pkgs.lib.escapeShellArg distro.packageFamily}
      export TEST_GUEST_IMAGE_DRV TEST_GUEST_IMAGE_URL TEST_GUEST_IMAGE_HASH
      export TEST_GUEST_OS_ID TEST_GUEST_OS_VERSION TEST_GUEST_PACKAGE_FAMILY
    '';

  distroCatalog = pkgs.linkFarm "openshell-test-guest-distros" (
    pkgs.lib.mapAttrsToList (name: distro: {
      inherit name;
      path = mkDistroProfile name distro;
    }) distros
  );

  configurationCatalog = pkgs.linkFarm "openshell-test-guest-configurations" (
    pkgs.lib.mapAttrsToList (name: path: { inherit name path; }) configurations
  );

  runtimeInputs = [
    qemu
    pkgs.python3Packages.ansible-core
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.jq
    pkgs.nix
    pkgs.openssh
    pkgs.oras
    pkgs.python3
    pkgs.xorriso
    pkgs.zstd
  ];

  runtimeEnvironment = ''
    export OPENSHELL_TEST_GUEST_RUNTIME=1
    export OPENSHELL_TEST_GUEST_DISTROS=${distroCatalog}
    export OPENSHELL_TEST_GUEST_CONFIGURATIONS=${configurationCatalog}
    export OPENSHELL_TEST_GUEST_CACHE_LIB=${./cache-lib.sh}
    export OPENSHELL_TEST_GUEST_CACHE_RUNNER=${./cache.sh}
    export OPENSHELL_TEST_GUEST_CACHE_SEAL=${./cache-seal.sh}
    export OPENSHELL_TEST_GUEST_ARTIFACT_PLAYBOOK=${./configuration/artifacts.yml}
    export OPENSHELL_TEST_GUEST_RUNNER=${./run.sh}
    export TEST_GUEST_BASH=${pkgs.bash}/bin/bash
    export TEST_GUEST_QEMU=${qemuBinary}
    export TEST_GUEST_FIRMWARE_CODE=${pkgs.OVMF.firmware}
    export TEST_GUEST_FIRMWARE_VARS=${pkgs.OVMF.variables}
    export TEST_GUEST_MACHINE=${if isAarch64 then "virt" else "q35"}
    export TEST_GUEST_ACCELERATOR=${if isDarwin then "hvf" else "kvm"}
    export TEST_GUEST_ARCHITECTURE=${architecture}
    export TEST_GUEST_ANSIBLE_VERSION=${pkgs.python3Packages.ansible-core.version}
    export TEST_GUEST_CACHE_GENERATION=1
  '';

  runner = pkgs.writeShellApplication {
    name = "openshell-test-guest";
    inherit runtimeInputs;
    text = runtimeEnvironment + ''
      exec ${pkgs.bash}/bin/bash ${./run.sh} "$@"
    '';
  };

  cacheRunner = pkgs.writeShellApplication {
    name = "openshell-test-guest-cache";
    inherit runtimeInputs;
    text = runtimeEnvironment + ''
      exec ${pkgs.bash}/bin/bash ${./cache.sh} "$@"
    '';
  };
in
{
  app = {
    type = "app";
    program = "${runner}/bin/openshell-test-guest";
    meta.description = "Boot and configure a disposable distro guest";
  };

  cacheApp = {
    type = "app";
    program = "${cacheRunner}/bin/openshell-test-guest-cache";
    meta.description = "Ensure a prepared test guest disk is available locally or in OCI";
  };
}
