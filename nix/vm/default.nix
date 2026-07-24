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
    rocky = import ./distros/rocky.nix { inherit pkgs architecture; };
  };

  configurations = {
    docker = ./configuration/docker.yml;
    podman = ./configuration/podman.yml;
    selinux = ./configuration/selinux.yml;
  };

  mkDistroProfile =
    name: distro:
    pkgs.writeText "openshell-test-vm-${name}" ''
      TEST_VM_IMAGE_DRV=${builtins.unsafeDiscardStringContext distro.image.drvPath}
      TEST_VM_OS_ID=${pkgs.lib.escapeShellArg distro.osId}
      TEST_VM_OS_VERSION=${pkgs.lib.escapeShellArg distro.osVersion}
      TEST_VM_PACKAGE_FAMILY=${pkgs.lib.escapeShellArg distro.packageFamily}
      export TEST_VM_IMAGE_DRV TEST_VM_OS_ID TEST_VM_OS_VERSION TEST_VM_PACKAGE_FAMILY
    '';

  distroCatalog = pkgs.linkFarm "openshell-test-vm-distros" (
    pkgs.lib.mapAttrsToList (name: distro: {
      inherit name;
      path = mkDistroProfile name distro;
    }) distros
  );

  configurationCatalog = pkgs.linkFarm "openshell-test-vm-configurations" (
    pkgs.lib.mapAttrsToList (name: path: { inherit name path; }) configurations
  );

  runner = pkgs.writeShellApplication {
    name = "openshell-test-vm";
    runtimeInputs = [
      qemu
      pkgs.python3Packages.ansible-core
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.nix
      pkgs.openssh
      pkgs.python3
      pkgs.xorriso
    ];
    text = ''
      export OPENSHELL_TEST_VM_RUNTIME=1
      export OPENSHELL_TEST_VM_DISTROS=${distroCatalog}
      export OPENSHELL_TEST_VM_CONFIGURATIONS=${configurationCatalog}
      export TEST_VM_QEMU=${qemuBinary}
      export TEST_VM_FIRMWARE_CODE=${pkgs.OVMF.firmware}
      export TEST_VM_FIRMWARE_VARS=${pkgs.OVMF.variables}
      export TEST_VM_MACHINE=${if isAarch64 then "virt" else "q35"}
      export TEST_VM_ACCELERATOR=${if isDarwin then "hvf" else "kvm"}
      export TEST_VM_ARCHITECTURE=${architecture}
      exec ${pkgs.bash}/bin/bash ${./run.sh} "$@"
    '';
  };
in
{
  app = {
    type = "app";
    program = "${runner}/bin/openshell-test-vm";
    meta.description = "Boot and configure a disposable distro VM";
  };
}
