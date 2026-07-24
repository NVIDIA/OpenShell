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

  ubuntu = import ./distros/ubuntu.nix { inherit pkgs architecture; };
  centos = import ./distros/centos.nix { inherit pkgs architecture; };
  rocky = import ./distros/rocky.nix { inherit pkgs architecture; };

  catalog = pkgs.writeText "openshell-test-vm-catalog.sh" ''
    test_vm_list_distros() {
      printf '%s\n' ubuntu centos rocky
    }

    test_vm_load_distro() {
      case "$1" in
        ubuntu)
          TEST_VM_IMAGE_DRV=${builtins.unsafeDiscardStringContext ubuntu.image.drvPath}
          TEST_VM_OS_ID=${ubuntu.osId}
          TEST_VM_OS_VERSION=${ubuntu.osVersion}
          TEST_VM_PACKAGE_FAMILY=${ubuntu.packageFamily}
          ;;
        centos)
          TEST_VM_IMAGE_DRV=${builtins.unsafeDiscardStringContext centos.image.drvPath}
          TEST_VM_OS_ID=${centos.osId}
          TEST_VM_OS_VERSION=${centos.osVersion}
          TEST_VM_PACKAGE_FAMILY=${centos.packageFamily}
          ;;
        rocky)
          TEST_VM_IMAGE_DRV=${builtins.unsafeDiscardStringContext rocky.image.drvPath}
          TEST_VM_OS_ID=${rocky.osId}
          TEST_VM_OS_VERSION=${rocky.osVersion}
          TEST_VM_PACKAGE_FAMILY=${rocky.packageFamily}
          ;;
        *)
          return 1
          ;;
      esac

      TEST_VM_QEMU=${qemuBinary}
      TEST_VM_FIRMWARE_CODE=${pkgs.OVMF.firmware}
      TEST_VM_FIRMWARE_VARS=${pkgs.OVMF.variables}
      TEST_VM_MACHINE=${if isAarch64 then "virt" else "q35"}
      TEST_VM_ACCELERATOR=${if isDarwin then "hvf" else "kvm"}
      TEST_VM_ARCHITECTURE=${architecture}
      export TEST_VM_IMAGE_DRV TEST_VM_OS_ID TEST_VM_OS_VERSION TEST_VM_PACKAGE_FAMILY
      export TEST_VM_QEMU TEST_VM_FIRMWARE_CODE TEST_VM_FIRMWARE_VARS
      export TEST_VM_MACHINE TEST_VM_ACCELERATOR TEST_VM_ARCHITECTURE
    }

    test_vm_list_configurations() {
      printf '%s\n' docker podman selinux
    }

    test_vm_load_configuration() {
      case "$1" in
        docker)
          TEST_VM_CONFIGURATION_PLAYBOOK=${./configuration/docker.yml}
          ;;
        podman)
          TEST_VM_CONFIGURATION_PLAYBOOK=${./configuration/podman.yml}
          ;;
        selinux)
          TEST_VM_CONFIGURATION_PLAYBOOK=${./configuration/selinux.yml}
          ;;
        *)
          return 1
          ;;
      esac
      export TEST_VM_CONFIGURATION_PLAYBOOK
    }
  '';

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
      export OPENSHELL_TEST_VM_CATALOG=${catalog}
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
