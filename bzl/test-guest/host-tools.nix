# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs ? import <nixpkgs> { } }:

let
  isAarch64 = pkgs.stdenv.hostPlatform.isAarch64;
  isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
  architecture = if isAarch64 then "aarch64" else "x86_64";
  qemu = pkgs.qemu.override { hostCpuOnly = true; };
  qemuBinary =
    if isAarch64 then "${qemu}/bin/qemu-system-aarch64" else "${qemu}/bin/qemu-system-x86_64";

  runner = pkgs.writeShellApplication {
    name = "openshell-test-guest";
    runtimeInputs = [
      qemu
      pkgs.python3Packages.ansible-core
      pkgs.python3Packages.virt-firmware
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.jq
      pkgs.openssh
      pkgs.python3
      pkgs.xorriso
    ];
    text = ''
      export OPENSHELL_TEST_GUEST_RUNTIME=1
      export TEST_GUEST_QEMU=${qemuBinary}
      export TEST_GUEST_FIRMWARE_CODE=${pkgs.OVMF.firmware}
      export TEST_GUEST_FIRMWARE_VARS=${pkgs.OVMF.variables}
      export TEST_GUEST_MACHINE=${if isAarch64 then "virt" else "q35"}
      export TEST_GUEST_ACCELERATOR=${if isDarwin then "hvf" else "kvm"}
      export TEST_GUEST_ARCHITECTURE=${architecture}
      exec ${pkgs.bash}/bin/bash ${./run.sh} "$@"
    '';
  };
in
{
  bazelHostTools = pkgs.runCommand "openshell-test-guest-bazel-host-tools" { } ''
    mkdir -p "$out/bin" "$out/firmware" "$out/share" "$out/versions"
    for tool in ${pkgs.coreutils}/bin/*; do
      ln -s "$tool" "$out/bin/''${tool##*/}"
    done
    ln -s ${runner}/bin/openshell-test-guest "$out/bin/openshell-test-guest"
    ln -s ${pkgs.bash}/bin/bash "$out/bin/bash"
    ln -s ${pkgs.jq}/bin/jq "$out/bin/jq"
    ln -s ${qemu}/bin/qemu-img "$out/bin/qemu-img"
    ln -s ${qemuBinary} "$out/bin/qemu-system"
    ln -s ${qemu}/share/qemu "$out/share/qemu"
    ln -s ${pkgs.OVMF.firmware} "$out/firmware/code.fd"
    ln -s ${pkgs.OVMF.variables} "$out/firmware/vars.fd"
    printf '%s\n' ${pkgs.lib.escapeShellArg qemu.version} > "$out/versions/qemu"
    printf '%s\n' ${pkgs.lib.escapeShellArg pkgs.python3Packages.ansible-core.version} > "$out/versions/ansible"
  '';
}
