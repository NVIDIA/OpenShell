# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  qemuPkgs ? pkgs,
  firmwarePkgs ? pkgs,
}:

let
  isAarch64 = pkgs.stdenv.hostPlatform.isAarch64;
  isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
  architecture = if isAarch64 then "aarch64" else "x86_64";
  ubuntuArchitecture = if isAarch64 then "arm64" else "amd64";
  qemu = qemuPkgs.qemu.override { hostCpuOnly = true; };
  qemuBinary =
    if isAarch64 then "${qemu}/bin/qemu-system-aarch64" else "${qemu}/bin/qemu-system-x86_64";
  machine = if isAarch64 then "virt" else "q35";
  accelerator = if isDarwin then "hvf" else "kvm";
  virtualizationFeature = if isDarwin then "apple-virt" else "kvm";
  qemuArgs = [
    "-machine"
    "${machine},accel=${accelerator}"
    "-cpu"
    "host"
    "-m"
    "1G"
    "-smp"
    "2"
    "-nodefaults"
    "-no-user-config"
    "-no-reboot"
    "-display"
    "none"
    "-serial"
    "stdio"
    "-monitor"
    "none"
  ]
  ++ pkgs.lib.optionals isAarch64 [
    "-drive"
    "if=pflash,format=raw,readonly=on,file=${firmwarePkgs.OVMF.firmware}"
    "-drive"
    "if=pflash,format=raw,file=firmware-vars.fd"
  ]
  ++ [
    "-drive"
    "id=rootfs,file=image.qcow2,format=qcow2,if=none"
    "-device"
    "virtio-blk-pci,drive=rootfs,bootindex=1"
    "-device"
    "virtio-rng-pci"
    "-blockdev"
    "driver=vvfat,node-name=seed,dir=${./cloud-init},label=cidata,read-only=on"
    "-device"
    "virtio-blk-pci,drive=seed"
    "-netdev"
    "user,id=net0"
    "-device"
    "virtio-net-pci,netdev=net0"
  ];

  mkProvisionedImage =
    { name, baseImage }:
    pkgs.runCommand name
      {
        nativeBuildInputs = [ qemu ];
        requiredSystemFeatures = [ virtualizationFeature ];
      }
      ''
        qemu-img create \
          -f qcow2 \
          -F qcow2 \
          -b "${baseImage}" \
          image.qcow2 \
          16G

        ${pkgs.lib.optionalString isAarch64 ''
          cp ${firmwarePkgs.OVMF.variables} firmware-vars.fd
          chmod 0600 firmware-vars.fd
        ''}

        ${qemuBinary} ${pkgs.lib.escapeShellArgs qemuArgs}

        mv image.qcow2 "$out"
      '';

  ubuntuCloudImage = pkgs.fetchurl {
    name = "ubuntu-24.04-server-cloudimg-${ubuntuArchitecture}.img";
    url = "https://cloud-images.ubuntu.com/releases/noble/release-20260826/ubuntu-24.04-server-cloudimg-${ubuntuArchitecture}.img";
    sha256 =
      if isAarch64 then
        "sha256-r6E5usbyYpweHy+PNCFfOprZd5gBvLlFUhuhpFAWdD8="
      else
        "0c0f7yvcjr9f7y9i31py7i610c3g20n8xqkbz8jk91c0byxq9znh";
  };

  fedoraCloudImage = pkgs.fetchurl {
    name = "Fedora-Cloud-Base-Generic-44-1.7.${architecture}.qcow2";
    url = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/${architecture}/images/Fedora-Cloud-Base-Generic-44-1.7.${architecture}.qcow2";
    hash =
      if isAarch64 then
        "sha256-VcYKO4DTYWoIcFr9BFnnX+nwPFSrp6RuQAKkGnL6DVs="
      else
        "sha256-KGgP5bNxpaguv0OjGSbghqFo5ZlJ0DlpxQk+cHH5C38=";
  };

  ubuntu = mkProvisionedImage {
    name = "ubuntu-24.04-${ubuntuArchitecture}-cloud-provisioned.qcow2";
    baseImage = ubuntuCloudImage;
  };

  fedora = mkProvisionedImage {
    name = "fedora-44-${architecture}-cloud-provisioned.qcow2";
    baseImage = fedoraCloudImage;
  };
in
{
  inherit ubuntu fedora;
}
