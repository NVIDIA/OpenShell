# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs }:

let
  ubuntuCloudImage = pkgs.fetchurl {
    name = "ubuntu-24.04-server-cloudimg-amd64.img";
    url = "https://cloud-images.ubuntu.com/releases/noble/release-20260826/ubuntu-24.04-server-cloudimg-amd64.img";
    sha256 = "0c0f7yvcjr9f7y9i31py7i610c3g20n8xqkbz8jk91c0byxq9znh";
  };

  ubuntu =
    pkgs.runCommand "ubuntu-24.04-amd64-cloud-provisioned.qcow2"
      {
        nativeBuildInputs = [ pkgs.qemu ];
        requiredSystemFeatures = [ "kvm" ];
      }
      ''
        qemu-img create \
          -f qcow2 \
          -F qcow2 \
          -b "${ubuntuCloudImage}" \
          image.qcow2 \
          16G

        qemu-system-x86_64 \
          -machine q35,accel=kvm \
          -cpu host \
          -m 1G \
          -smp 2 \
          -nodefaults \
          -no-user-config \
          -no-reboot \
          -display none \
          -serial stdio \
          -monitor none \
          -drive id=rootfs,file=image.qcow2,format=qcow2,if=none \
          -device virtio-blk-pci,drive=rootfs,bootindex=1 \
          -device virtio-rng-pci \
          -blockdev driver=vvfat,node-name=seed,dir="${./cloud-init}",label=cidata,read-only=on \
          -device virtio-blk-pci,drive=seed \
          -netdev user,id=net0 \
          -device virtio-net-pci,netdev=net0

        mv image.qcow2 "$out"
      '';
in
{
  inherit ubuntu;
}
