# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs, architecture }:

let
  imageArchitecture = if architecture == "aarch64" then "arm64" else "amd64";
  imageUrl = "https://cloud-images.ubuntu.com/releases/noble/release-20260225/ubuntu-24.04-server-cloudimg-${imageArchitecture}.img";
  imageHash =
    if architecture == "aarch64" then
      "sha256-meHUgrlY5r/QGDpMSM5twzTgmj4ppFYPb1/4VZPQnR0="
    else
      "sha256-eqbZ9eijpVx0RbE40xpz0Rh4cSEbK32p2i4abL8WmyE=";
in
{
  osId = "ubuntu";
  osVersion = "24.04";
  packageFamily = "deb";
  inherit imageUrl imageHash;
  image = pkgs.fetchurl {
    name = "ubuntu-24.04-server-cloudimg-${imageArchitecture}.img";
    url = imageUrl;
    hash = imageHash;
  };
}
