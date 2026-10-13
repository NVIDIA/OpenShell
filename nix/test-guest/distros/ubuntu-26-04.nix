# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs, architecture }:

let
  imageArchitecture = if architecture == "aarch64" then "arm64" else "amd64";
  imageUrl = "https://cloud-images.ubuntu.com/releases/releases/26.04/release/ubuntu-26.04-server-cloudimg-${imageArchitecture}.img";
  imageHash =
    if architecture == "aarch64" then
      "sha256-PhE/3UHznhNyk3UXO7KueT+H3G20KU5SUf8kdpcXiLo="
    else
      "sha256-gZa+nXlYBZy1bGx1yA/fbO6KiIW8FJ6nkdfbHH75MDU=";
in
{
  osId = "ubuntu";
  osVersion = "26.04";
  packageFamily = "deb";
  inherit imageUrl imageHash;
  image = pkgs.fetchurl {
    name = "ubuntu-26.04-server-cloudimg-${imageArchitecture}.img";
    url = imageUrl;
    hash = imageHash;
  };
}
