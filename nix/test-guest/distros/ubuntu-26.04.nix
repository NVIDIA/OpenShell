# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs, architecture }:

let
  imageArchitecture = if architecture == "aarch64" then "arm64" else "amd64";
  imageUrl = "https://cloud-images.ubuntu.com/releases/server/26.04/release-20260717/ubuntu-26.04-server-cloudimg-${imageArchitecture}.img";
  imageHash =
    if architecture == "aarch64" then
      "sha256-WS/EdHgWo4EkG3nQSkVFqNp711d57XaQ10dj1jCkbfQ="
    else
      "sha256-t9qg/8sGrPRFR6L3aCCI0TrPBgmTdQf6qNfvAwJkDd0=";
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
