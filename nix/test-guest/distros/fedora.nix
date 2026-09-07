# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs, architecture }:

let
  imageUrl = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/${architecture}/images/Fedora-Cloud-Base-Generic-44-1.7.${architecture}.qcow2";
  imageHash =
    if architecture == "aarch64" then
      "sha256-VcYKO4DTYWoIcFr9BFnnX+nwPFSrp6RuQAKkGnL6DVs="
    else
      "sha256-KGgP5bNxpaguv0OjGSbghqFo5ZlJ0DlpxQk+cHH5C38=";
in
{
  osId = "fedora";
  osVersion = "44";
  packageFamily = "rpm";
  inherit imageUrl imageHash;
  image = pkgs.fetchurl {
    name = "Fedora-Cloud-Base-Generic-44-1.7.${architecture}.qcow2";
    url = imageUrl;
    hash = imageHash;
  };
}
