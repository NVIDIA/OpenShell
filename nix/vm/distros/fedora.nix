# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs, architecture }:

{
  osId = "fedora";
  osVersion = "44";
  packageFamily = "rpm";
  image = pkgs.fetchurl {
    name = "Fedora-Cloud-Base-Generic-44-1.7.${architecture}.qcow2";
    url = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/${architecture}/images/Fedora-Cloud-Base-Generic-44-1.7.${architecture}.qcow2";
    hash =
      if architecture == "aarch64" then
        "sha256-VcYKO4DTYWoIcFr9BFnnX+nwPFSrp6RuQAKkGnL6DVs="
      else
        "sha256-KGgP5bNxpaguv0OjGSbghqFo5ZlJ0DlpxQk+cHH5C38=";
  };
}
