# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs, architecture }:

{
  osId = "rocky";
  osVersion = "9";
  packageFamily = "rpm";
  image = pkgs.fetchurl {
    name = "Rocky-9-GenericCloud-Base-9.8-20260525.0.${architecture}.qcow2";
    url = "https://download.rockylinux.org/pub/rocky/9/images/${architecture}/Rocky-9-GenericCloud-Base-9.8-20260525.0.${architecture}.qcow2";
    hash =
      if architecture == "aarch64" then
        "sha256-JGkqRE8fC4u5U3XDjItD+AmaEVNHYjaRviwzC0DIof4="
      else
        "sha256-ksIGzG95DGFYMkfu/oeJD4goQgZiwXys8kfOx4q07sg=";
  };
}
